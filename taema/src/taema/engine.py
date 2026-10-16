"""Decision and action engine: plan_stop/stop, adopt_pass, gc_pass."""
import fnmatch
import hashlib
import os
import signal
import subprocess
import sys
import time

from . import cgroup, inspect, knowledge, policy


HOOK_TIMEOUT = 30
EMPTY_PREFIXES = ("app-", "scope-")
POLL_STEP = 0.05


class Refused(Exception):
    pass


# ---- helpers ------------------------------------------------------------------------------

def helper_path(cfg):
    return policy.expand(cfg["paths"].get("helper", policy.HELPER))


def helper_attach(cfg, pid, name):
    """Move one pid into scope-NAME through the root helper (needed from the login cgroup)."""
    r = subprocess.run(["sudo", "-n", helper_path(cfg), "attach", str(pid), name], capture_output=True, text=True)
    if r.returncode != 0:
        raise Refused(r.stderr.strip() or "attach failed")


def helper_move(cfg, relpath, pids):
    pids = [str(p) for p in pids]
    for i in range(0, len(pids), 64):
        r = subprocess.run(["sudo", "-n", helper_path(cfg), "move", relpath] + pids[i:i + 64],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise Refused(r.stderr.strip() or "move failed")


def self_guard(path):
    """Refuse when the caller's own cgroup is the target or lies below it."""
    if cgroup.is_prefix(path, cgroup.own_cgroup()):
        raise Refused("running inside %s; refusing to kill self" % cgroup.rel(path))


def unit_for_leaf(units, leaf):
    """The unit for a top-level leaf: exact name, or '<unit name>-<suffix>' for app units."""
    for u in units:
        n = u.get("unit", {}).get("name")
        if n and (leaf == n or (u["unit"].get("kind") == "app" and leaf.startswith(n + "-"))):
            return u
    return None


# ---- stop ---------------------------------------------------------------------------------

def plan_stop(path, cfg, store, unit=None, force=False, hard=False, keep=(), pt=None, snap=None):
    """Decide per member: kill | share | skip. Never touches anything.

    pt: the pass's ProcTable. snap: an inspect.LazySnapshot shared across passes; ss runs only
    when at least one member is unprotected (a candidate for kill)."""
    pids = cgroup.tree_procs(path)
    pset = set(pids)
    pt = pt or inspect.ProcTable.scan()
    reasons = {pid: policy.protected_reason(pid, cfg) for pid in pids}
    edge_map, edges_ok = {}, True
    if any(r is None for r in reasons.values()):
        snap = snap or inspect.LazySnapshot()
        s = snap.get()
        edges_ok = getattr(s, "ok", True)
        edge_map = inspect.edges(pset, s)
        if not edges_ok:
            store.log(event="edge_scan_failed", scope=cgroup.rel(path))
    keep_set = set(keep) | set((unit or {}).get("kill", {}).get("keep", []))
    out = {}
    for pid in pids:
        key = policy.exe_key(pid)
        d = {"pid": pid, "comm": inspect.comm(pid), "key": key, "edges": edge_map.get(pid, [])}
        reason = reasons[pid]
        if reason:
            d.update(action="skip", why=reason)
        elif d["edges"] and not hard:
            d.update(action="share", why="outside users: " + "; ".join(
                "%s %s" % (e["kind"], e["detail"]) for e in d["edges"]))
        elif not edges_ok and not hard:
            d.update(action="share", why="edge scan failed")
        elif key in keep_set:
            d.update(action="share", why="kept by unit or --keep")
        elif not force and store.default_action(key)[0] == "share":
            d.update(action="share", why="default: " + store.default_action(key)[1])
        else:
            d.update(action="kill", why="no outside users")
        out[pid] = d
    # a descendant of a shared pid moves with it
    shared = {p for p, d in out.items() if d["action"] == "share"}
    for pid, d in out.items():
        if d["action"] == "kill" and any(a in shared for a in pt.ancestors(pid)):
            d.update(action="share", why="descendant of a shared process")
    return list(out.values())


def _signal_all(path, pids, sig, cfg):
    """Signal pids that are still members of path and unprotected. Pins each pid with a pidfd
    first so a recycled pid is never hit; falls back to os.kill without pidfd support."""
    use_fd = hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
    fds = {}
    for p in pids:
        fd = None
        if use_fd:
            try:
                fd = os.pidfd_open(p)
            except ProcessLookupError:
                continue
            except OSError:
                fd = None
        fds[p] = fd
    members = set(cgroup.tree_procs(path))   # after pinning: membership and protection re-checked
    sent = []
    for p, fd in fds.items():
        try:
            if p not in members or policy.protected_reason(p, cfg):
                continue
            if fd is not None:
                signal.pidfd_send_signal(fd, sig)
            else:
                os.kill(p, sig)
            sent.append(p)
        except (ProcessLookupError, PermissionError):
            pass
        finally:
            if fd is not None:
                os.close(fd)
    return sent


def _wait_each(path, pids, seconds):
    """Poll until pids leave path or seconds pass. Returns {pid: ms until it was gone}."""
    t0 = time.monotonic()
    deadline = t0 + seconds
    left, gone = set(pids), {}
    while True:
        left &= set(cgroup.tree_procs(path))
        for p in set(pids) - left - set(gone):
            gone[p] = (time.monotonic() - t0) * 1000
        if not left or time.monotonic() >= deadline:
            return gone
        time.sleep(POLL_STEP)


def _run_hook(hook):
    """Run the stop hook in its own process group; kill the group on timeout."""
    try:
        p = subprocess.Popen([hook], start_new_session=True)
    except OSError:
        return
    try:
        p.wait(timeout=HOOK_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()


def stop(path, cfg, store, unit=None, timeout=None, force=False, hard=False, keep=(),
         dry_run=False, hook=None, passes=3):
    """Stop a scope: move shared members aside, run the hook, SIGTERM, SIGKILL leftovers, rmdir."""
    self_guard(path)
    report = {"scope": cgroup.rel(path), "decisions": [], "removed": False, "left": []}
    ran_hook = False
    counted, killed_keys, sigkill_keys = set(), set(), set()
    snap = inspect.LazySnapshot()     # one ss snapshot for all passes, built only if needed
    for _ in range(passes):
        pt = inspect.ProcTable.scan()
        plan = plan_stop(path, cfg, store, unit, force, hard, keep, pt=pt, snap=snap)
        report["decisions"].extend(plan)
        if dry_run or not plan:
            break
        shared = [d for d in plan if d["action"] == "share"]
        kill = [d for d in plan if d["action"] == "kill"]
        shared_pids = {d["pid"] for d in shared}
        roots = [d for d in shared if not any(a in shared_pids for a in pt.ancestors(d["pid"]))]
        for d in shared:
            for e in d["edges"]:
                store.bump(d["key"], "shared_hits", 1.0)
        for r in roots:
            dest = cgroup.mkleaf("shared/" + leaf_slug(r["comm"], r["pid"]))
            moving = [p for p in pt.descendants([r["pid"]]) if p in shared_pids]
            dest_cg = "/user/%d/%s" % (os.getuid(), cgroup.rel(dest))
            for _i in range(3):
                for p in moving:
                    cgroup.move(p, dest)
                moving = [p for p in inspect.ProcTable.scan().descendants([r["pid"]]) if p in shared_pids
                          and cgroup.proc_cgroup(p) != dest_cg]
                if not moving:
                    break
        if not ran_hook:
            ran_hook = True
            hook = hook or ((unit or {}).get("kill", {}).get("hook"))
            if hook:
                hook = policy.expand(hook)
                if os.access(hook, os.X_OK):
                    _run_hook(hook)
        if not kill:
            break
        kill_set = {d["pid"] for d in kill}
        keys = {d["key"] for d in kill}
        grace = max([store.graceful_timeout(k, (unit or {}).get("kill", {}).get("graceful",
                     policy.timer(cfg, "graceful_timeout", 10)))[0] for k in keys] or [0])
        for k in keys - counted:
            store.bump(k, "stops")
            counted.add(k)
        if timeout is not None:
            grace = float(timeout)
        _signal_all(path, kill_set, signal.SIGTERM, cfg)
        exited = _wait_each(path, kill_set, grace)
        survivors = kill_set - set(exited)
        for d in kill:
            store.add_term_ms(d["key"], exited.get(d["pid"], grace * 1000))
            if d["key"] not in killed_keys:
                killed_keys.add(d["key"])
                store.bump(d["key"], "killed")
        if survivors:
            _signal_all(path, survivors, signal.SIGKILL, cfg)
            for d in kill:
                if d["pid"] in survivors and d["key"] not in sigkill_keys:
                    sigkill_keys.add(d["key"])
                    store.bump(d["key"], "sigkill_needed")
            _wait_each(path, survivors, 5)
    if not dry_run:
        try:
            cgroup.rmdir_tree(path)
            report["removed"] = True
        except OSError as e:
            report["left"] = cgroup.tree_procs(path)
            report["error"] = str(e)
    store.log(event="stop", scope=report["scope"], dry_run=dry_run, removed=report["removed"],
              decisions=[{k: v for k, v in d.items() if k != "edges"} | {"edges": len(d["edges"])}
                         for d in report["decisions"]])
    store.save_if_dirty(knowledge.SAVE_INTERVAL)
    return report


def _slug(s):
    out = "".join(c if c.isalnum() and c.isascii() else "-" for c in s.lower()).strip("-")
    return out[:24] or "proc"


def leaf_slug(name, pid=None):
    """Leaf name that always passes cgroup.valid_rel: '<slug>[-<hash>][-<pid>]'. A short hash
    is added when slugging changed anything (Xwayland, g++, 'my app') so names stay distinct."""
    slug = _slug(name)
    if slug != name:
        slug += "-" + hashlib.sha1(name.encode(errors="replace")).hexdigest()[:6]
    if pid is not None:
        slug += "-%d" % pid
    return slug if cgroup.valid_rel(slug) else "proc-%d" % (pid or 0)


# ---- adopt --------------------------------------------------------------------------------

_MATCH_KEYS = ("exe", "comm", "cmdline_contains")
_warned = set()


def _matches(m, pid, env=None):
    if not any(k in m for k in _MATCH_KEYS):   # an empty [match] would match every process
        w = repr(sorted(m.items()))
        if w not in _warned:
            _warned.add(w)
            print("taema: [match] needs one of %s; ignoring %s" % (", ".join(_MATCH_KEYS), w),
                  file=sys.stderr)
        return False
    if "exe" in m and inspect.exe(pid) != m["exe"]:
        return False
    if "comm" in m and inspect.comm(pid) != m["comm"]:
        return False
    if "cmdline_contains" in m and m["cmdline_contains"] not in inspect.cmdline(pid):
        return False
    return True


def adopt_plan(cfg, units, pp=None):
    """Operations that move matching processes out of the login session cgroup.
    pp: the pass's ProcTable (scanned here when omitted)."""
    in_session = set()
    for session in policy.session_cgroups(cfg):
        in_session.update(cgroup.procs(session))
    pp = pp or inspect.ProcTable.scan()
    ops = []
    for u in units:
        m = u.get("match")
        if not m or u.get("unit", {}).get("kind") != "app":
            continue
        name = u["unit"]["name"]
        if not cgroup.valid_rel(name) or "/" in name:
            name = leaf_slug(name)
        matched = [p for p in in_session if _matches(m, p) and not policy.protected_reason(p, cfg)]
        roots = [p for p in matched if not any(a in matched for a in pp.ancestors(p))]
        groups = {}
        for r in roots:
            env = inspect.environ(r)
            gb = u["unit"].get("group_by_env")
            if gb:
                val = env.get(gb)
                if not val or policy.env_excluded(env, m.get("env_exclude")):
                    continue
                groups.setdefault(name + "-" + hashlib.sha1(val.encode()).hexdigest()[:8], (val, []))[1].append(r)
            else:
                groups.setdefault(name, (None, []))[1].append(r)
        for scope, (val, rs) in groups.items():
            extra = []
            for c in u.get("children", []):
                if "same_env" in c and val is not None:
                    extra += [p for p in in_session
                              if inspect.comm(p) == c.get("comm") and
                              inspect.environ(p).get(c["same_env"]) == val]
            moved = [p for p in pp.descendants(rs + extra) if p in in_session]
            ops.append({"op": "move", "scope": scope, "unit": name, "pids": moved})
    return ops


def carve_plan(cfg, units, pp=None):
    """Child scopes (sessions, vm) for processes sitting directly in an app scope."""
    pp = pp or inspect.ProcTable.scan()
    ops = []
    for u in units:
        if u.get("unit", {}).get("kind") != "app" or not u.get("children"):
            continue
        base = cgroup.base()
        for scope_dir in [d for d in cgroup.subdirs(base)
                          if os.path.basename(d) == u["unit"]["name"]
                          or os.path.basename(d).startswith(u["unit"]["name"] + "-")]:
            direct = set(cgroup.procs(scope_dir))
            for c in u["children"]:
                if "ancestor_comm" not in c and "comm" not in c:
                    continue
                want = c.get("ancestor_comm") or c.get("comm")
                roots = [p for p in direct if inspect.comm(p) == want]
                roots = [p for p in roots if not any(a in roots for a in pp.ancestors(p))]
                for r in roots:
                    members = [p for p in pp.descendants([r]) if p in direct]
                    ops.append({"op": "carve", "parent": os.path.basename(scope_dir),
                                "scope": "%s/%s-%d" % (os.path.basename(scope_dir), c["name"], r),
                                "root": r, "binds_to": c.get("binds_to"), "pids": members})
    return ops


def _inside_user(pid):
    """True when pid already sits in user/<uid> (a move from there needs no root helper)."""
    cg = cgroup.proc_cgroup(pid) or ""
    me = "/user/%d" % os.getuid()
    return cg == me or cg.startswith(me + "/")


def run_ops(cfg, store, ops, execute):
    """Log every op; perform it when `execute`. Returns the ops with a 'done' flag.
    Pids inside user/<uid> move directly; the sudo helper is used only for pids in a session
    cgroup. A repeated adopt_would for an identical op is not logged again."""
    seen = set()
    for op in ops:
        op["done"] = False
        pids = [p for p in op["pids"] if not policy.protected_reason(p, cfg)]
        op["skipped_protected"] = len(op["pids"]) - len(pids)
        op["pids"] = pids
        if execute and pids:
            cgroup.mkleaf(op["scope"])
            dest = cgroup.base() + "/" + op["scope"]
            outside = [p for p in pids if not _inside_user(p)]
            if outside:
                helper_move(cfg, op["scope"], outside)
            inside = [p for p in pids if p not in set(outside)]
            if op["op"] == "carve":
                for _i in range(3):
                    for p in inside:
                        cgroup.move(p, dest)
                    inside = [p for p in inspect.descendants([op["root"]]) if p in set(op["pids"])
                              and cgroup.proc_cgroup(p) != "/user/%d/%s" % (os.getuid(), op["scope"])]
                    if not inside:
                        break
            else:
                for p in inside:
                    cgroup.move(p, dest)
            op["done"] = True
        fields = dict(op=op["op"], scope=op["scope"], count=len(op["pids"]),
                      skipped_protected=op["skipped_protected"])
        if execute:
            store.log(event="adopt", **fields)
        else:
            seen.add(op["scope"])
            if store.changed("adopt_would:" + op["scope"], (op["op"], tuple(sorted(op["pids"])),
                                                           op["skipped_protected"])):
                store.log(event="adopt_would", **fields)
    store.forget_sigs("adopt_would:", {"adopt_would:" + x for x in seen})
    store.save_if_dirty(knowledge.SAVE_INTERVAL)
    return ops


# ---- gc -----------------------------------------------------------------------------------

def _cpu_usage(path):
    """usage_usec from the leaf's cpu.stat, or None when unavailable."""
    try:
        with open(path + "/cpu.stat") as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def gc_candidates(cfg, units, store, idle_since, now=time.time, usage=None, skip=None, noted=None, pt=None):
    """Scopes that are unused: [(path, reason)]. Updates idle_since {rel: first-idle-ts}.

    usage {rel: usage_usec at idle start}: CPU that moves during the idle window means busy.
    skip: leaves never retried (protected member). noted: leaves already logged once.
    pt: the pass's ProcTable, scanned lazily. Empty app-*/scope-*/shared/* leaves come back
    with reason "empty" (never 'manager'). The ss snapshot is built only when a leaf needs it."""
    usage = {} if usage is None else usage
    skip = set() if skip is None else skip
    noted = set() if noted is None else noted
    base = cgroup.base()
    leaves = [d for d in cgroup.subdirs(base + "/shared")]
    unit_by_prefix = {u["unit"]["name"]: u for u in units if u.get("unit", {}).get("kind") == "app"}
    top = cgroup.subdirs(base)
    for d in top:
        n = os.path.basename(d)
        for un, u in unit_by_prefix.items():
            if (n == un or n.startswith(un + "-")) and u["unit"].get("stop_when_unneeded"):
                leaves.append(d)
    gc_set = set(leaves)
    leaves += [d for d in top if d not in gc_set and os.path.basename(d).startswith(EMPTY_PREFIXES)]
    live = {cgroup.rel(d) for d in leaves}
    for table in (idle_since, usage, skip, noted):
        for k in [k for k in table if k not in live]:
            table.discard(k) if isinstance(table, set) else table.pop(k)
    out = []
    snap = inspect.LazySnapshot()
    seeds = cfg.get("seeds", {})
    protect = set(seeds.get("share", [])) | set(seeds.get("persist", []))
    for d in leaves:
        rel = cgroup.rel(d)
        if rel in skip or os.path.basename(d) == "manager":
            continue
        pids = cgroup.tree_procs(d)
        if not pids:
            out.append((d, "empty"))
            continue
        if d not in gc_set:
            continue
        if rel.startswith("shared/"):
            pt = pt or inspect.ProcTable.scan()
            roots = [p for p in pids if not any(a in pids for a in pt.ancestors(p))]
            held = next((k for k in map(policy.exe_key, roots)
                         if k in protect or store.peek(k)["user_keep"] > 0), None)
            if held:
                if rel not in noted:
                    noted.add(rel)
                    store.log(event="gc_skip", scope=rel, why="share/persist seed or user keep: " + held)
                idle_since.pop(rel, None)
                continue
        u = next((v for k, v in unit_by_prefix.items() if os.path.basename(d).startswith(k)), None)
        gc = (u or {}).get("gc", {})
        # detector: pause process whose runtime directory is gone
        var = gc.get("env_dir_missing")
        if var:
            dirs = {inspect.environ(p).get(var) for p in pids}
            dirs.discard(None)
            if dirs and all(not os.path.isdir(x) for x in dirs):
                out.append((d, "%s gone: %s" % (var, sorted(dirs)[0])))
                continue
        s = snap.get()
        edge_map = inspect.edges(set(pids), s)
        busy = bool(edge_map) or not getattr(s, "ok", True)
        if gc.get("keep_while_children") and u:
            root_comm = (u.get("match") or {}).get("comm")
            busy = busy or any(inspect.comm(p) != root_comm for p in pids)
        if busy:
            idle_since.pop(rel, None)
            usage.pop(rel, None)
            continue
        cpu = _cpu_usage(d)
        if rel in idle_since and cpu is not None and usage.get(rel) is not None and cpu != usage[rel]:
            idle_since[rel] = now()   # CPU moved: not idle, restart the window
        first = idle_since.setdefault(rel, now())
        if cpu is not None:
            usage[rel] = cpu
        key = policy.exe_key(pids[0])
        grace = store.idle_grace(key, policy.timer(cfg, "idle_grace", 600))
        if now() - first >= grace:
            out.append((d, "idle %ds >= grace %ds" % (now() - first, grace)))
    return out


def remove_empty(path):
    """rmdir an empty leaf tree. False when a process is (or became) present or rmdir fails."""
    if os.path.basename(path) == "manager" or cgroup.tree_procs(path):
        return False
    try:
        cgroup.rmdir_tree(path)
        return True
    except OSError:
        return False
