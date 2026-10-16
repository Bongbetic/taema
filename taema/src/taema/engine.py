"""Decision and action engine: plan_stop/stop, adopt_pass, gc_pass."""
import fnmatch
import hashlib
import os
import signal
import subprocess
import time

from . import cgroup, inspect, policy


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

def plan_stop(path, cfg, store, unit=None, force=False, hard=False, keep=()):
    """Decide per member: kill | share | skip. Never touches anything."""
    pids = cgroup.tree_procs(path)
    pset = set(pids)
    pp = inspect.ppid_map()
    edge_map = inspect.edges(pset, inspect.Snapshot())
    keep_set = set(keep) | set((unit or {}).get("kill", {}).get("keep", []))
    out = {}
    for pid in pids:
        key = policy.exe_key(pid)
        d = {"pid": pid, "comm": inspect.comm(pid), "key": key, "edges": edge_map.get(pid, [])}
        reason = policy.protected_reason(pid, cfg)
        if reason:
            d.update(action="skip", why=reason)
        elif d["edges"] and not hard:
            d.update(action="share", why="outside users: " + "; ".join(
                "%s %s" % (e["kind"], e["detail"]) for e in d["edges"]))
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
        if d["action"] == "kill" and any(a in shared for a in inspect.ancestors(pid, pp)):
            d.update(action="share", why="descendant of a shared process")
    return list(out.values())


def _wait_gone(path, kill_set, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not (set(cgroup.tree_procs(path)) & kill_set):
            return True
        time.sleep(0.1)
    return not (set(cgroup.tree_procs(path)) & kill_set)


def stop(path, cfg, store, unit=None, timeout=None, force=False, hard=False, keep=(),
         dry_run=False, hook=None, passes=3):
    """Stop a scope: move shared members aside, run the hook, SIGTERM, SIGKILL leftovers, rmdir."""
    self_guard(path)
    report = {"scope": cgroup.rel(path), "decisions": [], "removed": False, "left": []}
    ran_hook = False
    for _ in range(passes):
        plan = plan_stop(path, cfg, store, unit, force, hard, keep)
        report["decisions"].extend(plan)
        if dry_run or not plan:
            break
        shared = [d for d in plan if d["action"] == "share"]
        kill = [d for d in plan if d["action"] == "kill"]
        pp = inspect.ppid_map()
        shared_pids = {d["pid"] for d in shared}
        roots = [d for d in shared if not any(a in shared_pids for a in inspect.ancestors(d["pid"], pp))]
        for d in shared:
            for e in d["edges"]:
                store.bump(d["key"], "shared_hits", 1.0)
        for r in roots:
            dest = cgroup.mkleaf("shared/%s-%d" % (_slug(r["comm"]), r["pid"]))
            moving = [p for p in inspect.descendants([r["pid"]], pp) if p in shared_pids]
            dest_cg = "/user/%d/%s" % (os.getuid(), cgroup.rel(dest))
            for _i in range(3):
                for p in moving:
                    cgroup.move(p, dest)
                moving = [p for p in inspect.descendants([r["pid"]]) if p in shared_pids
                          and cgroup.proc_cgroup(p) != dest_cg]
                if not moving:
                    break
        if not ran_hook:
            ran_hook = True
            hook = hook or ((unit or {}).get("kill", {}).get("hook"))
            if hook:
                hook = policy.expand(hook)
                if os.access(hook, os.X_OK):
                    subprocess.run([hook], timeout=30)
        if not kill:
            break
        kill_set = {d["pid"] for d in kill}
        keys = {d["key"] for d in kill}
        grace = max([store.graceful_timeout(k, (unit or {}).get("kill", {}).get("graceful",
                     policy.timer(cfg, "graceful_timeout", 10)))[0] for k in keys] or [0])
        if timeout is not None:
            grace = float(timeout)
        t0 = time.monotonic()
        for pid in kill_set:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        gone = _wait_gone(path, kill_set, grace)
        ms = (time.monotonic() - t0) * 1000
        for d in kill:
            store.bump(d["key"], "killed")
            store.add_term_ms(d["key"], ms if gone else grace * 1000)
        if not gone:
            for pid in set(cgroup.tree_procs(path)) & kill_set:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for d in kill:
                if d["pid"] in set(cgroup.tree_procs(path)) | kill_set:
                    store.bump(d["key"], "sigkill_needed")
            _wait_gone(path, kill_set, 5)
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
    store.save()
    return report


def _slug(s):
    out = "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")
    return out[:24] or "proc"


# ---- adopt --------------------------------------------------------------------------------

def _matches(m, pid, env=None):
    if "exe" in m and inspect.exe(pid) != m["exe"]:
        return False
    if "comm" in m and inspect.comm(pid) != m["comm"]:
        return False
    if "cmdline_contains" in m and m["cmdline_contains"] not in inspect.cmdline(pid):
        return False
    return True


def adopt_plan(cfg, units, pp=None):
    """Operations that move matching processes out of the login session cgroup."""
    in_session = set()
    for session in policy.session_cgroups(cfg):
        in_session.update(cgroup.procs(session))
    pp = pp or inspect.ppid_map()
    ops = []
    for u in units:
        m = u.get("match")
        if not m or u.get("unit", {}).get("kind") != "app":
            continue
        name = u["unit"]["name"]
        matched = [p for p in in_session if _matches(m, p) and not policy.protected_reason(p, cfg)]
        roots = [p for p in matched if not any(a in matched for a in inspect.ancestors(p, pp))]
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
            moved = [p for p in inspect.descendants(rs + extra, pp) if p in in_session]
            ops.append({"op": "move", "scope": scope, "unit": name, "pids": moved})
    return ops


def carve_plan(cfg, units, pp=None):
    """Child scopes (sessions, vm) for processes sitting directly in an app scope."""
    pp = pp or inspect.ppid_map()
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
                roots = [p for p in roots if not any(a in roots for a in inspect.ancestors(p, pp))]
                for r in roots:
                    members = [p for p in inspect.descendants([r], pp) if p in direct]
                    ops.append({"op": "carve", "parent": os.path.basename(scope_dir),
                                "scope": "%s/%s-%d" % (os.path.basename(scope_dir), c["name"], r),
                                "root": r, "binds_to": c.get("binds_to"), "pids": members})
    return ops


def run_ops(cfg, store, ops, execute):
    """Log every op; perform it when `execute`. Returns the ops with a 'done' flag."""
    for op in ops:
        op["done"] = False
        pids = [p for p in op["pids"] if not policy.protected_reason(p, cfg)]
        op["skipped_protected"] = len(op["pids"]) - len(pids)
        op["pids"] = pids
        if execute and pids:
            cgroup.mkleaf(op["scope"])
            if op["op"] == "move":
                helper_move(cfg, op["scope"], pids)
            else:
                dest = cgroup.base() + "/" + op["scope"]
                for _i in range(3):
                    for p in pids:
                        cgroup.move(p, dest)
                    pids = [p for p in inspect.descendants([op["root"]]) if p in set(op["pids"])
                            and cgroup.proc_cgroup(p) != "/user/%d/%s" % (os.getuid(), op["scope"])]
                    if not pids:
                        break
            op["done"] = True
        store.log(event="adopt" if execute else "adopt_would", op=op["op"], scope=op["scope"],
                  count=len(op["pids"]), skipped_protected=op["skipped_protected"])
    store.save()
    return ops


# ---- gc -----------------------------------------------------------------------------------

def gc_candidates(cfg, units, store, idle_since, now=time.time):
    """Scopes that are unused: [(path, reason)]. Updates idle_since {rel: first-idle-ts}."""
    base = cgroup.base()
    leaves = [d for d in cgroup.subdirs(base + "/shared")]
    unit_by_prefix = {u["unit"]["name"]: u for u in units if u.get("unit", {}).get("kind") == "app"}
    for d in cgroup.subdirs(base):
        n = os.path.basename(d)
        for un, u in unit_by_prefix.items():
            if (n == un or n.startswith(un + "-")) and u["unit"].get("stop_when_unneeded"):
                leaves.append(d)
    out = []
    snap = inspect.Snapshot()
    for d in leaves:
        rel = cgroup.rel(d)
        pids = cgroup.tree_procs(d)
        if not pids:
            out.append((d, "empty"))
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
        edge_map = inspect.edges(set(pids), snap)
        busy = bool(edge_map)
        if gc.get("keep_while_children") and u:
            root_comm = (u.get("match") or {}).get("comm")
            busy = busy or any(inspect.comm(p) != root_comm for p in pids)
        if busy:
            idle_since.pop(rel, None)
            continue
        first = idle_since.setdefault(rel, now())
        key = policy.exe_key(pids[0])
        grace = store.idle_grace(key, policy.timer(cfg, "idle_grace", 600))
        if now() - first >= grace:
            out.append((d, "idle %ds >= grace %ds" % (now() - first, grace)))
    return out
