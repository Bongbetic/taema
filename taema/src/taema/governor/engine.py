"""Decision and action engine: plan_stop/stop, adopt_pass, gc_pass."""

from contextlib import nullcontext
import fnmatch
import glob
import hashlib
import os
import signal
import sys
import time

from ..core import cgroup, process as inspect, signature as survivor_signature
from ..config import policy


class _LazySubprocess:
    def __getattr__(self, name):
        import subprocess as module

        return getattr(module, name)


# Preserve the patchable module seam without importing subprocess during startup.
subprocess = _LazySubprocess()


HOOK_TIMEOUT = 30
EMPTY_PREFIXES = ("app-", "scope-")
POLL_STEP = 0.05
LEFTOVER = "leftover"
AUTO_CAP = 64  # new app scopes per auto-adopt pass
AUTO_MAX_CPU = (
    1.0  # percent over the last minute; busier members are never auto-stopped
)


class Refused(Exception):
    pass


class Vetoed(Refused):
    """A user veto matched the stop target."""


# ---- helpers ------------------------------------------------------------------------------


def helper_path(cfg):
    return policy.expand(cfg["paths"].get("helper", policy.HELPER))


def helper_attach(cfg, pid, name):
    """Move one pid into scope-NAME through the root helper (needed from the login cgroup)."""
    r = subprocess.run(
        ["sudo", "-n", helper_path(cfg), "attach", str(pid), name],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise Refused(r.stderr.strip() or "attach failed")


def helper_oom_restore(cfg, pid, start, value, applied):
    """Restore a recorded oom_score_adj value through the root helper."""
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(start, int)
        or isinstance(start, bool)
        or start <= 0
        or not isinstance(value, int)
        or isinstance(value, bool)
        or not -1000 <= value <= 1000
        or not isinstance(applied, int)
        or isinstance(applied, bool)
        or not value <= applied <= 1000
    ):
        raise Refused("invalid OOM priority restore target")
    result = subprocess.run(
        [
            "sudo",
            "-n",
            helper_path(cfg),
            "oom-restore",
            str(pid),
            str(start),
            str(value),
            str(applied),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Refused(result.stderr.strip() or "OOM priority restore failed")


def helper_oom_record(cfg, pid, start, original, applied):
    """Register the original/applied score pair before the daemon raises a process score."""
    values = (pid, start, original, applied)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise Refused("invalid OOM priority record")
    if pid <= 1 or start <= 0 or not -1000 <= original < applied <= 1000:
        raise Refused("invalid OOM priority record")
    result = subprocess.run(
        [
            "sudo",
            "-n",
            helper_path(cfg),
            "oom-record",
            str(pid),
            str(start),
            str(original),
            str(applied),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Refused(result.stderr.strip() or "OOM priority record failed")


def helper_move(cfg, relpath, pids):
    pids = [str(p) for p in pids]
    for i in range(0, len(pids), 64):
        r = subprocess.run(
            ["sudo", "-n", helper_path(cfg), "move", relpath] + pids[i : i + 64],
            capture_output=True,
            text=True,
        )
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
        if n and (
            leaf == n or (u["unit"].get("kind") == "app" and leaf.startswith(n + "-"))
        ):
            return u
    return None


def generic_runtime_save_state_unit(unit):
    """Whether an explicitly matched generic container/VM opts into saved cleanup."""
    metadata = (unit or {}).get("unit", {})
    match = (unit or {}).get("match", {})
    unit_mem = (unit or {}).get("mem", {})
    command = unit_mem.get("save_state") if isinstance(unit_mem, dict) else None
    return (
        isinstance(metadata, dict)
        and metadata.get("kind") == "app"
        and metadata.get("class") in ("container", "vm")
        and isinstance(match, dict)
        and bool(match)
        and isinstance(command, list)
        and bool(command)
        and all(isinstance(arg, str) and arg for arg in command)
    )


# ---- stop ---------------------------------------------------------------------------------


def plan_stop(
    path,
    cfg,
    store,
    unit=None,
    force=False,
    hard=False,
    keep=(),
    pt=None,
    snap=None,
    veto_override=False,
):
    """Decide per member: kill | share | skip. Never touches anything.

    pt: the pass's ProcTable. snap: an inspect.LazySnapshot shared across passes; ss runs only
    when at least one member is unprotected (a candidate for kill)."""
    pids = cgroup.tree_procs(path)
    pset = set(pids)
    pt = pt or inspect.ProcTable.scan()
    vetoes = (
        vetoes_for_scope(store, path, unit=unit)
        if not veto_override and hasattr(store, "matching_vetoes")
        else []
    )
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
        key = policy.app_key(pid, units=[unit] if unit else ())
        d = {
            "pid": pid,
            "comm": inspect.comm(pid),
            "key": key,
            "edges": edge_map.get(pid, []),
        }
        reason = reasons[pid]
        if reason:
            d.update(action="skip", why=reason)
        elif vetoes:
            d.update(action="skip", why="vetoed " + store.describe_veto(vetoes[0]))
        elif d["edges"] and not hard:

            def describe_edge(edge):
                peers = edge.get("peers", [])
                detail = "%s %s" % (edge["kind"], edge["detail"])
                if edge["kind"] not in ("qmp", "podman_api"):
                    return detail
                names = []
                for peer in peers:
                    try:
                        name = inspect.comm(peer) or "process"
                    except (KeyError, OSError):
                        name = "process"
                    names.append("%s (pid %d)" % (name, peer))
                return detail + (" via " + ", ".join(names) if names else "")

            d.update(
                action="share",
                why="outside users: " + "; ".join(describe_edge(e) for e in d["edges"]),
            )
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
    members = set(
        cgroup.tree_procs(path)
    )  # after pinning: membership and protection re-checked
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


def vetoes_for_scope(store, path, unit=None, owner=None, signature=None, leftover=None):
    """Resolve every veto target against a leaf and its current member identities."""
    if not store._active_vetoes():
        return []
    members = []
    unit_name = (unit or {}).get("unit", {}).get("name")
    for pid in cgroup.tree_procs(path):
        start = inspect.starttime(pid)
        key = policy.app_key(pid, units=[unit] if unit else ())
        member = {
            "pid": pid,
            "start": start,
            "apps": [key] if key else [],
            "path": inspect.exe(pid) or "",
            "cgroup": cgroup.proc_cgroup(pid) or "",
            "unit": unit_name or "",
            "owners": store.owners_of(key, limit=1024) if key else [],
        }
        if owner:
            member["owner"] = owner
        if key:
            member["leftover"] = key
        members.append(member)
    if signature is None:
        signature = _matching_signature_veto(store, members)
    return store.matching_vetoes(
        scope=cgroup.rel(path),
        members=members,
        owner=owner,
        leftover=leftover,
        signature=signature,
        unit=unit_name,
        cgroup_path=cgroup.rel(path),
    )


def _matching_signature_veto(store, members):
    """Return an active signature veto matching this live member set, if one exists.

    Manual stops can run while the daemon is down, so they cannot depend on the daemon's
    in-memory lineage. A stored signature carries the owner and exact fingerprint inputs; using
    those inputs lets the current cgroup membership resolve the same stable id offline.
    """
    active = [
        veto for veto in store._active_vetoes() if veto.get("kind") == "signature"
    ]
    database = getattr(store, "db", None)
    if not active or database is None or not hasattr(database, "signature"):
        return None

    keys = []
    tty = False
    for member in members:
        apps = member.get("apps")
        if not isinstance(apps, (list, tuple)) or len(apps) != 1:
            return None
        key = apps[0]
        pid = member.get("pid")
        if not isinstance(key, str) or not key or not isinstance(pid, int):
            return None
        stat = inspect._parse_stat(inspect.read(pid, "stat"))
        if stat is None:
            return None
        keys.append(key)
        tty = tty or bool(stat.tty)

    if not keys:
        return None
    runtime_hash = survivor_signature.runtime_dir_hash()
    for veto in active:
        stored = database.signature(veto.get("value"))
        if not isinstance(stored, dict) or not isinstance(stored.get("owner"), str):
            continue
        try:
            current = survivor_signature.signature(
                stored["owner"],
                keys,
                runtime_hash,
                stored.get("runtime", ""),
                tty,
            )
        except (TypeError, ValueError):
            continue
        if current["id"] == veto.get("value"):
            return current["id"]
    return None


def veto_for_scope(store, path, unit=None, owner=None, signature=None, leftover=None):
    matches = vetoes_for_scope(store, path, unit, owner, signature, leftover)
    return matches[0] if matches else None


def restore_snapshot(pids, cfg, pt=None):
    """Return argv/cwd for a stopped root only when the user opted in to remembering argv."""
    if not cfg.get("learn", {}).get("remember_argv"):
        return None
    pids = {
        pid
        for pid in pids
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1
    }
    if not pids:
        return None
    pt = pt or inspect.ProcTable.scan()
    roots = sorted(
        pid for pid in pids if not any(parent in pids for parent in pt.ancestors(pid))
    )
    for pid in roots:
        snapshot = inspect.restore_command(pid)
        if snapshot:
            return snapshot
    return None


def _stop_impl(
    path,
    cfg,
    store,
    unit=None,
    timeout=None,
    force=False,
    hard=False,
    keep=(),
    dry_run=False,
    hook=None,
    passes=3,
    allow_sigkill=True,
    veto_override=False,
    decision_owner=None,
    signature=None,
    leftover=None,
):
    """Stop a scope: move shared members aside, run the hook, SIGTERM, SIGKILL leftovers, rmdir.
    allow_sigkill=False (auto mode, pairs not explicitly answered): members that ignore SIGTERM live."""
    self_guard(path)
    scope = cgroup.rel(path)
    if (unit or {}).get("kill", {}).get("never_stop"):
        store.log(
            event="unit_vetoed",
            trigger="stop",
            scope=scope,
            target="kill.never_stop",
        )
        raise Vetoed("unit veto: kill.never_stop")
    vetoes = vetoes_for_scope(store, path, unit, decision_owner, signature, leftover)
    if vetoes and not veto_override:
        veto = vetoes[0]
        store.log(
            event="vetoed",
            trigger="stop",
            scope=scope,
            target=store._target(veto),
            reason=veto.get("reason", ""),
            source=veto.get("source", "user"),
        )
        raise Vetoed("vetoed " + store.describe_veto(veto))
    if vetoes:
        for veto in vetoes:
            store.log(
                event="veto_override",
                trigger="manual_stop",
                scope=scope,
                target=store._target(veto),
                reason=veto.get("reason", ""),
                source=veto.get("source", "user"),
            )
    report = {
        "scope": cgroup.rel(path),
        "decisions": [],
        "removed": False,
        "left": [],
        "stopped": [],
        "restore": None,
    }
    stopped_pids = set()
    restore = None
    ran_hook = False
    counted, killed_keys, sigkill_keys = set(), set(), set()
    snap = (
        inspect.LazySnapshot()
    )  # one ss snapshot for all passes, built only if needed
    for _ in range(passes):
        pt = inspect.ProcTable.scan()
        plan = plan_stop(
            path,
            cfg,
            store,
            unit,
            force,
            hard,
            keep,
            pt=pt,
            snap=snap,
            veto_override=veto_override,
        )
        report["decisions"].extend(plan)
        if dry_run or not plan:
            break
        shared = [d for d in plan if d["action"] == "share"]
        kill = [d for d in plan if d["action"] == "kill"]
        restore = (
            restore_snapshot([d["pid"] for d in kill], cfg, pt=pt)
            if not dry_run
            else None
        )
        shared_pids = {d["pid"] for d in shared}
        roots = [
            d
            for d in shared
            if not any(a in shared_pids for a in pt.ancestors(d["pid"]))
        ]
        for d in shared:
            for e in d["edges"]:
                store.bump(d["key"], "shared_hits", 1.0)
        for r in roots:
            context = getattr(store, "decision_context", None)
            trace = (
                context(
                    "containment",
                    scope="shared/" + leaf_slug(r["comm"], r["pid"]),
                    owner=r["pid"],
                    authority="safety",
                    mode=cfg.get("mode", "observe"),
                    why="preserve a shared member during stop",
                )
                if callable(context)
                else nullcontext()
            )
            with trace:
                dest = cgroup.mkleaf("shared/" + leaf_slug(r["comm"], r["pid"]))
                moving = [p for p in pt.descendants([r["pid"]]) if p in shared_pids]
                dest_cg = "/user/%d/%s" % (os.getuid(), cgroup.rel(dest))
                for _i in range(3):
                    for p in moving:
                        cgroup.move(p, dest)
                    moving = [
                        p
                        for p in inspect.ProcTable.scan().descendants([r["pid"]])
                        if p in shared_pids and cgroup.proc_cgroup(p) != dest_cg
                    ]
                    if not moving:
                        break
                store.log(
                    event="containment",
                    source=report["scope"],
                    destination=cgroup.rel(dest),
                    owner=r["pid"],
                    pids=[r["pid"]],
                )
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
        grace = max(
            [
                store.graceful_timeout(
                    k,
                    (unit or {})
                    .get("kill", {})
                    .get("graceful", policy.timer(cfg, "graceful_timeout", 10)),
                )[0]
                for k in keys
            ]
            or [0]
        )
        for k in keys - counted:
            store.bump(k, "stops")
            counted.add(k)
        if timeout is not None:
            grace = float(timeout)
        term_sent = _signal_all(path, kill_set, signal.SIGTERM, cfg)
        exited = _wait_each(path, kill_set, grace)
        stopped_pids.update(set(term_sent) & set(exited))
        survivors = kill_set - set(exited)
        for d in kill:
            store.add_term_ms(d["key"], exited.get(d["pid"], grace * 1000))
            if d["key"] not in killed_keys:
                killed_keys.add(d["key"])
                store.bump(d["key"], "killed")
        if survivors and not allow_sigkill:
            report["unkilled"] = sorted(survivors)
            break
        if survivors:
            kill_sent = _signal_all(path, survivors, signal.SIGKILL, cfg)
            for d in kill:
                if d["pid"] in survivors and d["key"] not in sigkill_keys:
                    sigkill_keys.add(d["key"])
                    store.bump(d["key"], "sigkill_needed")
            killed = _wait_each(path, survivors, 5)
            stopped_pids.update(set(kill_sent) & set(killed))
    report["stopped"] = sorted(stopped_pids)
    if restore and restore["pid"] in stopped_pids:
        report["restore"] = {"argv": restore["argv"], "cwd": restore["cwd"]}
    if not dry_run:
        try:
            cgroup.rmdir_tree(path)
            report["removed"] = True
        except OSError as e:
            report["left"] = cgroup.tree_procs(path)
            report["error"] = str(e)
    store.log(
        event="stop",
        scope=report["scope"],
        dry_run=dry_run,
        removed=report["removed"],
        decisions=[
            {k: v for k, v in d.items() if k != "edges"} | {"edges": len(d["edges"])}
            for d in report["decisions"]
        ],
    )
    store.save_if_dirty()
    return report


def stop(
    path,
    cfg,
    store,
    unit=None,
    timeout=None,
    force=False,
    hard=False,
    keep=(),
    dry_run=False,
    hook=None,
    passes=3,
    allow_sigkill=True,
    decision_kind="stop",
    decision_authority=None,
    decision_why=None,
    decision_owner=None,
    veto_override=False,
    signature=None,
    leftover=None,
):
    """Trace a stop attempt unless its caller already established the decision context."""
    if policy.is_agent_scope(cgroup.rel(path)):
        raise Refused("agent leaf is never stopped")
    if not dry_run:
        thaw_managed_scope_before_stop(path, store)
    context = getattr(store, "decision_context", None)
    if not callable(context) or getattr(store, "_audit_context", None) is not None:
        return _stop_impl(
            path,
            cfg,
            store,
            unit,
            timeout,
            force,
            hard,
            keep,
            dry_run,
            hook,
            passes,
            allow_sigkill,
            veto_override,
            decision_owner,
            signature,
            leftover,
        )
    authority = decision_authority or ("manual" if force or unit is None else "unit")
    with context(
        decision_kind,
        scope=cgroup.rel(path),
        owner=decision_owner,
        authority=authority,
        mode=cfg.get("mode", "observe"),
        why=decision_why or "stop requested",
    ):
        return _stop_impl(
            path,
            cfg,
            store,
            unit,
            timeout,
            force,
            hard,
            keep,
            dry_run,
            hook,
            passes,
            allow_sigkill,
            veto_override,
            decision_owner,
            signature,
            leftover,
        )


def thaw_managed_scope_before_stop(path, store):
    """Thaw a Taema-managed freeze before any stop path can signal its members."""
    target_scope = cgroup.rel(path)
    managed = getattr(store, "data", {}).get("frozen_scopes", {})
    if not isinstance(managed, dict):
        return False
    targets = sorted(
        (
            scope
            for scope in managed
            if target_scope == scope or target_scope.startswith(scope + "/")
        ),
        key=lambda scope: scope.count("/"),
        reverse=True,
    )
    thawed_any = False
    for scope in targets:
        freeze_path = os.path.join(cgroup.base(), scope, "cgroup.freeze")
        try:
            with open(freeze_path, encoding="ascii") as source:
                frozen = source.read().strip() == "1"
            if frozen:
                with open(freeze_path, "w", encoding="ascii") as target:
                    target.write("0\n")
        except FileNotFoundError:
            frozen = False
        except OSError as error:
            raise Refused(
                "could not thaw managed scope %s before stop: %s" % (scope, error)
            ) from error
        clear = getattr(store, "clear_frozen_scope", None)
        if callable(clear):
            clear(scope)
        store.log(
            event="thaw",
            scope=scope,
            reason="before stop",
            source="stop",
            thawed=frozen,
        )
        thawed_any = thawed_any or frozen
    return thawed_any


def _slug(s):
    out = "".join(c if c.isalnum() and c.isascii() else "-" for c in s.lower()).strip(
        "-"
    )
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
_warned: set[str] = set()


def _matches(m, pid, env=None):
    if not any(
        k in m for k in _MATCH_KEYS
    ):  # an empty [match] would match every process
        w = repr(sorted(m.items()))
        if w not in _warned:
            _warned.add(w)
            print(
                "taema: [match] needs one of %s; ignoring %s"
                % (", ".join(_MATCH_KEYS), w),
                file=sys.stderr,
            )
        return False
    return unit_matches(m, pid)


def unit_matches(match, pid, *, exe=None, comm=None, cmdline=None):
    """Pure [match] evaluation. Overrides stand in for live process reads."""
    if not isinstance(match, dict) or not any(k in match for k in _MATCH_KEYS):
        return False
    if (
        "exe" in match
        and (exe if exe is not None else inspect.exe(pid)) != match["exe"]
    ):
        return False
    if "comm" in match and not fnmatch.fnmatchcase(
        comm if comm is not None else inspect.comm(pid), match["comm"]
    ):
        return False
    needle = match.get("cmdline_contains")
    if needle is not None and needle not in (
        cmdline if cmdline is not None else inspect.cmdline(pid)
    ):
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
        matched = [
            p
            for p in in_session
            if _matches(m, p) and not policy.protected_reason(p, cfg)
        ]
        roots = [p for p in matched if not any(a in matched for a in pp.ancestors(p))]
        groups = {}
        for r in roots:
            env = inspect.environ(r)
            gb = u["unit"].get("group_by_env")
            if gb:
                val = env.get(gb)
                if not val or policy.env_excluded(env, m.get("env_exclude")):
                    continue
                groups.setdefault(
                    name + "-" + hashlib.sha1(val.encode()).hexdigest()[:8], (val, [])
                )[1].append(r)
            elif u["unit"].get("group_by_qmp") is True:
                sockets = inspect.qmp_socket_paths(r)
                val = sockets[0] if sockets else "%s#%d" % (cgroup.proc_cgroup(r), r)
                groups.setdefault(
                    name + "-" + hashlib.sha1(val.encode()).hexdigest()[:8],
                    (None, []),
                )[1].append(r)
            else:
                groups.setdefault(name, (None, []))[1].append(r)
        for scope, (val, rs) in groups.items():
            extra = []
            for c in u.get("children", []):
                if "same_env" in c and gb and val is not None:
                    extra += [
                        p
                        for p in in_session
                        if inspect.comm(p) == c.get("comm")
                        and inspect.environ(p).get(c["same_env"]) == val
                    ]
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
        for scope_dir in [
            d
            for d in cgroup.subdirs(base)
            if os.path.basename(d) == u["unit"]["name"]
            or os.path.basename(d).startswith(u["unit"]["name"] + "-")
        ]:
            direct = set(cgroup.procs(scope_dir))
            for c in u["children"]:
                if "ancestor_comm" not in c and "comm" not in c:
                    continue
                want = c.get("ancestor_comm") or c.get("comm")
                roots = [p for p in direct if inspect.comm(p) == want]
                roots = [
                    p for p in roots if not any(a in roots for a in pp.ancestors(p))
                ]
                for r in roots:
                    members = [p for p in pp.descendants([r]) if p in direct]
                    ops.append(
                        {
                            "op": "carve",
                            "parent": os.path.basename(scope_dir),
                            "scope": "%s/%s-%d"
                            % (os.path.basename(scope_dir), c["name"], r),
                            "root": r,
                            "binds_to": c.get("binds_to"),
                            "pids": members,
                        }
                    )
    return ops


def _inside_user(pid):
    """True when pid already sits in user/<uid> (a move from there needs no root helper)."""
    cg = cgroup.proc_cgroup(pid) or ""
    me = "/user/%d" % os.getuid()
    return cg == me or cg.startswith(me + "/")


def run_ops(
    cfg,
    store,
    ops,
    execute,
    cleanup=True,
    decision_kind="adopt_move",
    authority="mode",
):
    """Log every op; perform it when `execute`. Returns the ops with a 'done' flag.
    Pids inside user/<uid> move directly; the sudo helper is used only for pids in a session
    cgroup. A repeated adopt_would for an identical op is not logged again. Callers batching
    multiple plans can defer stale-signature cleanup until the batch is complete."""
    seen = set()
    for op in ops:
        op["done"] = False
        pids = [p for p in op["pids"] if not policy.protected_reason(p, cfg)]
        op["skipped_protected"] = len(op["pids"]) - len(pids)
        op["pids"] = pids
        should_log = execute or not pids
        if not execute:
            seen.add(op["scope"])
            should_log = store.changed(
                "adopt_would:" + op["scope"],
                (op["op"], tuple(sorted(op["pids"])), op["skipped_protected"]),
            )
        if not should_log:
            continue
        kind = decision_kind if execute else "adopt_would"
        context = getattr(store, "decision_context", None)
        trace = (
            context(
                kind,
                scope=op["scope"],
                owner=op.get("owner", op.get("root")),
                authority=authority,
                mode=cfg.get("mode", "observe"),
                why=op.get("why") or "%s %s" % (op["op"], op["scope"]),
            )
            if callable(context)
            else nullcontext()
        )
        with trace as decision:
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
                        inside = [
                            p
                            for p in inspect.descendants([op["root"]])
                            if p in set(op["pids"])
                            and cgroup.proc_cgroup(p)
                            != "/user/%d/%s" % (os.getuid(), op["scope"])
                        ]
                        if not inside:
                            break
                else:
                    for p in inside:
                        cgroup.move(p, dest)
                op["done"] = True
                if (
                    isinstance(decision, dict)
                    and decision_kind in ("adopt_move", "containment")
                    and authority != "user"
                ):
                    members = []
                    for pid in pids:
                        start = inspect.starttime(pid)
                        key = policy.app_key(pid)
                        if start is not None and key:
                            members.append({"pid": pid, "start": start, "key": key})
                    if members:
                        decision["undo"] = {
                            "operation": "adopt_standalone",
                            "scope": op["scope"],
                            "members": members,
                        }
                        decision["undoable"] = True
            fields = dict(
                op=op["op"],
                scope=op["scope"],
                count=len(op["pids"]),
                skipped_protected=op["skipped_protected"],
            )
            if execute and pids:
                store.log(event=decision_kind, **fields)
            elif execute:
                store.log(
                    event="refusal",
                    scope=op["scope"],
                    why="all planned members were protected",
                    **fields,
                )
            else:
                store.log(event="adopt_would", **fields)
            if isinstance(decision, dict):
                op["decision_id"] = decision["id"]
                op["corr"] = decision["corr"]
    if cleanup:
        store.forget_sigs("adopt_would:", {"adopt_would:" + x for x in seen})
    store.save_if_dirty()
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


def gc_candidates(
    cfg,
    units,
    store,
    idle_since,
    now=time.time,
    usage=None,
    skip=None,
    noted=None,
    pt=None,
    lin=None,
    auto=False,
    authority="learned",
    signature_for_scope=None,
):
    """Scopes that are unused: [(path, reason)]. Updates idle_since {rel: first-idle-ts}.

    usage {rel: usage_usec at idle start}: CPU that moves during the idle window means busy.
    skip: leaves never retried (protected member). noted: leaves already logged once.
    pt: the pass's ProcTable, scanned lazily. Empty app-*/scope-*/shared/* leaves come back
    with reason "empty" (never 'manager'). The ss snapshot is built only when a leaf needs it.
    auto (with lin, the Lineage): leftover/* leaves are candidates too, "pair stop ..." when every
    member passes auto_stop_ok, else by the idle rule unless a member is held (open review, protected,
    persist seed, share seed with user_keep, pair decided keep, pty host)."""
    usage = {} if usage is None else usage
    skip = set() if skip is None else skip
    noted = set() if noted is None else noted
    base = cgroup.base()
    leaves = [d for d in cgroup.subdirs(base + "/shared")]
    unit_by_prefix = {
        u["unit"]["name"]: u for u in units if u.get("unit", {}).get("kind") == "app"
    }
    top = cgroup.subdirs(base)
    for d in top:
        n = os.path.basename(d)
        for un, u in unit_by_prefix.items():
            if (n == un or n.startswith(un + "-")) and (
                u["unit"].get("stop_when_unneeded")
                or generic_runtime_save_state_unit(u)
            ):
                leaves.append(d)
    left_dirs = cgroup.subdirs(base + "/" + LEFTOVER)
    if auto:
        leaves += left_dirs
    gc_set = set(leaves)
    if not auto:
        leaves += left_dirs  # empty ones only
    leaves += [
        d
        for d in top
        if d not in gc_set and os.path.basename(d).startswith(EMPTY_PREFIXES)
    ]
    live = {cgroup.rel(d) for d in leaves}
    store.prune_leftover_expiries(live)
    store.prune_scope_reviews(live)
    for table in (idle_since, usage, skip, noted):
        for k in [k for k in table if k not in live]:
            table.discard(k) if isinstance(table, set) else table.pop(k)
    out = []
    snap = inspect.LazySnapshot()
    runtime_process_names = None
    runtime_process_scan_failed = False
    runtime_process_scan_done = False
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
        if not (auto and rel.startswith(LEFTOVER + "/")) and store.review_holds_scope(
            rel
        ):
            if rel not in noted:
                noted.add(rel)
                store.log(event="gc_skip", scope=rel, why="GC review pending")
            idle_since.pop(rel, None)
            continue
        if rel.startswith("shared/"):
            pt = pt or inspect.ProcTable.scan()
            roots = [p for p in pids if not any(a in pids for a in pt.ancestors(p))]
            held = next(
                (
                    k
                    for k in (policy.app_key(p, units=units) for p in roots)
                    if k in protect or store.peek(k)["user_keep"] > 0
                ),
                None,
            )
            if held:
                if rel not in noted:
                    noted.add(rel)
                    store.log(
                        event="gc_skip",
                        scope=rel,
                        why="share/persist seed or user keep: " + held,
                    )
                idle_since.pop(rel, None)
                continue
        if auto and rel.startswith(LEFTOVER + "/"):
            expiry_days = policy.timer(cfg, "leftover_expire_days", 0)
            expiry_due = store.leftover_expiry_due(rel, expiry_days, now=now())
            if store.review_holds_scope(rel) and not expiry_due:
                if rel not in noted:
                    noted.add(rel)
                    store.log(event="gc_skip", scope=rel, why="close review pending")
                idle_since.pop(rel, None)
                continue
            verdict = _leftover_verdict(
                cfg,
                store,
                lin,
                pids,
                snap,
                protect,
                scope=rel,
                expiry_days=expiry_days,
                at=now(),
                signature=(
                    signature_for_scope(d, pids)
                    if callable(signature_for_scope)
                    else None
                ),
                authority=authority,
            )
            if verdict[0] == "held":
                if rel not in noted:
                    noted.add(rel)
                    store.log(
                        event="gc_skip", scope=rel, why="leftover held: " + verdict[1]
                    )
                idle_since.pop(rel, None)
                continue
            if verdict[0] == "stop":
                out.append((d, "pair stop: " + verdict[1]))
                continue
        u = next(
            (v for k, v in unit_by_prefix.items() if os.path.basename(d).startswith(k)),
            None,
        )
        gc = (u or {}).get("gc", {})
        no_attach_grace = gc.get("no_attach_grace")
        has_no_attach_grace = (
            isinstance(no_attach_grace, (int, float))
            and not isinstance(no_attach_grace, bool)
            and no_attach_grace >= 0
        )
        # A missing runtime endpoint or process provides evidence that the app has quit.
        runtime_quit_reason = None
        var = gc.get("env_dir_missing")
        if var:
            dirs = {inspect.environ(p).get(var) for p in pids}
            dirs.discard(None)
            if dirs and all(not os.path.isdir(x) for x in dirs):
                runtime_quit_reason = "%s gone: %s" % (var, sorted(dirs)[0])
        socket_env = gc.get("socket_env")
        socket_path = gc.get("socket_path")
        if (
            isinstance(socket_env, str)
            and socket_env
            and isinstance(socket_path, str)
            and socket_path
            and not os.path.isabs(socket_path)
            and ".." not in socket_path.split(os.sep)
        ):
            socket_paths = {
                os.path.join(value, socket_path)
                for p in pids
                if (value := inspect.environ(p).get(socket_env))
            }
            if socket_paths and all(not os.path.exists(path) for path in socket_paths):
                runtime_quit_reason = (
                    "runtime socket gone: %s" % sorted(socket_paths)[0]
                )
        socket_glob = gc.get("socket_glob")
        if (
            isinstance(socket_glob, str)
            and socket_glob.startswith(os.sep)
            and ".." not in socket_glob.split(os.sep)
        ):
            socket_paths = glob.glob(socket_glob)
            if not any(os.path.exists(path) for path in socket_paths):
                runtime_quit_reason = "runtime socket gone: %s" % socket_glob
        quit_process_missing = gc.get("quit_process_missing")
        runtime_process_live = False
        if (
            isinstance(quit_process_missing, str)
            and quit_process_missing
            and not any(ord(char) < 32 for char in quit_process_missing)
        ):
            if not runtime_process_scan_done:
                runtime_process_scan_done = True
                runtime_process_names = []
                try:
                    for pid in inspect.all_pids():
                        process_uid = inspect.uid_of(pid)
                        if (
                            not isinstance(process_uid, int)
                            or isinstance(process_uid, bool)
                            or process_uid < 0
                        ):
                            runtime_process_scan_failed = True
                            break
                        if process_uid != os.getuid():
                            continue
                        process_name = inspect.comm(pid)
                        if not process_name:
                            runtime_process_scan_failed = True
                            break
                        runtime_process_names.append(process_name)
                except OSError:
                    # A failed process scan is not proof that a runtime has quit.
                    runtime_process_scan_failed = True
            runtime_process_live = runtime_process_scan_failed or any(
                fnmatch.fnmatchcase(name, quit_process_missing)
                for name in runtime_process_names
            )
            if not runtime_process_live and runtime_quit_reason is None:
                runtime_quit_reason = "runtime process gone: %s" % quit_process_missing
        if gc.get("qmp_socket") is True:
            qmp_paths = {path for p in pids for path in inspect.qmp_socket_paths(p)}
            if qmp_paths and all(not os.path.exists(path) for path in qmp_paths):
                runtime_quit_reason = "QMP socket gone: %s" % sorted(qmp_paths)[0]
        s = snap.get()
        edge_map = inspect.edges(set(pids), s)
        busy = bool(edge_map) or not getattr(s, "ok", True) or runtime_process_live
        if gc.get("keep_while_children") and u and not has_no_attach_grace:
            root_match = u.get("match") or {}
            busy = busy or any(not _matches(root_match, p) for p in pids)
        if busy:
            idle_since.pop(rel, None)
            usage.pop(rel, None)
            continue
        cpu = _cpu_usage(d)
        if (
            rel in idle_since
            and cpu is not None
            and usage.get(rel) is not None
            and cpu != usage[rel]
            and not has_no_attach_grace
            and runtime_quit_reason is None
        ):
            idle_since[rel] = now()  # CPU moved: not idle, restart the window
        first = idle_since.setdefault(rel, now())
        if cpu is not None:
            usage[rel] = cpu
        if runtime_quit_reason:
            out.append((d, runtime_quit_reason))
            continue
        if has_no_attach_grace and now() - first >= no_attach_grace:
            out.append((d, "no attachment for %ds" % int(now() - first)))
            continue
        key = policy.app_key(pids[0], units=units)
        grace = store.idle_grace(key, policy.timer(cfg, "idle_grace", 600))
        if now() - first >= grace:
            if auto and rel.startswith(LEFTOVER + "/") and expiry_due:
                out.append((d, "leftover expired after %s days" % expiry_days))
            else:
                out.append((d, "idle %ds >= grace %ds" % (now() - first, grace)))
    return out


def _leftover_verdict(
    cfg,
    store,
    lin,
    pids,
    snap,
    protect,
    scope="",
    expiry_days=0,
    at=None,
    signature=None,
    authority="learned",
):
    """("stop", why) when every member passes auto_stop_ok, ("held", why) when a member must not be
    stopped by the idle rule, else ("idle", "")."""
    s = snap.get()
    ok = getattr(s, "ok", True)
    edge_map = inspect.edges(set(pids), s)
    infos = [member_info(cfg, lin, p, edge_map, ok) for p in pids]
    for i in infos:
        if i["protected"]:
            return "held", "protected: " + i["protected"]
        if i["ptmx"]:
            return "held", "pty host %s" % i["key"]
        if i["key"] in protect and (
            store.is_persistent(i["key"]) or store.peek(i["key"])["user_keep"] > 0
        ):
            return "held", "persist/share seed " + i["key"]
        if i["origin"] and store.pair_decision(i["origin"], i["key"])[0] == "keep":
            if not store.leftover_expiry_overrides_keep(
                i["origin"], i["key"], scope, expiry_days, now=at
            ):
                return "held", "pair decided keep: %s>%s" % (i["origin"], i["key"])
    for i in infos:
        veto = _member_veto(
            store,
            i["origin"],
            i["key"],
            i,
            scope=scope,
            signature=signature,
        )
        if veto:
            with store.decision_context(
                "refusal",
                scope=scope,
                authority="veto",
                why="veto blocked automatic leftover stop",
            ):
                store.log(
                    event="vetoed",
                    trigger="gc_stop",
                    scope=scope,
                    target=store._target(veto),
                    source=veto.get("source", "user"),
                )
            return "held", "vetoed " + store.describe_veto(veto)
    res = [
        auto_stop_ok(
            store,
            i["origin"],
            i["key"],
            i,
            authority=authority,
            scope=scope,
            signature=signature,
        )
        for i in infos
    ]
    if infos and all(r[0] for r in res):
        return "stop", res[0][1]
    return "idle", ""


def remove_empty(path):
    """rmdir an empty leaf tree. False when a process is (or became) present or rmdir fails."""
    if (
        os.path.basename(path) == "manager"
        or policy.is_agent_scope(cgroup.rel(path))
        or cgroup.tree_procs(path)
    ):
        return False
    try:
        cgroup.rmdir_tree(path)
        return True
    except OSError:
        return False


# ---- auto mode ------------------------------------------------------------------------------


def member_info(cfg, lin, pid, edge_map, edges_ok=True, origin=None):
    """Facts auto_stop_ok needs about one process. edges None = unknown (ss failed)."""
    e = lin.entry(pid) if lin is not None else None
    units = getattr(lin, "units", ()) if lin is not None else ()
    return {
        "pid": pid,
        "start": inspect.starttime(pid),
        "key": e["key"] if e else policy.app_key(pid, units=units),
        "origin": origin if origin is not None else (e["root_key"] if e else ""),
        "edges": edge_map.get(pid, []) if edges_ok else None,
        "protected": policy.protected_reason(pid, cfg),
        "ptmx": bool(lin is not None and lin.ptmx_host(pid)),
        "cpu": lin.cpu_pct(pid) if lin is not None else None,
    }


def auto_stop_ok(
    store,
    owner_key,
    leftover_key,
    mi,
    decision=None,
    authority="learned",
    scope=None,
    signature=None,
    unit=None,
):
    """May auto mode stop this member? (ok, why). A pair or matched survivor signature must decide
    "stop", and the member must be plainly idle and known: no edges, not protected / a pty host / a
    persist seed / a share seed the user keeps, <= 1 % CPU over the last minute, origin known.
    Anything unknown keeps."""
    action, _conf, why = decision or (
        store.pair_decision(owner_key, leftover_key) if owner_key else ("ask", 0, "")
    )
    if action != "stop":
        return False, "learning decision is %s" % action
    if authority == "answered" and not store.explicit_stop((action, _conf, why)):
        return False, "learning authority requires an explicit stop answer"
    veto = _member_veto(
        store,
        owner_key,
        leftover_key,
        mi,
        scope=scope,
        signature=signature,
        unit=unit,
    )
    if veto:
        return False, "vetoed " + store.describe_veto(veto)
    if not mi.get("origin"):
        return False, "origin unknown"
    if mi.get("edges") is None:
        return False, "edges unknown"
    if mi["edges"]:
        return False, "has edges"
    if mi.get("protected"):
        return False, "protected: %s" % mi["protected"]
    if mi.get("ptmx"):
        return False, "pty host"
    if store.is_persistent(leftover_key):
        return False, "persist seed"
    if (
        leftover_key in store.seeds.get("share", [])
        and store.peek(leftover_key)["user_keep"] > 0
    ):
        return False, "share seed kept by user"
    cpu = mi.get("cpu")
    if cpu is None:
        return False, "cpu unknown"
    if cpu > AUTO_MAX_CPU:
        return False, "cpu %.1f%% > %.0f%%" % (cpu, AUTO_MAX_CPU)
    return True, why


def _member_veto(store, owner, leftover, mi, scope=None, signature=None, unit=None):
    """Resolve a veto against one known member and the automatic-stop context."""
    if not store._active_vetoes():
        return None
    pid = mi.get("pid")
    start = mi.get("start")
    if start is None and isinstance(pid, int):
        start = inspect.starttime(pid)
    apps = [leftover] if isinstance(leftover, str) and leftover else []
    owners = store.owners_of(leftover, limit=1024) if apps else []
    if owner and owner not in owners:
        owners.append(owner)
    member = {
        "pid": pid,
        "start": start,
        "apps": apps,
        "owner": owner or "",
        "owners": owners,
        "leftover": leftover or "",
        "unit": mi.get("unit") or unit or "",
        "path": mi.get("path") or (inspect.exe(pid) if isinstance(pid, int) else ""),
        "cgroup": mi.get("cgroup")
        or (cgroup.proc_cgroup(pid) if isinstance(pid, int) else "")
        or "",
    }
    return store.match_veto(
        scope=scope,
        members=[member],
        owner=owner,
        leftover=leftover,
        signature=signature,
        unit=member["unit"] or None,
        cgroup_path=scope,
    )


def auto_grace(store, keys):
    """SIGTERM grace for an auto stop: max(5 s, p95 x 1.5) capped at 30 s."""
    return min(30.0, max([5.0] + [store.graceful_timeout(k, 5)[0] for k in keys]))


def auto_scope_name(key, pid, start):
    return "app-%s-%s" % (
        leaf_slug(key),
        hashlib.sha1(("%d.%d" % (pid, start)).encode()).hexdigest()[:6],
    )


def auto_adopt_plan(cfg, units, table, lin, store, cap=AUTO_CAP):
    """Move ops giving each app root its own scope app-<key>-<hash>, with every member of the
    root that still sits in a session cgroup. Not adopted: session leaders, protected, pty hosts,
    anything younger than 5 s (lin.root_for), terminal jobs (they stay in their host's scope),
    roots already outside the session cgroups, and roots a unit with [match] claims."""
    in_session = set()
    for session in policy.session_cgroups(cfg):
        in_session.update(cgroup.procs(session))
    explicit = [
        u["match"]
        for u in units
        if u.get("match") and u.get("unit", {}).get("kind") == "app"
    ]
    by_root = {}
    for e in lin.entries.values():
        if e["root"] is not None and e["pid"] in in_session:
            by_root.setdefault(e["root"], []).append(e["pid"])
    ops = []
    for rid in sorted(by_root, key=lambda r: (r[1], r[0])):
        if len(ops) >= cap:
            break
        rpid = rid[0]
        e = lin.entry(rpid)
        if (
            e is None
            or rpid not in in_session
            or lin.root_for(rpid) != rpid
            or e["sid"] == rpid
        ):
            continue
        if (
            lin.is_terminal_job(e)
            or policy.protected_reason(rpid, cfg)
            or lin.ptmx_host(rpid)
        ):
            continue
        if explicit and any(
            _matches(m, p)
            for m in explicit
            for p in [rpid] + [c[0] for c in e["chain_ids"]]
        ):
            continue
        ops.append(
            {
                "op": "move",
                "scope": auto_scope_name(e["key"], rpid, e["start"]),
                "unit": None,
                "auto": True,
                "pids": sorted(by_root[rid]),
            }
        )
    return ops


def signal_survivors(cfg, items, grace, allow_sigkill, store=None):
    """Stop job survivors that cannot be carved (they live outside user/<uid>): SIGTERM through a
    pidfd-pinned _signal_all, wait, SIGKILL only when allowed. items: [{"pid","start"}]. Returns the
    pids that left the scope after a signal was sent."""
    groups = {}
    for it in items:
        if inspect.starttime(it["pid"]) != it["start"]:
            continue
        cg = cgroup.proc_cgroup(it["pid"])
        if cg:
            groups.setdefault(cgroup.CG + cg, []).append(it["pid"])
    stopped = set()
    for path, pids in groups.items():
        try:
            self_guard(path)
            if store is not None:
                thaw_managed_scope_before_stop(path, store)
        except Refused:
            continue
        term_sent = _signal_all(path, pids, signal.SIGTERM, cfg)
        exited = _wait_each(path, pids, grace)
        stopped.update(set(term_sent) & set(exited))
        left = set(pids) - set(exited)
        if left and allow_sigkill:
            kill_sent = _signal_all(path, left, signal.SIGKILL, cfg)
            killed = _wait_each(path, left, 5)
            stopped.update(set(kill_sent) & set(killed))
    return sorted(stopped)
