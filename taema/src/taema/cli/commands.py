"""`taema` command line. scoperun / scopekill / scopels are thin aliases (see bin/)."""

import argparse
import json
import os
import socket
import sys
import tempfile
import time
import uuid

from ..model import authorization
from ..core import cgroup, process as inspect, lineage
from ..governor import engine
from ..store import knowledge
from ..config import policy


def _load():
    cfg = policy.load_config()
    store = knowledge.Store(
        policy.state_dir(cfg),
        cfg.get("seeds"),
        read_only=True,
        deny=policy.owner_deny(cfg),
    )
    return cfg, store, policy.load_units(cfg)


def sock_paths(cfg):
    """[primary, fallback]. The daemon binds the first whose directory exists (the fallback at
    boot, before login creates /run/user/<uid>); clients try both."""
    primary = cfg["paths"]["socket"]
    fallback = policy.expand(cfg["paths"]["socket_fallback"])
    return [primary, fallback]


def sock_path(cfg):
    primary, fallback = sock_paths(cfg)
    return primary if os.path.isdir(os.path.dirname(primary)) else fallback


def ask(cfg, msg, timeout=3.0):
    """One JSON request to the daemon. Returns the reply dict, or None when it is not running."""
    for path in sock_paths(cfg):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(path)
            s.sendall((json.dumps(msg) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf) if buf else None
        except (OSError, ValueError):
            continue
        finally:
            s.close()
    return None


def feedback(cfg, store, op, key):
    """Send an explicit answer to the daemon (single writer); append to feedback.jsonl when it is down."""
    reply = ask(cfg, {"cmd": "feedback", "op": op, "key": key})
    if reply and reply.get("ok"):
        return "daemon"
    fd = os.open(store.feedback_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps({"op": op, "key": key}) + "\n")
    return "queued"


def feedback_action(cfg, store, op, **fields):
    """Send a versioned policy action to the daemon or append it for offline replay."""
    msg = {"v": 1, "id": uuid.uuid4().hex, "op": op, **fields}
    reply = ask(cfg, {"cmd": "feedback", **msg})
    if reply is not None:
        return "daemon", reply
    fd = os.open(store.feedback_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(msg) + "\n")
    return "queued", {"ok": True, "queued": True}


def veto_target(target, store=None, for_removal=False):
    """Resolve an explicit SCOPE, APP, or current PID into a stable veto target."""
    if not isinstance(target, str) or not target:
        raise ValueError("target is empty")
    kind, value = None, target
    for prefix in ("scope:", "app:", "pid:"):
        if target.startswith(prefix):
            kind, value = prefix[:-1], target[len(prefix) :]
            break
    if not value:
        raise ValueError("target is empty")
    if kind == "pid" or (kind is None and value.isdigit()):
        if not value.isdigit():
            raise ValueError("pid must be a number")
        pid = int(value)
        if for_removal and store is not None:
            existing = next(
                (
                    v
                    for v in store._active_vetoes()
                    if v.get("kind") == "pid" and v.get("value") == str(pid)
                ),
                None,
            )
            if existing:
                return store._target(existing)
        start = inspect.starttime(pid)
        if pid <= 1 or start is None or inspect.uid_of(pid) != os.getuid():
            raise ValueError("pid is gone or not yours")
        return {"kind": "pid", "value": str(pid), "start": start}
    if kind == "scope":
        path = cgroup.resolve(value)
        if path:
            value = cgroup.rel(path)
        elif not cgroup.valid_rel(value):
            raise ValueError("bad scope name")
        return {"kind": "scope", "value": value, "start": None}
    if kind == "app":
        return {"kind": "app", "value": value, "start": None}
    path = cgroup.resolve(value)
    if path:
        return {"kind": "scope", "value": cgroup.rel(path), "start": None}
    if store is not None:
        found = next(
            (v for v in store._active_vetoes() if v.get("value") == value), None
        )
        if found:
            return store._target(found)
    return {"kind": "app", "value": value, "start": None}


def veto_label(target):
    label = "%s %s" % (target["kind"], target["value"])
    if target["kind"] == "pid" and target.get("start") is not None:
        label += " (starttime %s)" % target["start"]
    return label


def die(msg, code=1):
    print("taema: " + msg, file=sys.stderr)
    return code


# ---- run ----------------------------------------------------------------------------------


def _sudo_denied(msg):
    """True when the helper call failed because sudo refused (no taema group), not the helper itself."""
    m = msg.lower()
    return (
        "sudo" in m
        or "permission denied" in m
        or "password is required" in m
        or "not allowed" in m
    )


def cmd_run(a):
    cfg, store, units = _load()
    name = a.name
    if not cgroup.valid_rel(name) or "/" in name or len(name) > 32:
        return die("bad name (use a-z 0-9 _ -, max 32)")
    base = cgroup.base()
    if not os.path.isdir(base):
        return die(
            "%s missing; is the taema service running and are you in the taema group? (sv status taema)"
            % base
        )
    leaf = "%s/scope-%s" % (base, name)
    if os.path.isdir(leaf) and cgroup.tree_procs(leaf) and not a.join:
        return die("scope %s already has processes (use --join to add)" % name)
    owner = os.getpid() if a.bind else a.owner
    if owner and inspect.uid_of(owner) == -1:
        return die("owner pid %d is gone; not starting scope-%s" % (owner, name))
    os.makedirs(leaf, exist_ok=True)
    # register before attaching: the daemon must be watching when this process enters the scope
    reply = (
        ask(cfg, {"cmd": "register", "scope": "scope-" + name, "owner": owner})
        if owner
        else None
    )
    if reply is not None and "error" in reply:
        try:
            os.rmdir(leaf)
        except OSError:
            pass
        return die("register failed: %s" % reply["error"])
    try:
        try:
            engine.helper_attach(cfg, os.getpid(), name)
        except engine.Refused as e:
            if not _sudo_denied(str(e)):
                raise
            # no taema group in this shell yet: the daemon has it and attaches us
            r = ask(
                cfg, {"cmd": "attach", "scope": "scope-" + name, "pids": [os.getpid()]}
            )
            if not (r and r.get("ok")):
                raise engine.Refused(
                    "%s (daemon: %s)" % (e, (r or {}).get("error", "not running"))
                )
    except engine.Refused as e:
        try:
            os.rmdir(leaf)
        except OSError:
            pass
        return die("attach failed: %s" % e)
    if owner and reply is None:
        print(
            "taema: daemon not running; no owner watch for scope-%s" % name,
            file=sys.stderr,
        )
    elif reply is None:
        print(
            "taema: daemon not running; scope-%s is not auto-managed" % name,
            file=sys.stderr,
        )
    os.execvp(a.cmd[0], a.cmd)


# ---- kill ---------------------------------------------------------------------------------


def cmd_kill(a):
    if getattr(a, "do_not_kill", False):
        return die("kill and --do-not-kill cannot be combined", 2)
    cfg, store, units = _load()
    path = cgroup.resolve(a.name)
    if not path:
        return die("no scope %s" % a.name)
    veto = engine.veto_for_scope(store, path)
    facts = authorization.Facts(
        scope=cgroup.rel(path), vetoed=veto_label(veto) if veto else ""
    )
    dec = authorization.authorize(authorization.MANUAL_STOP, cfg["mode"], facts)
    if dec.verdict != authorization.ACT:
        if dec.slot == authorization.VETO:
            store.log(
                event="vetoed",
                trigger=authorization.MANUAL_STOP,
                scope=cgroup.rel(path),
                target=dec.reason,
            )
            return die(dec.reason, 4)
        return die("kill not allowed: %s" % dec.reason)
    leaf_name = os.path.basename(path)
    unit = engine.unit_for_leaf(units, leaf_name)
    try:
        rep = engine.stop(
            path,
            cfg,
            store,
            unit,
            timeout=a.timeout,
            force=a.force,
            hard=a.hard,
            keep=[x for x in (a.keep or "").split(",") if x],
            dry_run=a.dry_run,
            hook=policy.hook_for(cfg, leaf_name),
        )
    except engine.Refused as e:
        if isinstance(e, engine.Vetoed):
            return die(str(e), 4)
        return die(str(e))
    for d in rep["decisions"]:
        print(
            "%-5s %7d %-18s %s"
            % (d["action"], d["pid"], d["comm"][:18], d["why"][:110])
        )
    if a.force:
        for key in {d["key"] for d in rep["decisions"] if d["action"] == "kill"}:
            feedback(cfg, store, "kill", key)
    if a.dry_run:
        print("dry run: nothing changed")
        return 0
    if rep["removed"]:
        print("scope %s stopped" % rep["scope"])
        return 0
    print(
        "scope %s kept: %s (pids %s)"
        % (rep["scope"], rep.get("error", "busy"), rep["left"]),
        file=sys.stderr,
    )
    return 1


# ---- ls / explain / keep / forget ---------------------------------------------------------


def _fmt_mem(n):
    """Human-readable byte count (1.5G, 512); '-' when the fact is unknown."""
    if n is None:
        return "-"
    x = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if x < 1024 or u == "T":
            return "%d" % x if u == "B" else "%.1f%s" % (x, u)
        x /= 1024.0


def _fmt_psi(v):
    """memory pressure 'some avg10' with two decimals; '-' when the fact is unknown."""
    return "-" if v is None else "%.2f" % v


def _walk(path, depth, out):
    pids = cgroup.procs(path)
    comms = []
    for p in pids:
        c = inspect.comm(p)
        if c and c not in comms:
            comms.append(c)
    out.append(
        (
            depth,
            os.path.basename(path) if depth else cgroup.rel(path),
            len(pids),
            _fmt_mem(cgroup.memory_current(path)),
            _fmt_psi(cgroup.memory_psi(path)),
            ",".join(comms),
        )
    )
    for d in cgroup.subdirs(path):
        _walk(d, depth + 1, out)


def cmd_ls(a):
    base = cgroup.base()
    if not os.path.isdir(base):
        return die("%s missing" % base)
    rows = []
    for d in cgroup.subdirs(base):
        _walk(d, 0, rows)
    if not rows:
        print("no scopes")
    else:
        print("%-28s %4s  %8s %6s  %s" % ("name", "procs", "MEM", "PSI", "comms"))
        for depth, name, n, mem, psi, comms in rows:
            print(
                "%s%-*s %4d  %8s %6s  %s"
                % ("  " * depth, 28 - 2 * depth, name, n, mem, psi, comms[:80])
            )
    return 0


def cmd_explain(a):
    cfg, store, units = _load()
    if a.target.isdigit():
        pid = int(a.target)
        pp = inspect.ppid_map()
        members = set(inspect.descendants([pid], pp))
        edges = inspect.edges(members, inspect.Snapshot()).get(pid, [])
        print(
            "pid %d comm=%s key=%s app_key=%s"
            % (pid, inspect.comm(pid), policy.exe_key(pid), policy.app_key(pid))
        )
        print("cgroup: %s" % cgroup.proc_cgroup(pid))
        print("protected: %s" % (policy.protected_reason(pid, cfg) or "no"))
        print(
            "edges (outside users of this pid and its descendants): %s"
            % (json.dumps(edges) if edges else "none")
        )
        info = store.explain(policy.exe_key(pid))
        info["pairs"] = store.explain(policy.app_key(pid))["pairs"]
        print(json.dumps(info, indent=1))
        return 0
    path = cgroup.resolve(a.target)
    if path:
        unit = engine.unit_for_leaf(units, os.path.basename(path))
        for d in engine.plan_stop(path, cfg, store, unit):
            print(
                "%-5s %7d %-18s %s"
                % (d["action"], d["pid"], d["comm"][:18], d["why"][:140])
            )
        return 0
    print(json.dumps(store.explain(a.target), indent=1))
    return 0


def cmd_keep(a):
    cfg, store, units = _load()
    how = feedback(cfg, store, "keep", a.exe)
    store.bump(a.exe, "user_keep", 3.0)  # local view only: read-only store, never saved
    print("%s: %s (%s)" % (a.exe, store.default_action(a.exe)[0], how))
    return 0


def cmd_do_not_kill(a):
    cfg, store, _units = _load()
    if a.target:
        try:
            targets = [veto_target(a.target, store)]
        except ValueError as e:
            return die(str(e))
    else:
        action = store.auto_action()
        if not action:
            return die("no automatic stop to veto")
        apps = action.get("apps") or [
            pair[1]
            for pair in action.get("pairs", [])
            if isinstance(pair, list) and len(pair) == 2
        ]
        targets = (
            [
                {"kind": "app", "value": app, "start": None}
                for app in dict.fromkeys(apps)
            ]
            if apps
            else [{"kind": "scope", "value": action["scope"], "start": None}]
        )
    for target in targets:
        how, reply = feedback_action(cfg, store, "veto", target=target)
        if not reply or not reply.get("ok"):
            return die(reply.get("error", "could not add veto"))
        print("vetoed %s (%s)" % (veto_label(target), how))
    return 0


def cmd_undo(_a):
    cfg, store, _units = _load()
    action = store.auto_action()
    if not action:
        return die("no automatic stop to undo")
    how, reply = feedback_action(cfg, store, "undo", action_id=action["id"])
    if not reply or not reply.get("ok"):
        return die(reply.get("error", "could not undo automatic stop"))
    targets = reply.get("targets") or [
        {"kind": "app", "value": app} for app in action.get("apps", [])
    ]
    print(
        "undo: %s; vetoed %s"
        % (
            action.get("scope", "automatic stop"),
            ", ".join(veto_label(t) for t in targets) or "the stopped scope",
        )
    )
    return 0


def cmd_forget(a):
    cfg, store, units = _load()
    if getattr(a, "veto", False):
        try:
            target = veto_target(a.exe, store, for_removal=True)
        except ValueError as e:
            return die(str(e))
        existed = any(
            v.get("kind") == target["kind"]
            and v.get("value") == str(target["value"])
            and (target.get("start") is None or v.get("start") == target.get("start"))
            for v in store._active_vetoes()
        )
        how, reply = feedback_action(cfg, store, "unveto", target=target)
        if not reply or not reply.get("ok"):
            return die(reply.get("error", "could not remove veto"))
        removed = reply.get("removed", []) or existed
        print(
            "forgot veto for %s (%s)" % (veto_label(target), how)
            if removed
            else "no veto for %s (%s)" % (veto_label(target), how)
        )
        return 0
    known = store.forget(a.exe)
    feedback(cfg, store, "forget", a.exe)
    print("forgot %s" % a.exe if known else "nothing learned for %s" % a.exe)
    return 0


# ---- status / gc / adopt / daemon ---------------------------------------------------------


def print_pairs(pairs):
    """Pair table: what each (owner, leftover) pair would do and how sure taema is."""
    if not pairs:
        print("pairs: none learned yet")
        return
    print(
        "%-22s %-22s %-10s %5s %5s %5s %6s  %s"
        % ("owner", "leftover", "action", "conf", "stop", "keep", "closes", "why")
    )
    for r in pairs:
        print(
            "%-22s %-22s %-10s %5.2f %5.2f %5.2f %6d  %s"
            % (
                lineage.clean(r["owner"], 22),
                lineage.clean(r["leftover"], 22),
                r["action"],
                r["confidence"],
                r["stop"],
                r["keep"],
                r["closes"],
                lineage.clean(r["why"], 60),
            )
        )


def print_auto(auto):
    """Auto mode: scopes it created, leftover leaves, and the last auto stops with their reason."""
    print(
        "auto: %d auto-adopted scopes, %d leftover leaves"
        % (auto.get("auto_adopted_scopes", 0), auto.get("leftover_leaves", 0))
    )
    stops = auto.get("auto_stops", [])
    if not stops:
        print("auto stops: none yet")
    for s in stops[-5:]:
        print(
            "auto stop %s %-24s %s  [%s]"
            % (
                time.strftime("%m-%d %H:%M", time.localtime(s.get("ts", 0))),
                lineage.clean(s.get("scope", ""), 24),
                lineage.clean(s.get("why", ""), 70),
                lineage.clean(", ".join(s.get("pairs", [])), 60),
            )
        )


def cmd_status(a):
    cfg, store, units = _load()
    reply = ask(cfg, {"cmd": "status"})
    if reply is None:
        print(
            "daemon: not running (config mode=%s, from %s)"
            % (cfg["mode"], ", ".join(cfg["_sources"]) or "built-in defaults")
        )
        return 1
    reply["config"] = cfg["_sources"]
    pairs = reply.pop("pairs", [])
    auto = reply.pop("auto", None)
    print(json.dumps(reply, indent=1))
    print_pairs(pairs)
    if auto:
        print_auto(auto)
    return 0


def cmd_review(a):
    _cfg, store, _units = _load()
    reviews = store.open_reviews()
    print("open reviews: %d" % len(reviews))
    now = time.time()
    for review in reviews:
        if review.get("kind") == "legacy-invalid":
            age = max(0, int(now - review.get("created", now)))
            print(
                "review #%s legacy owner=%s survivor=%s previous=%s age=%ds"
                % (
                    review.get("id", "?"),
                    lineage.clean(review.get("owner", "?"), 40),
                    lineage.clean((review.get("survivors") or ["?"])[0], 40),
                    lineage.clean(review.get("answer", "?"), 16),
                    age,
                )
            )
            continue
        if review.get("kind") == "scope":
            age = max(0, int(now - review.get("created", now)))
            print(
                "review #%s scope=%s reason=%s age=%ds"
                % (
                    review.get("id", "?"),
                    lineage.clean(review.get("scope", "?"), 80),
                    lineage.clean(review.get("reason", "GC candidate"), 80),
                    age,
                )
            )
            continue
        survivors = (
            ", ".join(lineage.clean(k, 40) for k in review.get("survivors", []))
            or "none"
        )
        age = max(0, int(now - review.get("created", now)))
        print(
            "review #%s owner=%s survivors=%s age=%ds"
            % (
                review.get("id", "?"),
                lineage.clean(review.get("owner", "?"), 40),
                survivors,
                age,
            )
        )
    return 0


def cmd_learn_export(a):
    """Write the current store in the JSON format understood by the 0.2 release."""
    _cfg, store, _units = _load()
    payload = json.dumps(store.export_legacy(), indent=2, sort_keys=True) + "\n"
    if not a.output:
        sys.stdout.write(payload)
        return 0
    path = os.path.abspath(os.path.expanduser(a.output))
    directory = os.path.dirname(path)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".taema-export-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as error:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        return die("could not write export: %s" % error)
    return 0


def cmd_gc(a):
    cfg, store, units = _load()
    reply = ask(cfg, {"cmd": "gc", "dry_run": a.dry_run}, timeout=60)
    if reply is None:
        cands = engine.gc_candidates(cfg, units, store, {})
        reply = {
            "candidates": [[cgroup.rel(p), why] for p, why in cands],
            "note": "daemon not running; immediate candidates only",
        }
    print(json.dumps(reply, indent=1))
    return 0


def cmd_adopt(a):
    cfg, store, units = _load()
    if a.all:
        pt = inspect.ProcTable.scan()
        lin = lineage.Lineage(cfg)
        lin.observe(pt)
        ops = engine.adopt_plan(cfg, units, pt) + engine.carve_plan(cfg, units, pt)
        ops += engine.auto_adopt_plan(cfg, units, pt, lin, store)
        decision = authorization.authorize(authorization.AUTO_ADOPT, cfg["mode"])
    else:
        ops = engine.adopt_plan(cfg, units) + engine.carve_plan(cfg, units)
        decision = authorization.authorize(authorization.UNIT_ADOPT, cfg["mode"])
    execute = (not a.dry_run) and decision.verdict == authorization.ACT
    ops = engine.run_ops(cfg, store, ops, execute)
    for op in ops:
        print(
            "%-6s %-34s pids=%d%s"
            % (op["op"], op["scope"], len(op["pids"]), " done" if op["done"] else "")
        )
    if not execute:
        print(
            "nothing moved (mode=%s%s)"
            % (cfg["mode"], ", --dry-run" if a.dry_run else "")
        )
    return 0


def cmd_daemon(a):
    from ..daemon import service as daemon

    return daemon.run()


def main(argv):
    from .. import __version__

    p = argparse.ArgumentParser(
        prog="taema", description="Dependency-aware cgroup v2 process scopes"
    )
    p.add_argument("--version", action="version", version="taema " + __version__)
    p.add_argument(
        "--do-not-kill",
        nargs="?",
        const="",
        metavar="TARGET",
        help="veto a target, or the latest automatic stop",
    )
    sub = p.add_subparsers(dest="c")
    s = sub.add_parser("run", help="run CMD inside scope-NAME")
    s.add_argument("--join", action="store_true")
    s.add_argument("--owner", type=int, help="stop the scope when this pid exits")
    s.add_argument(
        "--bind", action="store_true", help="stop the scope when CMD itself exits"
    )
    s.add_argument("name")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(f=cmd_run)
    s = sub.add_parser(
        "kill", help="stop a scope; shared members are moved aside, not killed"
    )
    s.add_argument("-t", "--timeout", type=float)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument(
        "--do-not-kill",
        action="store_true",
        help="conflicts with kill; use the do-not-kill command separately",
    )
    s.add_argument("--force", action="store_true", help="ignore learned/seed defaults")
    s.add_argument(
        "--hard", action="store_true", help="also ignore detected outside users"
    )
    s.add_argument(
        "--keep", help="comma list of exe names to move aside instead of killing"
    )
    s.add_argument("name")
    s.set_defaults(f=cmd_kill)
    s = sub.add_parser("ls")
    s.set_defaults(f=cmd_ls)
    s = sub.add_parser("explain")
    s.add_argument("target")
    s.set_defaults(f=cmd_explain)
    s = sub.add_parser("keep")
    s.add_argument("exe")
    s.set_defaults(f=cmd_keep)
    s = sub.add_parser("forget")
    s.add_argument("--veto", action="store_true")
    s.add_argument("exe")
    s.set_defaults(f=cmd_forget)
    s = sub.add_parser("do-not-kill", aliases=["dnk", "never"])
    s.add_argument("target", nargs="?")
    s.set_defaults(f=cmd_do_not_kill)
    s = sub.add_parser("undo")
    s.set_defaults(f=cmd_undo)
    s = sub.add_parser("status")
    s.set_defaults(f=cmd_status)
    s = sub.add_parser("review", help="list pending close reviews")
    s.set_defaults(f=cmd_review)
    s = sub.add_parser("learn", help="inspect or export learned state")
    learn = s.add_subparsers(dest="learn_command", required=True)
    export = learn.add_parser("export", help="export state for a 0.2 downgrade")
    export.add_argument("--format", choices=("v2",), required=True)
    export.add_argument("--output", help="write atomically to PATH instead of stdout")
    export.set_defaults(f=cmd_learn_export)
    s = sub.add_parser("gc")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(f=cmd_gc)
    s = sub.add_parser("adopt")
    s.add_argument("--all", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(f=cmd_adopt)
    s = sub.add_parser("daemon")
    s.set_defaults(f=cmd_daemon)
    a = p.parse_args(argv)
    if a.c is None:
        if a.do_not_kill is None:
            p.error("a command is required")
        return cmd_do_not_kill(argparse.Namespace(target=a.do_not_kill or None))
    if a.c == "run":
        if a.cmd and a.cmd[0] == "--":
            a.cmd = a.cmd[1:]
        if not a.cmd:
            return die("usage: taema run [--join] [--owner PID|--bind] NAME CMD...")
    return a.f(a) or 0
