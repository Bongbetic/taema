"""`taema` command line. scoperun / scopekill / scopels are thin aliases (see bin/)."""
import argparse
import json
import os
import socket
import sys

from . import cgroup, engine, inspect, knowledge, policy


def _load():
    cfg = policy.load_config()
    store = knowledge.Store(policy.state_dir(cfg), cfg.get("seeds"))
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


def die(msg, code=1):
    print("taema: " + msg, file=sys.stderr)
    return code


# ---- run ----------------------------------------------------------------------------------

def cmd_run(a):
    cfg, store, units = _load()
    name = a.name
    if not cgroup.valid_rel(name) or "/" in name or len(name) > 32:
        return die("bad name (use a-z 0-9 _ -, max 32)")
    base = cgroup.base()
    if not os.path.isdir(base):
        return die("%s missing; is the taema service running and are you in the taema group? (sv status taema)" % base)
    leaf = "%s/scope-%s" % (base, name)
    if os.path.isdir(leaf) and cgroup.tree_procs(leaf) and not a.join:
        return die("scope %s already has processes (use --join to add)" % name)
    os.makedirs(leaf, exist_ok=True)
    try:
        engine.helper_attach(cfg, os.getpid(), name)
    except engine.Refused as e:
        try:
            os.rmdir(leaf)
        except OSError:
            pass
        return die("attach failed: %s" % e)
    owner = os.getpid() if a.bind else a.owner
    reply = ask(cfg, {"cmd": "register", "scope": "scope-" + name, "owner": owner}) if owner else None
    if owner and reply is None:
        print("taema: daemon not running; no owner watch for scope-%s" % name, file=sys.stderr)
    elif reply is None:
        print("taema: daemon not running; scope-%s is not auto-managed" % name, file=sys.stderr)
    os.execvp(a.cmd[0], a.cmd)


# ---- kill ---------------------------------------------------------------------------------

def cmd_kill(a):
    cfg, store, units = _load()
    path = cgroup.resolve(a.name)
    if not path:
        return die("no scope %s" % a.name)
    leaf_name = os.path.basename(path)
    unit = policy.unit_for_scope(units, leaf_name)
    try:
        rep = engine.stop(path, cfg, store, unit, timeout=a.timeout, force=a.force, hard=a.hard,
                          keep=[x for x in (a.keep or "").split(",") if x], dry_run=a.dry_run,
                          hook=policy.hook_for(cfg, leaf_name))
    except engine.Refused as e:
        return die(str(e))
    for d in rep["decisions"]:
        print("%-5s %7d %-18s %s" % (d["action"], d["pid"], d["comm"][:18], d["why"][:110]))
    if a.force:
        for d in rep["decisions"]:
            if d["action"] == "kill":
                store.bump(d["key"], "user_kill")
        store.save()
    if a.dry_run:
        print("dry run: nothing changed")
        return 0
    if rep["removed"]:
        print("scope %s stopped" % rep["scope"])
        return 0
    print("scope %s kept: %s (pids %s)" % (rep["scope"], rep.get("error", "busy"), rep["left"]),
          file=sys.stderr)
    return 1


# ---- ls / explain / keep / forget ---------------------------------------------------------

def _walk(path, depth, out):
    pids = cgroup.procs(path)
    comms = []
    for p in pids:
        c = inspect.comm(p)
        if c and c not in comms:
            comms.append(c)
    out.append((depth, os.path.basename(path) if depth else cgroup.rel(path), len(pids), ",".join(comms)))
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
    for depth, name, n, comms in rows:
        print("%s%-*s %4d  %s" % ("  " * depth, 28 - 2 * depth, name, n, comms[:80]))
    return 0


def cmd_explain(a):
    cfg, store, units = _load()
    if a.target.isdigit():
        pid = int(a.target)
        pp = inspect.ppid_map()
        members = set(inspect.descendants([pid], pp))
        edges = inspect.edges(members, inspect.Snapshot()).get(pid, [])
        print("pid %d comm=%s key=%s" % (pid, inspect.comm(pid), policy.exe_key(pid)))
        print("cgroup: %s" % cgroup.proc_cgroup(pid))
        print("protected: %s" % (policy.protected_reason(pid, cfg) or "no"))
        print("edges (outside users of this pid and its descendants): %s" % (json.dumps(edges) if edges else "none"))
        print(json.dumps(store.explain(policy.exe_key(pid)), indent=1))
        return 0
    path = cgroup.resolve(a.target)
    if path:
        unit = policy.unit_for_scope(units, os.path.basename(path))
        for d in engine.plan_stop(path, cfg, store, unit):
            print("%-5s %7d %-18s %s" % (d["action"], d["pid"], d["comm"][:18], d["why"][:140]))
        return 0
    print(json.dumps(store.explain(a.target), indent=1))
    return 0


def cmd_keep(a):
    cfg, store, units = _load()
    store.bump(a.exe, "user_keep", 3.0)
    store.log(event="keep", exe=a.exe)
    store.save()
    print("%s: %s" % (a.exe, store.default_action(a.exe)[0]))
    return 0


def cmd_forget(a):
    cfg, store, units = _load()
    print("forgot %s" % a.exe if store.forget(a.exe) else "nothing learned for %s" % a.exe)
    store.log(event="forget", exe=a.exe)
    store.save()
    return 0


# ---- status / gc / adopt / daemon ---------------------------------------------------------

def cmd_status(a):
    cfg, store, units = _load()
    reply = ask(cfg, {"cmd": "status"})
    if reply is None:
        print("daemon: not running (config mode=%s, from %s)" % (cfg["mode"], ", ".join(cfg["_sources"]) or "built-in defaults"))
        return 1
    reply["config"] = cfg["_sources"]
    print(json.dumps(reply, indent=1))
    return 0


def cmd_gc(a):
    cfg, store, units = _load()
    reply = ask(cfg, {"cmd": "gc", "dry_run": a.dry_run}, timeout=60)
    if reply is None:
        cands = engine.gc_candidates(cfg, units, store, {})
        reply = {"candidates": [[cgroup.rel(p), why] for p, why in cands], "note": "daemon not running; immediate candidates only"}
    print(json.dumps(reply, indent=1))
    return 0


def cmd_adopt(a):
    cfg, store, units = _load()
    ops = engine.adopt_plan(cfg, units) + engine.carve_plan(cfg, units)
    execute = (not a.dry_run) and cfg["mode"] in ("adopt", "enforce")
    ops = engine.run_ops(cfg, store, ops, execute)
    for op in ops:
        print("%-6s %-34s pids=%d%s" % (op["op"], op["scope"], len(op["pids"]), " done" if op["done"] else ""))
    if not execute:
        print("nothing moved (mode=%s%s)" % (cfg["mode"], ", --dry-run" if a.dry_run else ""))
    return 0


def cmd_daemon(a):
    from . import daemon
    return daemon.run()


def main(argv):
    from . import __version__
    p = argparse.ArgumentParser(prog="taema", description="Dependency-aware cgroup v2 process scopes")
    p.add_argument("--version", action="version", version="taema " + __version__)
    sub = p.add_subparsers(dest="c", required=True)
    s = sub.add_parser("run", help="run CMD inside scope-NAME")
    s.add_argument("--join", action="store_true")
    s.add_argument("--owner", type=int, help="stop the scope when this pid exits")
    s.add_argument("--bind", action="store_true", help="stop the scope when CMD itself exits")
    s.add_argument("name")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(f=cmd_run)
    s = sub.add_parser("kill", help="stop a scope; shared members are moved aside, not killed")
    s.add_argument("-t", "--timeout", type=float)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--force", action="store_true", help="ignore learned/seed defaults")
    s.add_argument("--hard", action="store_true", help="also ignore detected outside users")
    s.add_argument("--keep", help="comma list of exe names to move aside instead of killing")
    s.add_argument("name")
    s.set_defaults(f=cmd_kill)
    s = sub.add_parser("ls"); s.set_defaults(f=cmd_ls)
    s = sub.add_parser("explain"); s.add_argument("target"); s.set_defaults(f=cmd_explain)
    s = sub.add_parser("keep"); s.add_argument("exe"); s.set_defaults(f=cmd_keep)
    s = sub.add_parser("forget"); s.add_argument("exe"); s.set_defaults(f=cmd_forget)
    s = sub.add_parser("status"); s.set_defaults(f=cmd_status)
    s = sub.add_parser("gc"); s.add_argument("--dry-run", action="store_true"); s.set_defaults(f=cmd_gc)
    s = sub.add_parser("adopt"); s.add_argument("--dry-run", action="store_true"); s.set_defaults(f=cmd_adopt)
    s = sub.add_parser("daemon"); s.set_defaults(f=cmd_daemon)
    a = p.parse_args(argv)
    if a.c == "run":
        if a.cmd and a.cmd[0] == "--":
            a.cmd = a.cmd[1:]
        if not a.cmd:
            return die("usage: taema run [--join] [--owner PID|--bind] NAME CMD...")
    return a.f(a) or 0
