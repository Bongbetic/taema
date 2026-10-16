"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Mode gates every action: observe logs only, adopt moves, enforce also kills.
"""
import json
import os
import selectors
import socket
import time

from . import cgroup, engine, knowledge, policy


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = knowledge.Store(policy.state_dir(cfg), cfg.get("seeds"))
        self.units = policy.load_units(cfg)
        self.sel = selectors.DefaultSelector()
        self.owners = {}        # pidfd -> (scope leaf name, owner pid)
        self.idle_since = {}
        self.last = {"adopt": 0.0, "gc": 0.0}
        self.last_result = {"adopt": None, "gc": None}
        self.started = time.time()
        self.stopping = False
        self.session_seen = False

    # ---- mode gates ----
    @property
    def mode(self):
        return self.cfg["mode"]

    def may_move(self):
        return self.mode in ("adopt", "enforce")

    def may_kill(self):
        return self.mode == "enforce"

    # ---- owner watch ----
    def watch_owner(self, leaf, pid):
        try:
            fd = os.pidfd_open(pid)
        except OSError:
            self.stop_leaf(leaf, "owner %d already gone" % pid)
            return False
        self.owners[fd] = (leaf, pid)
        self.sel.register(fd, selectors.EVENT_READ, "owner")
        self.store.log(event="owner_watch", scope=leaf, owner=pid)
        return True

    def on_owner_exit(self, fd):
        leaf, pid = self.owners.pop(fd)
        self.sel.unregister(fd)
        os.close(fd)
        self.stop_leaf(leaf, "owner %d exited" % pid)

    def stop_leaf(self, leaf, why):
        path = "%s/%s" % (cgroup.base(), leaf)
        if not os.path.isdir(path):
            return
        if not self.may_kill():
            self.store.log(event="would_stop", scope=leaf, why=why, mode=self.mode)
            return
        unit = policy.unit_for_scope(self.units, leaf)
        try:
            engine.stop(path, self.cfg, self.store, unit, hook=policy.hook_for(self.cfg, leaf))
            self.store.log(event="stopped", scope=leaf, why=why)
        except engine.Refused as e:
            self.store.log(event="stop_refused", scope=leaf, why=str(e))

    # ---- loops ----
    def adopt_pass(self):
        ops = engine.adopt_plan(self.cfg, self.units) + engine.carve_plan(self.cfg, self.units)
        done = engine.run_ops(self.cfg, self.store, ops, self.may_move())
        for op in done:
            if op["op"] == "carve" and op["done"] and op.get("binds_to") == "root":
                self.watch_owner(op["scope"], op["root"])
        self.last_result["adopt"] = [{"op": o["op"], "scope": o["scope"], "pids": len(o["pids"]),
                                      "done": o["done"]} for o in done]

    def gc_pass(self, dry_run=False):
        cands = engine.gc_candidates(self.cfg, self.units, self.store, self.idle_since)
        res = []
        for path, why in cands:
            leaf = cgroup.rel(path)
            res.append([leaf, why, "would" if (dry_run or not self.may_kill()) else "stop"])
            if dry_run:
                continue
            if self.may_kill():
                try:
                    engine.stop(path, self.cfg, self.store, policy.unit_for_scope(self.units, os.path.basename(path)))
                    self.store.log(event="gc_stopped", scope=leaf, why=why)
                except engine.Refused as e:
                    self.store.log(event="gc_refused", scope=leaf, why=str(e))
            else:
                self.store.log(event="gc_would_stop", scope=leaf, why=why, mode=self.mode)
        self.last_result["gc"] = res
        return res

    def session_ended(self):
        """True once every login session of this user has gone (after at least one was seen)."""
        try:
            if policy.session_cgroups(self.cfg):
                self.session_seen = True
                return False
            return self.session_seen
        except OSError:
            return False

    def end_session(self):
        self.store.log(event="session_end", mode=self.mode)
        for d in cgroup.subdirs(cgroup.base()):
            if os.path.basename(d) == "manager":
                continue
            unit = engine.unit_for_leaf(self.units, os.path.basename(d))
            if unit and unit.get("kill", {}).get("survive_logout"):
                self.store.log(event="session_end_kept", scope=cgroup.rel(d))
                continue
            if self.may_kill():
                try:
                    engine.stop(d, self.cfg, self.store, policy.unit_for_scope(self.units, os.path.basename(d)))
                except engine.Refused:
                    pass
            else:
                self.store.log(event="would_stop", scope=cgroup.rel(d), why="session ended", mode=self.mode)
        self.session_seen = False   # wait for the next login before acting again
        if self.may_kill():
            self.stopping = True

    def guarded(self, fn):
        try:
            fn()
        except Exception as e:  # a failed pass must not stop the daemon
            self.store.log(event="error", where=fn.__name__, error="%s: %s" % (type(e).__name__, e))

    # ---- socket API ----
    def handle(self, msg):
        c = msg.get("cmd")
        if c == "status":
            return {"mode": self.mode, "uptime_s": int(time.time() - self.started),
                    "owners": [{"scope": l, "owner": p} for l, p in self.owners.values()],
                    "idle_tracked": {k: int(time.time() - v) for k, v in self.idle_since.items()},
                    "last_adopt": self.last_result["adopt"], "last_gc": self.last_result["gc"]}
        if c == "register":
            leaf, owner = msg.get("scope", ""), msg.get("owner")
            if not cgroup.valid_rel(leaf) or not isinstance(owner, int):
                return {"error": "bad request"}
            return {"watching": self.watch_owner(leaf, owner)}
        if c == "gc":
            return {"candidates": self.gc_pass(dry_run=bool(msg.get("dry_run")))}
        return {"error": "unknown command"}

    def serve(self, srv):
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        try:
            data = conn.recv(65536)
            reply = self.handle(json.loads(data)) if data else {"error": "empty"}
        except (ValueError, OSError) as e:
            reply = {"error": str(e)}
        try:
            conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass
        conn.close()

    # ---- main ----
    def run(self):
        path = os.environ.get("TAEMA_SOCKET") or None
        if not path:
            from .cli import sock_path
            path = sock_path(self.cfg)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chmod(path, 0o600)
        srv.listen(8)
        self.sel.register(srv, selectors.EVENT_READ, "srv")
        self.store.log(event="daemon_start", mode=self.mode, units=[u["_file"] for u in self.units])
        iv_adopt = policy.timer(self.cfg, "adopt_interval", 15)
        iv_gc = policy.timer(self.cfg, "gc_interval", 60)
        while not self.stopping:
            for key, _ in self.sel.select(timeout=1.0):
                if key.data == "srv":
                    self.serve(srv)
                else:
                    self.on_owner_exit(key.fd)
            now = time.time()
            if now - self.last["adopt"] >= iv_adopt:
                self.last["adopt"] = now
                self.guarded(self.adopt_pass)
            if now - self.last["gc"] >= iv_gc:
                self.last["gc"] = now
                self.guarded(self.gc_pass)
            if self.session_ended():
                self.end_session()
        return 0


def run():
    cfg = policy.load_config()
    return Daemon(cfg).run()
