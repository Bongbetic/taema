"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Mode gates every action: observe logs only, adopt moves, enforce also kills.
"""
import json
import os
import selectors
import signal
import socket
import stat
import struct
import time

from . import cgroup, engine, inspect, knowledge, policy


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = knowledge.Store(policy.state_dir(cfg), cfg.get("seeds"))
        self.store.apply_feedback()
        self.units = policy.load_units(cfg)
        self.sel = selectors.DefaultSelector()
        self.owners = {}        # pidfd -> (scope leaf name, owner pid, owner starttime)
        self.idle_since = {}
        self.gc_usage = {}      # rel -> cpu usage_usec when the idle window started
        self.gc_skip = set()    # leaves with a protected member: not retried
        self.gc_noted = set()   # leaves already logged as kept
        self.srv = None
        self.sock_path = None
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
        if any(l == leaf for l, _p, _s in self.owners.values()):
            return True     # already watched (first owner wins)
        st = inspect.starttime(pid)
        try:
            fd = os.pidfd_open(pid)
        except OSError:
            fd = None
        if fd is None or st is None:
            if fd is not None:
                os.close(fd)
            self.stop_leaf(leaf, "owner %d already gone" % pid)
            return False
        self.owners[fd] = (leaf, pid, st)
        self.sel.register(fd, selectors.EVENT_READ, "owner")
        self.store.log(event="owner_watch", scope=leaf, owner=pid)
        return True

    def on_owner_exit(self, fd):
        leaf, pid, _st = self.owners.pop(fd)
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
        unit = engine.unit_for_leaf(self.units, os.path.basename(leaf))
        try:
            engine.stop(path, self.cfg, self.store, unit, hook=policy.hook_for(self.cfg, leaf))
            self.store.log(event="stopped", scope=leaf, why=why)
        except engine.Refused as e:
            self.store.log(event="stop_refused", scope=leaf, why=str(e))
        except Exception as e:  # never let one scope take the daemon down
            self.store.log(event="stop_error", scope=leaf, error="%s: %s" % (type(e).__name__, e))

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
        self.store.apply_feedback()
        cands = engine.gc_candidates(self.cfg, self.units, self.store, self.idle_since,
                                     usage=self.gc_usage, skip=self.gc_skip, noted=self.gc_noted)
        res = []
        for path, why in cands:
            leaf = cgroup.rel(path)
            res.append([leaf, why, "would" if (dry_run or not self.may_kill()) else "stop"])
            if dry_run:
                continue
            if self.may_kill():
                try:
                    rep = engine.stop(path, self.cfg, self.store,
                                      engine.unit_for_leaf(self.units, os.path.basename(path)),
                                      hook=policy.hook_for(self.cfg, os.path.basename(path)))
                except engine.Refused as e:
                    self.store.log(event="gc_refused", scope=leaf, why=str(e))
                    continue
                if rep["removed"]:
                    self.store.log(event="gc_stopped", scope=leaf, why=why)
                elif any(d["action"] == "skip" for d in rep["decisions"]):
                    self.gc_skip.add(leaf)
                    self.store.log(event="gc_kept", scope=leaf, why="kept: protected member")
                else:
                    self.store.log(event="gc_incomplete", scope=leaf, why=rep.get("error", "busy"))
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
                    engine.stop(d, self.cfg, self.store, unit,
                                hook=policy.hook_for(self.cfg, os.path.basename(d)))
                except engine.Refused:
                    pass
            else:
                self.store.log(event="would_stop", scope=cgroup.rel(d), why="session ended", mode=self.mode)
        self.session_seen = False   # wait for the next login before acting again

    def guarded(self, fn):
        try:
            fn()
        except Exception as e:  # a failed pass must not stop the daemon
            self.store.log(event="error", where=getattr(fn, "__name__", "?"), error="%s: %s" % (type(e).__name__, e))

    # ---- socket API ----
    def handle(self, msg):
        if not isinstance(msg, dict):
            return {"error": "bad request"}
        c = msg.get("cmd")
        if c == "status":
            return {"mode": self.mode, "uptime_s": int(time.time() - self.started),
                    "owners": [{"scope": l, "owner": p} for l, p, _s in self.owners.values()],
                    "idle_tracked": {k: int(time.time() - v) for k, v in self.idle_since.items()},
                    "last_adopt": self.last_result["adopt"], "last_gc": self.last_result["gc"]}
        if c == "register":
            leaf, owner = msg.get("scope"), msg.get("owner")
            if not isinstance(leaf, str) or not cgroup.valid_rel(leaf) \
                    or not isinstance(owner, int) or isinstance(owner, bool):
                return {"error": "bad request"}
            if owner <= 1 or inspect.uid_of(owner) != os.getuid():
                return {"error": "owner gone or not yours"}
            return {"watching": self.watch_owner(leaf, owner)}
        if c == "gc":
            return {"candidates": self.gc_pass(dry_run=msg.get("dry_run") is True)}
        if c == "feedback":
            if not self.store.apply_op(msg.get("op"), msg.get("key")):
                return {"error": "bad request"}
            self.store.save_if_dirty()
            return {"ok": True}
        return {"error": "unknown command"}

    def _read_request(self, conn):
        """Bytes up to a newline (or EOF) within 0.5 s total and 64 KiB."""
        deadline = time.monotonic() + 0.5
        buf = b""
        while b"\n" not in buf and len(buf) < 65536:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("request too slow")
            conn.settimeout(left)
            chunk = conn.recv(65536 - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def serve(self, srv):
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                 struct.calcsize("3i")))
            if uid != os.getuid():
                reply = {"error": "forbidden"}
            else:
                data = self._read_request(conn)
                reply = self.handle(json.loads(data)) if data.strip() else {"error": "empty"}
        except Exception as e:  # bad input of any shape gets an error reply, never a crash
            reply = {"error": "%s: %s" % (type(e).__name__, e)}
        try:
            conn.settimeout(0.5)
            conn.sendall((json.dumps(reply) + "\n").encode())
        except (OSError, ValueError):
            pass
        conn.close()

    # ---- main ----
    def _want_path(self):
        path = os.environ.get("TAEMA_SOCKET") or None
        if not path:
            from .cli import sock_path
            path = sock_path(self.cfg)
        return path

    def bind(self, path):
        """(Re)create the listening socket at path, mode 0600 from the start (umask, no chmod)."""
        if self.srv is not None:
            try:
                self.sel.unregister(self.srv)
            except (KeyError, ValueError):
                pass
            self.srv.close()
            self.srv = None
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o077)
        try:
            srv.bind(path)
        except OSError:
            srv.close()
            raise
        finally:
            os.umask(old)
        srv.listen(8)
        self.srv, self.sock_path = srv, path
        self.sel.register(srv, selectors.EVENT_READ, "srv")

    def check_socket(self):
        """Re-bind when the socket file vanished or a better path appeared (/run/user/<uid>)."""
        want = self._want_path()
        if self.srv is None or want != self.sock_path or not os.path.exists(self.sock_path):
            self.bind(want)
            self.store.log(event="socket_bound", path=want)

    def _on_signal(self, signum, _frame):
        self.stopping = True

    def run(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        self.guarded(self.check_socket)
        self.store.log(event="daemon_start", mode=self.mode, units=[u["_file"] for u in self.units])
        iv_adopt = policy.timer(self.cfg, "adopt_interval", 15)
        iv_gc = policy.timer(self.cfg, "gc_interval", 60)
        while not self.stopping:
            for key, _ in self.sel.select(timeout=1.0):
                if key.data == "srv":
                    self.guarded(lambda: self.serve(self.srv))
                else:
                    fd = key.fd
                    self.guarded(lambda: self.on_owner_exit(fd))
            self.guarded(self.check_socket)
            now = time.time()
            if now - self.last["adopt"] >= iv_adopt:
                self.last["adopt"] = now
                self.guarded(self.adopt_pass)
            if now - self.last["gc"] >= iv_gc:
                self.last["gc"] = now
                self.guarded(self.gc_pass)
            if self.session_ended():
                self.guarded(self.end_session)
            self.guarded(self.store.save_if_dirty)
        self.store.log(event="daemon_stop")
        self.store.save()
        return 0


def run():
    cfg = policy.load_config()
    return Daemon(cfg).run()
