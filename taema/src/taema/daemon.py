"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Mode gates every action: observe logs only, adopt moves, enforce also kills.
"""
import json
import os
import select
import selectors
import signal
import socket
import stat
import struct
import time

from . import cgroup, engine, inspect, knowledge, policy

MAX_OWNERS = 256        # pidfd owner watches
MAX_LEAF_WATCH = 256    # cgroup.events watches (EPOLLPRI)
MAX_SLEEP = 60.0        # longest select() sleep
MAX_GATE_SKIPS = 4      # fork gate: at most 4 skipped adopt passes, so every 5th one runs


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
        self.iv_adopt = policy.timer(cfg, "adopt_interval", 15)
        self.iv_gc = policy.timer(cfg, "gc_interval", 60)
        self.gate_sig = None    # fork gate: (last pid, session pid sets) of the last adopt pass
        self.gate_skips = 0
        self.leaf_ep = None     # epoll on leaf cgroup.events (EPOLLPRI), itself in self.sel
        self.leaf_watch = {}    # fd -> (leaf rel, open cgroup.events file)
        self.leaf_nowatch = set()   # leaves that could not be watched: the GC pass checks them
        self.empty_seen = set()     # leaves seen empty by the previous GC pass
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
        if len(self.owners) >= MAX_OWNERS:
            self.store.log(event="owner_watch_full", scope=leaf, owner=pid)
            return False
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
    def _fork_sig(self):
        """Cheap change signature: /proc/loadavg last pid plus the session cgroup pid sets."""
        try:
            with open(inspect.PROC + "/loadavg") as f:
                last_pid = f.read().split()[4]
        except (OSError, IndexError):
            return None
        return (last_pid, tuple((d, frozenset(cgroup.procs(d))) for d in policy.session_dirs(self.cfg)))

    def adopt_pass(self):
        sig = self._fork_sig()
        if sig is not None and sig == self.gate_sig and self.gate_skips < MAX_GATE_SKIPS:
            self.gate_skips += 1        # nothing forked and nobody joined a session: skip the walk
            return
        self.gate_sig, self.gate_skips = sig, 0
        if not self.units:
            self.last_result["adopt"] = []
            return
        pt = inspect.ProcTable.scan()
        ops = engine.adopt_plan(self.cfg, self.units, pt) + engine.carve_plan(self.cfg, self.units, pt)
        done = engine.run_ops(self.cfg, self.store, ops, self.may_move())
        for op in done:
            if op["op"] == "carve" and op["done"] and op.get("binds_to") == "root":
                self.watch_owner(op["scope"], op["root"])
        self.last_result["adopt"] = [{"op": o["op"], "scope": o["scope"], "pids": len(o["pids"]),
                                      "done": o["done"]} for o in done]

    # ---- empty leaves ----
    def _empty_leaf_dirs(self):
        base = cgroup.base()
        return cgroup.subdirs(base + "/shared") + [
            d for d in cgroup.subdirs(base)
            if os.path.basename(d).startswith(engine.EMPTY_PREFIXES) and os.path.basename(d) != "manager"]

    def _drop_leaf_watch(self, fd):
        _rel, f = self.leaf_watch.pop(fd)
        try:
            self.leaf_ep.unregister(fd)
        except (OSError, ValueError):
            pass
        f.close()

    def sync_leaf_watches(self):
        """Watch cgroup.events of each removable leaf (cap MAX_LEAF_WATCH); leaves that cannot be
        watched stay on the GC-pass check."""
        dirs = {cgroup.rel(d): d for d in self._empty_leaf_dirs()}
        for fd in [fd for fd, (rel, _f) in self.leaf_watch.items() if rel not in dirs]:
            self._drop_leaf_watch(fd)
        self.leaf_nowatch &= set(dirs)
        watched = {rel for rel, _f in self.leaf_watch.values()}
        for rel, d in dirs.items():
            if rel in watched or rel in self.leaf_nowatch or len(self.leaf_watch) >= MAX_LEAF_WATCH:
                continue
            try:
                if self.leaf_ep is None:
                    self.leaf_ep = select.epoll()
                    self.sel.register(self.leaf_ep.fileno(), selectors.EVENT_READ, "leaves")
                f = open(d + "/cgroup.events")
                f.read()    # arm: EPOLLPRI fires on the next change after a read
                try:
                    self.leaf_ep.register(f.fileno(), select.EPOLLPRI | select.EPOLLERR)
                except OSError:
                    f.close()
                    raise
                self.leaf_watch[f.fileno()] = (rel, f)
            except OSError:
                self.leaf_nowatch.add(rel)

    def on_leaf_events(self):
        """A watched leaf changed: remove it when cgroup.events says 'populated 0'."""
        for fd, _ev in self.leaf_ep.poll(0):
            if fd not in self.leaf_watch:
                continue
            rel, f = self.leaf_watch[fd]
            try:
                f.seek(0)
                text = f.read()
            except OSError:
                text = ""
            if "populated 0" in text:
                self._drop_leaf_watch(fd)
                self.remove_leaf(cgroup.base() + "/" + rel, "populated 0")
            elif not text:
                self._drop_leaf_watch(fd)

    def remove_leaf(self, path, why):
        leaf = cgroup.rel(path)
        if engine.remove_empty(path):
            self.empty_seen.discard(leaf)
            self.store.log(event="gc_removed_empty", scope=leaf, why=why)
            return True
        return False

    def _gc_empty(self, path, leaf, dry_run, res, now_empty):
        """Empty leaf: removed on the second consecutive GC pass that sees it empty (a scope that
        was just created is empty until its first process arrives)."""
        if dry_run or not self.may_move():
            res.append([leaf, "empty", "would"])
            if not dry_run and self.store.changed("gc_empty:" + leaf, True):
                self.store.log(event="gc_would_remove_empty", scope=leaf, mode=self.mode)
            return
        res.append([leaf, "empty", "remove"])
        if leaf in self.empty_seen:
            self.remove_leaf(path, "empty")
        else:
            now_empty.add(leaf)

    def gc_pass(self, dry_run=False):
        if self.store.apply_feedback():
            self.store.save_if_dirty()
        self.store.decay()
        self.store.enforce_caps()
        cands = engine.gc_candidates(self.cfg, self.units, self.store, self.idle_since,
                                     usage=self.gc_usage, skip=self.gc_skip, noted=self.gc_noted)
        res, now_empty = [], set()
        if not dry_run and self.may_move():
            self.sync_leaf_watches()
        for path, why in cands:
            leaf = cgroup.rel(path)
            if why == "empty":
                self._gc_empty(path, leaf, dry_run, res, now_empty)
                continue
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
        if not dry_run:
            self.empty_seen = now_empty
            self.store.forget_sigs("gc_empty:", {"gc_empty:" + r[0] for r in res if r[1] == "empty"})
        self.last_result["gc"] = res
        return res

    def session_ended(self):
        """True once every login session of this user has gone (after at least one was seen)."""
        st = policy.session_state()
        if st is not None:     # elogind's per-user state file: no cgroup scan
            if st[1]:
                self.session_seen = True
                return False
            return self.session_seen
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

    def next_timeout(self, now=None):
        """Seconds until the next timer is due (adopt, gc), capped at MAX_SLEEP."""
        now = time.time() if now is None else now
        due = min(self.last["adopt"] + self.iv_adopt, self.last["gc"] + self.iv_gc, now + MAX_SLEEP)
        return max(0.0, min(MAX_SLEEP, due - now))

    def tick(self):
        """Run what is due: socket check, adopt (+ session end), GC, routine save."""
        self.guarded(self.check_socket)
        now = time.time()
        if now - self.last["adopt"] >= self.iv_adopt:
            self.last["adopt"] = now
            self.guarded(self.adopt_pass)
            if self.session_ended():
                self.guarded(self.end_session)
        if now - self.last["gc"] >= self.iv_gc:
            self.last["gc"] = now
            self.guarded(self.gc_pass)
        self.guarded(lambda: self.store.save_if_dirty(knowledge.SAVE_INTERVAL))

    def run(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        wake_r, wake_w = socket.socketpair()    # a signal wakes select() at once
        wake_r.setblocking(False)
        wake_w.setblocking(False)
        self.sel.register(wake_r, selectors.EVENT_READ, "wake")
        try:
            signal.set_wakeup_fd(wake_w.fileno(), warn_on_full_buffer=False)
        except ValueError:      # not the main thread
            pass
        self.guarded(self.check_socket)
        self.store.log(event="daemon_start", mode=self.mode, units=[u["_file"] for u in self.units])
        while not self.stopping:
            for key, _ in self.sel.select(timeout=self.next_timeout()):
                if key.data == "srv":
                    self.guarded(lambda: self.serve(self.srv))
                elif key.data == "wake":
                    try:
                        wake_r.recv(4096)
                    except OSError:
                        pass
                elif key.data == "leaves":
                    self.guarded(self.on_leaf_events)
                else:
                    fd = key.fd
                    self.guarded(lambda: self.on_owner_exit(fd))
            self.tick()
        self.store.log(event="daemon_stop")
        self.store.save()
        return 0


def run():
    cfg = policy.load_config()
    return Daemon(cfg).run()
