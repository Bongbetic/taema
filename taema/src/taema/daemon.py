"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Mode gates every action: observe logs only, adopt moves, enforce also kills.
"""
import hmac
import json
import os
import re
import secrets
import select
import selectors
import signal
import socket
import stat
import struct
import time

from . import cgroup, engine, inspect, knowledge, lineage, policy

MAX_OWNERS = 256        # pidfd owner watches
MAX_LEAF_WATCH = 256    # cgroup.events watches (EPOLLPRI)
MAX_SLEEP = 60.0        # longest select() sleep
JOB_SETTLE = 1.5        # seconds between job_done and the decision (survivors must outlive it)
JOB_LAUNCHER = 2.0      # a job shorter than this is a launcher: survivors are learned silently
STOPPED_JOB = (148, 149, 150)   # 128 + SIGTSTP/SIGTTIN/SIGTTOU: Ctrl-Z is not a close
MAX_PENDING = 64
PENDING_TTL = 60.0
MAX_CANDIDATES = 8
KILL_WORDS = ("kill", "pkill", "killall", "taema")
GONE_WINDOW = 120.0     # how long a vanished process is remembered for a kill_done
MAX_GONE = 256
KILL_LOOKBACK = 30.0    # a kill line counts processes that vanished up to this long before its report
SHELL_KEYS = ("sh", "bash", "dash", "zsh", "fish")
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
        self.lineage = lineage.Lineage(cfg)
        self.deadlines = []     # [(due ts, kind, arg)]: job settle and question expiry, run by tick()
        self.jobs = {}          # tag -> {"shell", "status", "word", "t"} awaiting its settle deadline
        self.pending = {}       # question id -> question record
        self.next_qid = 1
        self.kills = {}         # kill id -> {"shell", "word", "t"} awaiting its settle deadline
        self.next_kid = 1
        self.gone = []          # [(ts, vanished record)] from recent observes
        self.stopped = {}       # key -> ts of the last stop (respawn tracking)
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
            rep = engine.stop(path, self.cfg, self.store, unit, hook=policy.hook_for(self.cfg, leaf))
            self.note_stop(rep)
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
        self.expire_respawns()
        sig = self._fork_sig()
        if sig is not None and sig == self.gate_sig and self.gate_skips < MAX_GATE_SKIPS:
            self.gate_skips += 1        # nothing forked and nobody joined a session: skip the walk
            return
        self.gate_sig, self.gate_skips = sig, 0
        pt = inspect.ProcTable.scan()
        self.lineage.observe(pt)
        self.guarded(self.after_observe)
        if not self.units:
            self.last_result["adopt"] = []
            return
        ops = engine.adopt_plan(self.cfg, self.units, pt) + engine.carve_plan(self.cfg, self.units, pt)
        done = engine.run_ops(self.cfg, self.store, ops, self.may_move())
        for op in done:
            if op["op"] == "carve" and op["done"] and op.get("binds_to") == "root":
                self.watch_owner(op["scope"], op["root"])
        self.last_result["adopt"] = [{"op": o["op"], "scope": o["scope"], "pids": len(o["pids"]),
                                      "done": o["done"]} for o in done]

    # ---- learning hooks (log only: nothing here kills) ----
    def note_stop(self, rep):
        """Remember the keys a stop killed, to see whether they come back (respawn / GC outcome)."""
        now = time.time()
        for d in (rep or {}).get("decisions", []):
            if d.get("action") == "kill":
                self.stopped[d["key"]] = now
        while len(self.stopped) > 256:
            del self.stopped[min(self.stopped, key=self.stopped.get)]

    def expire_respawns(self):
        """A stopped key that did not reappear within timers.respawn_window was a good stop."""
        w = policy.timer(self.cfg, "respawn_window", 60)
        now = time.time()
        for k in [k for k, t in self.stopped.items() if now - t > w]:
            del self.stopped[k]
            self.store.gc_outcome(k, False)

    def after_observe(self):
        lin, now = self.lineage, time.time()
        self.gone = [g for g in self.gone if now - g[0] <= GONE_WINDOW] + [(now, r) for r in lin.vanished()]
        del self.gone[:-MAX_GONE]
        w = policy.timer(self.cfg, "respawn_window", 60)
        for eid in lin.born:
            e = lin.entries.get(eid)
            t = self.stopped.get(e["key"]) if e else None
            if t is None or now - t > w:
                continue
            pe = lin.entry(e["ppid"])
            # re-running the same command from a shell is not a respawn; a supervisor or another app is
            same = pe is not None and pe["sid"] == pe["pid"] and pe["tty"] != 0
            if not same:        # a shell re-run is neither a respawn nor evidence about the stop
                self.store.respawn(e["key"], False)
                self.store.gc_outcome(e["key"], True)
            del self.stopped[e["key"]]
        for rid in lin.closed:
            owner = lin.ghosts.get(rid, {}).get("key")
            if owner:
                left = lin.leftovers_of(rid[0])
                for key in dict.fromkeys(l["key"] for l in left):
                    self.store.observe_close(owner, key)       # weight 0: only counts closes
                self.attribute(owner, left, root=rid[0])

    def attribute(self, owner, leftovers, root=None, job=None):
        """Log would_attribute / would_stop for each distinct leftover key. Returns {key: decision}."""
        out = {}
        for key in dict.fromkeys(l["key"] for l in leftovers):
            pids = [l["pid"] for l in leftovers if l["key"] == key]
            out[key] = self.store.pair_decision(owner, key)
            self.store.log(event="would_attribute", owner=owner, leftover=key, pids=pids[:8], root=root, job=job)
            if out[key][0] == "stop":
                self.store.log(event="would_stop", owner=owner, leftover=key, confidence=round(out[key][1], 2),
                               why=out[key][2], mode=self.mode)
        return out

    # ---- terminal jobs and questions ----
    def add_deadline(self, due, kind, arg):
        self.deadlines.append((due, kind, arg))

    def run_deadlines(self):
        now = time.time()
        due = [d for d in self.deadlines if d[0] <= now]
        self.deadlines = [d for d in self.deadlines if d[0] > now]
        for _t, kind, arg in due:
            if kind == "job":
                self.guarded(lambda: self.decide_job(arg))
            elif kind == "kill":
                self.guarded(lambda: self.decide_kill(arg))
            elif kind == "expire":
                self.guarded(lambda: self.expire_question(arg))

    def job_done(self, msg):
        shell, tag, status, word = msg.get("shell_pid"), msg.get("tag"), msg.get("status"), msg.get("word")
        if not isinstance(shell, int) or isinstance(shell, bool) or not isinstance(status, int) \
                or isinstance(status, bool) or not isinstance(tag, str) or not isinstance(word, str) \
                or len(word) > 32 or not 0 <= status <= 255:
            return {"error": "bad request"}
        if shell <= 1 or inspect.uid_of(shell) != os.getuid():
            return {"error": "shell gone or not yours"}
        if not tag.startswith("%d." % shell) or not lineage._TAG.fullmatch(tag):
            return {"error": "bad request"}
        if status in STOPPED_JOB:
            return {"ok": True, "ignored": "stopped, not closed"}
        if len(self.jobs) >= MAX_PENDING and tag not in self.jobs:
            del self.jobs[min(self.jobs, key=lambda t: self.jobs[t]["t"])]
        self.jobs[tag] = {"shell": shell, "status": status, "word": lineage.clean(word, 32), "t": time.time()}
        self.add_deadline(time.time() + JOB_SETTLE, "job", tag)
        return {"ok": True}

    def decide_job(self, tag):
        """After the settle: who survived the job, whose are they, and is a question due."""
        j = self.jobs.pop(tag, None)
        if j is None:
            return
        self.lineage.observe(inspect.ProcTable.scan())
        self.guarded(self.after_observe)        # observe resets closed/born: consume them here too
        left = self.lineage.leftovers_of(tag)
        if not left:
            return
        info = self.lineage.job_info(tag) or {}
        owner = info.get("root_key") or next((l["root_key"] for l in left if l["root_key"]), "") or j["word"]
        owner = owner.replace(knowledge.SEP, "")[:256]
        if not owner:
            return
        launcher = not info or j["t"] - info["first"] < JOB_LAUNCHER
        keys = list(dict.fromkeys(l["key"] for l in left))
        for k in keys:
            self.store.observe_close(owner, k, launcher=launcher)
        if launcher:
            self.store.log(event="launcher_learned", job=tag, owner=owner, leftovers=keys[:8])
            return
        dec = self.attribute(owner, left, job=tag)
        ask = [k for k in keys if dec[k][0] == "ask" and self.store.can_ask((owner, k))]
        if ask:
            self.make_question(j, tag, owner, left, ask)

    def candidates(self, owner, left):
        """Owners to offer, job root first, then recorded ancestors, then historical owners."""
        prot = self.cfg["protected"].get("comm", [])
        out, seen = [], set()

        def add(kind, key):
            if key and key not in seen and len(out) < MAX_CANDIDATES:
                seen.add(key)
                out.append({"id": len(out) + 1, "kind": kind, "key": key, "label": lineage.clean(key, 48)})
        add("job", owner)
        for l in left:
            for k, cid in zip(l["chain"], l["chain_ids"]):
                e = self.lineage.entries.get(cid)
                if k in SHELL_KEYS or policy.comm_protected(k, prot) or self.store.is_persistent(k) \
                        or (e is not None and (e["sid"] == e["pid"] or self.lineage.ptmx_host(e["pid"]))):
                    continue
                add("ancestor", k)
        for l in left:
            for o in self.store.owners_of(l["key"]):
                add("historic", o)
        return out

    def kill_done(self, msg):
        shell, word = msg.get("shell_pid"), msg.get("word")
        if not isinstance(shell, int) or isinstance(shell, bool) or word not in KILL_WORDS:
            return {"error": "bad request"}
        if shell <= 1 or inspect.uid_of(shell) != os.getuid():
            return {"error": "shell gone or not yours"}
        if len(self.kills) >= MAX_PENDING:
            del self.kills[min(self.kills)]
        kid, self.next_kid = self.next_kid, self.next_kid + 1
        self.kills[kid] = {"shell": shell, "word": word, "t": time.time()}
        self.add_deadline(time.time() + JOB_SETTLE, "kill", kid)
        return {"ok": True}

    def decide_kill(self, kid):
        """After the settle: tracked processes that vanished around the kill line. Each is weak
        evidence for its recorded owner; one may become a "was it part of X?" question."""
        k = self.kills.pop(kid, None)
        if k is None:
            return
        self.lineage.observe(inspect.ProcTable.scan())
        self.guarded(self.after_observe)
        prot = self.cfg["protected"].get("comm", [])
        asks, used = [], []
        for ts, r in self.gone:
            if ts < k["t"] - KILL_LOOKBACK or r["root"] is None:
                continue
            used.append(r)
            key = r["key"]
            if not key or key in SHELL_KEYS or policy.comm_protected(key, prot) or self.store.is_persistent(key):
                continue
            # the recorded owner: the app root it was a member of, else the nearest real ancestor
            owner = next((c for c in [r["root_key"], r["parent_key"]] + list(r["chain"])
                          if c and c != key and c not in SHELL_KEYS and not policy.comm_protected(c, prot)
                          and not self.store.is_persistent(c)), None)
            if owner is None:
                continue
            owner = owner.replace(knowledge.SEP, "")[:256]
            self.store.observe_kill_inferred(owner, key)
            if self.store.pair_decision(owner, key)[0] == "ask" and self.store.can_ask((owner, key)):
                asks.append((owner, key, r))
        self.gone = [g for g in self.gone if not any(g[1] is u for u in used)]
        if asks:
            owner, key, r = asks[0]
            left = [{"key": key, "comm": key.split(":")[-1], "chain": list(r["chain"]),
                     "chain_ids": [None] * len(r["chain"])}]
            self.make_question({"shell": k["shell"], "word": k["word"]}, None, owner, left, [key], kind="closed")

    def make_question(self, j, tag, owner, left, ask_keys, kind="job"):
        shell = j["shell"]
        for qid in [i for i, q in self.pending.items() if q["shell_pid"] == shell]:
            self.drop_question(qid)
        while len(self.pending) >= MAX_PENDING:
            self.drop_question(min(self.pending, key=lambda i: self.pending[i]["created"]))
        qid, self.next_qid = self.next_qid, self.next_qid + 1
        cnt = {}
        for l in left:
            if l["key"] in ask_keys:
                cnt.setdefault(l["key"], {"key": l["key"], "comm": l["comm"], "count": 0})["count"] += 1
        q = {"id": qid, "kind": kind, "nonce": secrets.token_hex(8), "shell_pid": shell, "tag": tag, "word": j["word"],
             "owner": owner, "ask_keys": list(ask_keys), "candidates": self.candidates(owner, left),
             "leftovers": list(cnt.values()), "created": time.time(), "shown": False}
        self.pending[qid] = q
        self.add_deadline(q["created"] + PENDING_TTL, "expire", qid)
        self.write_q(q)
        self.store.log(event="question_ready", id=qid, shell=shell, owner=owner, leftovers=list(cnt))

    # per-shell pending file: the prompt hook only tests that it exists
    @staticmethod
    def qdir():
        rd = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
        return rd + "/taema"

    def write_q(self, q):
        d = self.qdir()
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
            fd = os.open("%s/q.%d" % (d, q["shell_pid"]), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"id": q["id"]}) + "\n")
        except OSError as e:
            self.store.log(event="question_file_failed", error=str(e))

    def drop_question(self, qid):
        q = self.pending.pop(qid, None)
        if q and not any(o["shell_pid"] == q["shell_pid"] for o in self.pending.values()):
            try:
                os.unlink("%s/q.%d" % (self.qdir(), q["shell_pid"]))
            except OSError:
                pass
        return q

    def expire_question(self, qid):
        q = self.pending.get(qid)
        if q is not None and time.time() - q["created"] >= PENDING_TTL - 0.001:
            self.drop_question(qid)

    def _live_question(self, shell):
        for qid, q in list(self.pending.items()):
            if time.time() - q["created"] >= PENDING_TTL:
                self.drop_question(qid)
        return next((q for q in self.pending.values() if q["shell_pid"] == shell), None)

    def ask_question(self, msg):
        shell = msg.get("shell_pid")
        if not isinstance(shell, int) or isinstance(shell, bool) or shell <= 1:
            return {"error": "bad request"}
        if inspect.uid_of(shell) != os.getuid():
            return {"error": "shell gone or not yours"}
        q = self._live_question(shell)
        if q is None:
            return {"question": None, "reason": "none"}
        pairs = [(q["owner"], k) for k in q["ask_keys"]]
        if not q["shown"]:
            ok = [p for p in pairs if self.store.can_ask(p)]
            if not ok:
                self.drop_question(q["id"])
                return {"question": None, "reason": "rate_limited"}
            q["shown"] = True
            self.store.mark_asked(ok)
        return {"question": {"id": q["id"], "kind": q["kind"], "nonce": q["nonce"], "shell_pid": shell, "job": q["word"],
                             "candidates": q["candidates"], "leftovers": q["leftovers"],
                             "choices": list(knowledge.CHOICES),
                             "expires_in": max(0, int(PENDING_TTL - (time.time() - q["created"])))}}

    def answer_question(self, msg):
        nonce, choice, owner = msg.get("nonce"), msg.get("choice"), msg.get("owner")
        if not isinstance(nonce, str) or not 0 < len(nonce) < 65 or choice not in knowledge.CHOICES \
                or (owner is not None and not isinstance(owner, str)):
            return {"error": "bad request"}
        q = next((x for x in self.pending.values() if hmac.compare_digest(x["nonce"], nonce)), None)
        if q is None or time.time() - q["created"] >= PENDING_TTL:
            if q is not None:
                self.drop_question(q["id"])
            return {"error": "unknown or expired nonce"}
        keys = [c["key"] for c in q["candidates"]]
        if owner is None:
            owner = q["owner"]
        elif owner not in keys:
            return {"error": "owner is not a candidate"}
        for k in q["ask_keys"]:
            self.store.answer(owner, k, choice)
        self.drop_question(q["id"])
        self.store.log(event="answer", choice=choice, owner=owner, leftovers=q["ask_keys"][:8])
        self.store.save()
        return {"ok": True, "choice": choice, "owner": owner, "leftovers": q["ask_keys"]}

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
                self.note_stop(rep)
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
                    self.note_stop(engine.stop(d, self.cfg, self.store, unit,
                                               hook=policy.hook_for(self.cfg, os.path.basename(d))))
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
                    "last_adopt": self.last_result["adopt"], "last_gc": self.last_result["gc"],
                    "pairs": self.store.pairs_summary(), "standalone": sorted(self.store.data["standalone"])[:50],
                    "lineage": {"entries": len(self.lineage.entries), "ghosts": len(self.lineage.ghosts),
                                "jobs": len(self.lineage.jobs)},
                    "pending_questions": len(self.pending)}
        if c == "register":
            leaf, owner = msg.get("scope"), msg.get("owner")
            if not isinstance(leaf, str) or not cgroup.valid_rel(leaf) \
                    or not isinstance(owner, int) or isinstance(owner, bool):
                return {"error": "bad request"}
            if owner <= 1 or inspect.uid_of(owner) != os.getuid():
                return {"error": "owner gone or not yours"}
            return {"watching": self.watch_owner(leaf, owner)}
        if c == "job_done":
            return self.job_done(msg)
        if c == "kill_done":
            return self.kill_done(msg)
        if c == "ask":
            return self.ask_question(msg)
        if c == "answer":
            return self.answer_question(msg)
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
        due = min([self.last["adopt"] + self.iv_adopt, self.last["gc"] + self.iv_gc, now + MAX_SLEEP]
                  + [d[0] for d in self.deadlines])
        return max(0.0, min(MAX_SLEEP, due - now))

    def tick(self):
        """Run what is due: socket check, adopt (+ session end), GC, routine save."""
        self.guarded(self.check_socket)
        self.run_deadlines()
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
        for qid in list(self.pending):
            self.drop_question(qid)
        self.store.log(event="daemon_stop")
        self.store.save()
        return 0


def run():
    cfg = policy.load_config()
    return Daemon(cfg).run()
