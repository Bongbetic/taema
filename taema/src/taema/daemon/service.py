"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Every lifecycle decision point asks the one authorization ladder
(taema.authorization.authorize) instead of checking the mode itself: observe logs only, adopt
moves, enforce also kills, auto moves and gives every app root its own scope; auto stops only what
a learned or answered pair authorises (engine.auto_stop_ok, re-checked at actuation).
"""

import collections
import hmac
import json
import os
import secrets
import select
import selectors
import signal
import socket
import stat
import struct
import time

from ..model import authorization
from ..core import cgroup, process as inspect, lineage
from ..governor import engine
from ..store import knowledge
from ..config import policy
from .. import protocol

MAX_OWNERS = 256  # pidfd owner watches
MAX_LEAF_WATCH = 256  # cgroup.events watches (EPOLLPRI)
MAX_SLEEP = 60.0  # longest select() sleep
JOB_SETTLE = (
    1.5  # seconds between job_done and the decision (survivors must outlive it)
)
JOB_LAUNCHER = (
    2.0  # a job shorter than this is a launcher: its close is noise, never a pair
)
STOPPED_JOB = (148, 149, 150)  # 128 + SIGTSTP/SIGTTIN/SIGTTOU: Ctrl-Z is not a close
MAX_PENDING = 64
PENDING_TTL = 60.0
MAX_CANDIDATES = 8
KILL_WORDS = ("kill", "pkill", "killall", "taema")
GONE_WINDOW = 120.0  # how long a vanished process is remembered for a kill_done
MAX_GONE = 256
KILL_LOOKBACK = (
    30.0  # a kill line counts processes that vanished up to this long before its report
)
SHELL_KEYS = ("sh", "bash", "dash", "zsh", "fish")
MAX_GATE_SKIPS = 4  # fork gate: at most 4 skipped adopt passes, so every 5th one runs


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self._in_tick = False
        self.deny = policy.owner_deny(cfg)
        self.store = knowledge.Store(
            policy.state_dir(cfg),
            cfg.get("seeds"),
            deny=self.deny,
            mode=cfg.get("mode", "observe"),
        )
        self.store.apply_feedback()
        self.restore_runtime_hold()
        self.store.expire_reviews()
        self.store.save_if_dirty()
        self.units = policy.load_units(cfg)
        self.config_error = None
        self.profile_reason = cfg.get("_profile_reason", "automatic profile selection")
        self.reload_requested = False
        self._config_watch_paths = policy.config_watch_paths(cfg)
        self._config_fingerprint = policy.file_fingerprint(self._config_watch_paths)
        self.sel = selectors.DefaultSelector()
        self.owners = {}  # pidfd -> (scope leaf name, owner pid, owner starttime)
        self.idle_since = {}
        self.gc_usage = {}  # rel -> cpu usage_usec when the idle window started
        self.gc_skip = set()  # leaves with a protected member: not retried
        self.gc_noted = set()  # leaves already logged as kept
        self.srv = None
        self.sock_path = None
        self.last = {"adopt": 0.0, "gc": 0.0}
        self.iv_adopt = policy.timer(cfg, "adopt_interval", 15)
        self.iv_gc = policy.timer(cfg, "gc_interval", 60)
        self.gate_sig = (
            None  # fork gate: (last pid, session pid sets) of the last adopt pass
        )
        self.gate_skips = 0
        self.leaf_ep = (
            None  # epoll on leaf cgroup.events (EPOLLPRI), itself in self.sel
        )
        self.leaf_watch = {}  # fd -> (leaf rel, open cgroup.events file)
        self.leaf_nowatch = (
            set()
        )  # leaves that could not be watched: the GC pass checks them
        self.empty_seen = set()  # leaves seen empty by the previous GC pass
        self.last_result = {"adopt": None, "gc": None}
        self.lineage = lineage.Lineage(cfg)
        self.deadlines = []  # [(due ts, kind, arg)]: job settle and question expiry, run by tick()
        self.jobs = {}  # tag -> {"shell", "status", "word", "t"} awaiting its settle deadline
        self.pending = {}  # question id -> question record
        self.next_qid = 1
        self.kills = {}  # kill id -> {"shell", "word", "t"} awaiting its settle deadline
        self.next_kid = 1
        self.gone = []  # [(ts, vanished record)] from recent observes
        self.stopped = {}  # key -> ts of the last stop (respawn tracking)
        self.auto_scopes = set()  # app-* scopes created by auto adoption (status)
        self.auto_stops = collections.deque(
            maxlen=5
        )  # last auto stops, newest last (status)
        self.auto_recent = {}  # leftover key -> (owner key, ts) of an auto stop, for regret
        self.started = time.time()
        self.stopping = False
        self.toggle_hold_requested = False
        self.session_seen = False

    def restore_runtime_hold(self):
        """Import an offline runtime marker and honor the cautious service boot setting."""
        runtime = self.store._read_runtime_hold()
        state = self.store.hold_status(include_pending=False, include_runtime=False)
        runtime_until = runtime.get("snooze_until")
        if (
            isinstance(runtime_until, (int, float))
            and not isinstance(runtime_until, bool)
            and time.time() < runtime_until
            and runtime_until > (state["snooze_until"] or 0)
        ):
            self.store.apply_feedback_command(
                {
                    "v": 2,
                    "id": secrets.token_hex(16),
                    "op": "snooze",
                    "until": runtime_until,
                    "reason": runtime.get("reason")
                    or "restored runtime snooze after daemon restart",
                }
            )
            state = self.store.hold_status(include_pending=False, include_runtime=False)
        if runtime.get("held") is True and not state["global"]:
            self.store.apply_feedback_command(
                {
                    "v": 2,
                    "id": secrets.token_hex(16),
                    "op": "hold",
                    "held": True,
                    "reason": runtime.get("reason")
                    or "restored runtime hold after daemon restart",
                }
            )
            state = self.store.hold_status(include_pending=False, include_runtime=False)
        if os.environ.get("TAEMA_HOLD") == "1" and not state["global"]:
            self.store.apply_feedback_command(
                {
                    "v": 2,
                    "id": secrets.token_hex(16),
                    "op": "hold",
                    "held": True,
                    "reason": "TAEMA_HOLD=1 service setting",
                }
            )
        self.store.sync_runtime_hold()

    # ---- mode gates ----
    # Predicates for code and tests that ask what a mode means; the decision points themselves
    # ask the authorization ladder via self.authorize() (taema.authorization).
    @property
    def mode(self):
        return self.cfg["mode"]

    def auto(self):
        return self.mode == "auto"

    def may_move(self):
        return self.mode in ("adopt", "enforce", "auto")

    def may_kill(self):
        """Global kill switch: enforce only. Auto stops go through engine.auto_stop_ok per pair."""
        return self.mode == "enforce"

    def log_would_stop(self, event, scope, why):
        """Log a would-stop decision only when its scope, mode, or reason signature changes."""
        path = scope if os.path.isabs(scope) else os.path.join(cgroup.base(), scope)
        members = tuple(
            (pid, inspect.starttime(pid)) for pid in cgroup.tree_procs(path)
        )
        if why.startswith("idle "):
            reason = "idle"
        elif " gone:" in why:
            reason = why.split(" gone:", 1)[0] + " gone"
        else:
            reason = why
        key = event + ":" + scope
        signature = (self.mode, members, reason)
        if self.store.changed(key, signature):
            with self.store.decision_context(
                "would_stop",
                scope=scope,
                authority="mode",
                mode=self.mode,
                why=why,
            ):
                self.store.log(event=event, scope=scope, why=why, mode=self.mode)

    def authorize(self, trigger, facts=None):
        """Ask the one authorization ladder (taema.authorization) for `trigger` in the current
        mode; every lifecycle decision point below routes through it instead of checking the mode."""
        f = facts or authorization.Facts()
        suppress_stops = bool(self.cfg.get("_profile_suppress_stops"))
        if f.suppress_stops != suppress_stops:
            f = authorization.Facts(
                scope=f.scope,
                leftover=f.leftover,
                shared=f.shared,
                unit_survive_logout=f.unit_survive_logout,
                vetoed=f.vetoed,
                held=f.held,
                suppress_stops=suppress_stops,
            )
        if f.scope:
            path = (
                f.scope
                if os.path.isabs(f.scope)
                else os.path.join(cgroup.base(), f.scope)
            )
            veto = engine.veto_for_scope(self.store, path) if not f.vetoed else None
            held = self.store.hold_reason(f.scope) if not f.held else ""
            if veto or held:
                f = authorization.Facts(
                    scope=f.scope,
                    leftover=f.leftover,
                    shared=f.shared,
                    unit_survive_logout=f.unit_survive_logout,
                    vetoed=f.vetoed or (self.store.describe_veto(veto) if veto else ""),
                    held=f.held or held,
                    suppress_stops=f.suppress_stops,
                )
        dec = authorization.authorize(trigger, self.mode, f)
        if dec.slot == authorization.VETO:
            with self.store.decision_context(
                "refusal",
                scope=f.scope or None,
                authority="veto",
                mode=self.mode,
                why=dec.reason,
            ):
                self.store.log(
                    event="vetoed",
                    trigger=trigger,
                    scope=f.scope or None,
                    target=dec.reason,
                )
        elif dec.slot == authorization.HOLD and self.store.changed(
            "action_held:%s:%s" % (trigger, f.scope),
            (self.mode, dec.reason),
        ):
            with self.store.decision_context(
                "hold",
                scope=f.scope or None,
                authority="hold",
                mode=self.mode,
                why=dec.reason,
            ):
                self.store.log(
                    event="action_held",
                    trigger=trigger,
                    scope=f.scope or None,
                    reason=dec.reason,
                )
        elif dec.verdict == authorization.KEEP and self.store.changed(
            "authorization_refused:%s:%s" % (trigger, f.scope),
            (self.mode, dec.slot, dec.reason),
        ):
            with self.store.decision_context(
                "refusal",
                scope=f.scope or None,
                authority=dec.authority or dec.slot,
                mode=self.mode,
                why=dec.reason,
            ):
                self.store.log(
                    event="authorization_refused",
                    trigger=trigger,
                    scope=f.scope or None,
                )
        return dec

    # ---- owner watch ----
    def watch_owner(self, leaf, pid):
        if any(l == leaf for l, _p, _s in self.owners.values()):
            return True  # already watched (first owner wins)
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
        self.stop_leaf(leaf, "owner %d exited" % pid, owner=pid)

    def stop_leaf(self, leaf, why, owner=None):
        path = "%s/%s" % (cgroup.base(), leaf)
        dec = self.authorize(authorization.OWNER_EXIT, authorization.Facts(scope=leaf))
        if dec.verdict == authorization.WOULD_ACT:
            self.log_would_stop("would_stop", leaf, why)
            return
        if dec.verdict != authorization.ACT or not os.path.isdir(path):
            # keep: a future veto/hold blocks silently here. An absent leaf can still be
            # observed in observe mode when a unit's binds_to=root is only a projected carve.
            return
        unit = engine.unit_for_leaf(self.units, os.path.basename(leaf))
        try:
            with self.store.decision_context(
                "stop",
                scope=leaf,
                owner=owner,
                authority=authorization.AUTHORITY_UNIT,
                mode=self.mode,
                why=why,
            ) as decision:
                rep = engine.stop(
                    path,
                    self.cfg,
                    self.store,
                    unit,
                    hook=policy.hook_for(self.cfg, leaf),
                    decision_authority=authorization.AUTHORITY_UNIT,
                    decision_why=why,
                    decision_owner=owner,
                )
                self.note_stop(rep)
                stopped = [
                    d["key"]
                    for d in rep.get("decisions", [])
                    if d.get("action") == "kill"
                ]
                if stopped:
                    self.note_auto_stop(leaf, why, [], apps=stopped, decision=decision)
                self.store.log(event="stopped", scope=leaf, why=why)
        except engine.Refused as e:
            self.store.log(event="stop_refused", scope=leaf, why=str(e))
        except Exception as e:  # never let one scope take the daemon down
            self.store.log(
                event="stop_error", scope=leaf, error="%s: %s" % (type(e).__name__, e)
            )

    # ---- loops ----
    def _fork_sig(self):
        """Cheap change signature: /proc/loadavg last pid plus the session cgroup pid sets."""
        try:
            with open(inspect.PROC + "/loadavg") as f:
                last_pid = f.read().split()[4]
        except (OSError, IndexError):
            return None
        return (
            last_pid,
            tuple(
                (d, frozenset(cgroup.procs(d))) for d in policy.session_dirs(self.cfg)
            ),
        )

    def adopt_pass(self):
        self.store.expire_reviews()
        self._save_if_idle()
        self.expire_respawns()
        sig = self._fork_sig()
        if (
            sig is not None
            and sig == self.gate_sig
            and self.gate_skips < MAX_GATE_SKIPS
        ):
            self.gate_skips += (
                1  # nothing forked and nobody joined a session: skip the walk
            )
            return
        self.gate_sig, self.gate_skips = sig, 0
        pt = inspect.ProcTable.scan()
        self.lineage.observe(pt)
        self.guarded(self.after_observe)
        unit_decision = self.authorize(authorization.UNIT_ADOPT)
        execute = unit_decision.verdict == authorization.ACT
        done = []
        if self.units:
            ops = engine.adopt_plan(self.cfg, self.units, pt) + engine.carve_plan(
                self.cfg, self.units, pt
            )
            done = engine.run_ops(
                self.cfg,
                self.store,
                ops,
                execute,
                cleanup=False,
                decision_kind="adopt_move",
                authority=unit_decision.authority or "mode",
            )
            for op in done:
                owner_bound = (
                    op["op"] == "carve"
                    and op.get("binds_to") == "root"
                    and op.get("root") in op.get("pids", [])
                )
                if owner_bound and (op["done"] or self.mode == "observe"):
                    self.watch_owner(op["scope"], op["root"])
        self.last_result["adopt"] = [
            {
                "op": o["op"],
                "scope": o["scope"],
                "pids": len(o["pids"]),
                "done": o["done"],
            }
            for o in done
        ]
        decision = self.authorize(authorization.AUTO_ADOPT)
        would_scopes = (
            [op["scope"] for op in done]
            if unit_decision.verdict == authorization.WOULD_ACT
            else []
        )
        if decision.verdict in (authorization.ACT, authorization.WOULD_ACT):
            auto_done = []
            self.guarded(
                lambda: auto_done.extend(
                    self.auto_adopt(
                        pt,
                        execute=decision.verdict == authorization.ACT,
                        cleanup=False,
                        authority=decision.authority or "mode",
                    )
                )
            )
            if decision.verdict == authorization.WOULD_ACT:
                would_scopes.extend(op["scope"] for op in auto_done)
        self.store.forget_sigs(
            "adopt_would:", {"adopt_would:" + s for s in would_scopes}
        )

    def auto_adopt(self, pt, execute=True, cleanup=True, authority="mode"):
        """Give every app root its own scope (engine.auto_adopt_plan), at most 64 new ones per pass."""
        ops = engine.auto_adopt_plan(self.cfg, self.units, pt, self.lineage, self.store)
        if ops:
            try:
                for op in engine.run_ops(
                    self.cfg,
                    self.store,
                    ops,
                    execute,
                    cleanup=cleanup,
                    decision_kind="adopt_move",
                    authority=authority,
                ):
                    if execute and op["done"]:
                        self.auto_scopes.add(op["scope"])
            except engine.Refused as e:
                if self.store.changed("auto_adopt_refused", str(e)):
                    self.store.log(event="auto_adopt_refused", error=str(e))
        base = cgroup.base()
        self.auto_scopes = {
            s for s in self.auto_scopes if os.path.isdir(base + "/" + s)
        }
        return ops

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
        self.gone = [g for g in self.gone if now - g[0] <= GONE_WINDOW] + [
            (now, r) for r in lin.vanished()
        ]
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
            if (
                not same
            ):  # a shell re-run is neither a respawn nor evidence about the stop
                self.store.respawn(e["key"], False)
                self.store.gc_outcome(e["key"], True)
            del self.stopped[e["key"]]
        self.check_regret(lin, now)
        for rid in lin.closed:
            owner = lin.ghosts.get(rid, {}).get("key")
            if owner:
                left = lin.leftovers_of(rid[0])
                for key in dict.fromkeys(l["key"] for l in left):
                    self.store.observe_close(
                        owner, key, launcher=False
                    )  # weight 0: only counts closes
                self.attribute(owner, left, root=rid[0])
                if left and not lin.ghosts.get(rid, {}).get("terminal"):
                    dec = self.authorize(authorization.GUI_CLOSE)
                    if dec.verdict == authorization.ACT:
                        self.guarded(
                            lambda: self.gui_close(
                                rid, owner, left, authority=dec.authority or "mode"
                            )
                        )
                    elif dec.verdict == authorization.WOULD_ACT:
                        self.guarded(
                            lambda: self.would_contain_gui_close(rid, owner, left)
                        )

    # ---- auto mode: silent GUI closes, survivors of closed jobs, regret ----
    def check_regret(self, lin, now):
        """The same leftover key reappearing within 30 min of an auto stop, under any owner, undoes it."""
        for k in [
            k
            for k, (_o, t) in self.auto_recent.items()
            if now - t > knowledge.REGRET_WINDOW
        ]:
            del self.auto_recent[k]
        for eid in lin.born:
            e = lin.entries.get(eid)
            hit = self.auto_recent.get(e["key"]) if e else None
            if hit and self.store.regret(hit[0], e["key"]):
                self.store.log(event="regret", owner=hit[0], leftover=e["key"])
                del self.auto_recent[e["key"]]

    def note_auto_stop(self, scope, why, pairs, apps=(), decision=None, owner=None):
        """Remember an auto stop: knowledge, undo history, status ring, and decisions.log."""
        now = time.time()
        for o, k in pairs:
            self.store.auto_stopped(o, k)
            self.auto_recent[k] = (o, now)
        self.store.record_auto_action(
            scope,
            why,
            pairs,
            apps,
            decision=decision,
            owner=owner,
            authority=(decision or {}).get("authority", "mode"),
        )
        self._save_if_idle()
        while len(self.auto_recent) > 256:
            del self.auto_recent[
                min(self.auto_recent, key=lambda k: self.auto_recent[k][1])
            ]
        self.auto_stops.append(
            {
                "ts": int(now),
                "scope": scope,
                "why": why,
                "pairs": [
                    "%s > %s" % (lineage.clean(o, 24), lineage.clean(k, 24))
                    for o, k in pairs
                ][:6],
            }
        )

    def adopt_standalone(self, items, owner=None):
        """Leftovers the user declared standalone get their own app scope and are never stopped."""
        by_key = {}
        for l in items:
            by_key.setdefault(l["key"], []).append(l)
        ops = [
            {
                "op": "move",
                "scope": engine.auto_scope_name(k, ls[0]["pid"], ls[0]["start"]),
                "owner": owner,
                "unit": None,
                "auto": True,
                "pids": [l["pid"] for l in ls],
            }
            for k, ls in by_key.items()
        ]
        try:
            for op in engine.run_ops(
                self.cfg,
                self.store,
                ops,
                True,
                decision_kind="containment",
                authority="user",
            ):
                if op["done"]:
                    self.auto_scopes.add(op["scope"])
        except engine.Refused as e:
            self.store.log(event="standalone_adopt_refused", error=str(e))

    def gui_close(self, rid, owner, left, authority="mode"):
        """A GUI root vanished (not a terminal job): standalone leftovers get their own scope, the rest
        go to leftover/<owner>-<id> with a pending review that holds the scope until answered or expiry."""
        standalone = [l for l in left if self.store.standalone(l["key"])]
        rest = [l for l in left if not self.store.standalone(l["key"])]
        if standalone:
            self.adopt_standalone(standalone, owner)
        if rest:
            name = "%s/%s" % (engine.LEFTOVER, engine.leaf_slug(owner, rid[0]))
            try:
                ops = engine.run_ops(
                    self.cfg,
                    self.store,
                    [
                        {
                            "op": "move",
                            "scope": name,
                            "owner": owner,
                            "unit": None,
                            "auto": True,
                            "pids": [l["pid"] for l in rest],
                        }
                    ],
                    True,
                    decision_kind="containment",
                    authority=authority,
                )
                op = next((x for x in ops if x.get("done")), None)
                if op:
                    moved = set(op["pids"])
                    contained = [l for l in rest if l["pid"] in moved]
                    review = self.store.add_review(owner, contained, name)
                    if review:
                        self.store.log(
                            event="review_created",
                            decision_id=op.get("decision_id"),
                            corr=op.get("corr"),
                            id=review["id"],
                            owner=owner,
                            scope=name,
                            survivors=review["survivors"],
                            pids=review["pids"],
                        )
                        self._save_if_idle()
            except engine.Refused as e:
                self.store.log(event="leftover_move_refused", scope=name, error=str(e))

    def would_contain_gui_close(self, rid, owner, left):
        """Record one observe-mode would-action for the survivors of a closed GUI root."""
        pids = sorted({l["pid"] for l in left})
        keys = sorted({l["key"] for l in left})
        signature = (owner, tuple(keys), tuple(pids))
        key = "would_contain:%d.%d" % rid
        if self.store.changed(key, signature):
            with self.store.decision_context(
                "containment_would",
                owner=owner,
                authority="mode",
                mode=self.mode,
                why="observe mode would contain GUI survivors",
            ):
                self.store.log(
                    event="would_contain",
                    owner=owner,
                    root=rid[0],
                    survivors=keys,
                    pids=pids,
                )

    def _infos(self, pids, origin=None):
        """member_info for each pid from one ss snapshot ('edges unknown' when ss failed)."""
        pids = list(pids)
        s = inspect.LazySnapshot().get() if pids else None
        ok = getattr(s, "ok", True)
        edge_map = inspect.edges(set(pids), s) if pids else {}
        return [
            engine.member_info(self.cfg, self.lineage, p, edge_map, ok, origin)
            for p in pids
        ]

    def auto_stop_path(self, path, why, require_pair):
        """Stop one scope on auto authority. require_pair: every member must pass auto_stop_ok (a pair
        decided stop); otherwise only the idle checks (known CPU, no edges, no pty host, not protected) apply.
        SIGKILL only when every pair was answered explicitly. Returns True when the scope was removed."""
        leaf = cgroup.rel(path)
        infos = self._infos(cgroup.tree_procs(path))
        if not infos:
            return False
        for i in infos:
            if require_pair:
                ok, w = engine.auto_stop_ok(self.store, i["origin"], i["key"], i)
            else:
                cpu = i.get("cpu")
                ok = not (
                    i["edges"] is None
                    or i["edges"]
                    or i["protected"]
                    or i["ptmx"]
                    or cpu is None
                    or cpu > engine.AUTO_MAX_CPU
                )
                if i["edges"] is None:
                    w = "edges unknown"
                elif i["edges"]:
                    w = "has edges"
                elif i["protected"]:
                    w = "protected: %s" % i["protected"]
                elif i["ptmx"]:
                    w = "pty host"
                elif cpu is None:
                    w = "cpu unknown"
                elif cpu > engine.AUTO_MAX_CPU:
                    w = "cpu %.1f%% > %.0f%%" % (cpu, engine.AUTO_MAX_CPU)
                else:
                    w = "idle checks passed"
            if not ok:
                with self.store.decision_context(
                    "refusal",
                    scope=leaf,
                    owner=i.get("origin"),
                    authority="pair" if require_pair else "mode",
                    mode=self.mode,
                    why=w,
                ):
                    self.store.log(
                        event="auto_stop_refused",
                        scope=leaf,
                        pid=i["pid"],
                        key=i["key"],
                        why=w,
                    )
                return False
        pairs = [(i["origin"], i["key"]) for i in infos if i["origin"]]
        explicit = require_pair and all(
            self.store.pair_explicit(o, k) for o, k in pairs
        )
        grace = engine.auto_grace(self.store, {i["key"] for i in infos})
        unit = engine.unit_for_leaf(self.units, os.path.basename(path))
        with self.store.decision_context(
            "stop",
            scope=leaf,
            owner=pairs[0][0] if pairs else None,
            authority="pair" if require_pair else "mode",
            mode=self.mode,
            why=why,
        ) as decision:
            try:
                rep = engine.stop(
                    path,
                    self.cfg,
                    self.store,
                    unit,
                    hook=policy.hook_for(self.cfg, os.path.basename(path)),
                    timeout=grace,
                    allow_sigkill=explicit,
                    decision_authority=decision["authority"],
                    decision_why=why,
                    decision_owner=decision["owner"],
                )
            except engine.Refused as e:
                self.store.log(event="auto_stop_refused", scope=leaf, why=str(e))
                return False
            self.note_stop(rep)
            self.note_auto_stop(
                leaf,
                why,
                list(dict.fromkeys(pairs)),
                apps=[d["key"] for d in rep["decisions"] if d.get("action") == "kill"],
                decision=decision,
                owner=decision["owner"],
            )
            return rep["removed"]

    def auto_stop_survivors(self, tag, owner, left, dec):
        """Survivors of a closed terminal job whose pair is decided stop: those that pass auto_stop_ok
        are carved into <host scope>/job-<id> (when the host scope is under user/<uid>, no sudo) and
        stopped there, else signalled in place. Everyone else is left alone."""
        want = [l for l in left if dec.get(l["key"], ("",))[0] == "stop"]
        if not want:
            return
        allowed = []
        for l in want:
            veto = self.store.match_veto(
                members=[{"pid": l["pid"], "start": l.get("start"), "apps": [l["key"]]}]
            )
            if veto:
                with self.store.decision_context(
                    "refusal",
                    owner=owner,
                    authority="veto",
                    mode=self.mode,
                    why="veto blocked survivor stop",
                ):
                    self.store.log(
                        event="vetoed",
                        trigger=authorization.JOB_SURVIVORS,
                        job=tag,
                        pid=l["pid"],
                        target=self.store._target(veto),
                    )
            else:
                allowed.append(l)
        want = allowed
        if not want:
            return
        infos = {
            i["pid"]: i for i in self._infos([l["pid"] for l in want], origin=owner)
        }
        good = []
        for l in want:
            ok, w = engine.auto_stop_ok(self.store, owner, l["key"], infos[l["pid"]])
            if ok:
                good.append(l)
            else:
                with self.store.decision_context(
                    "refusal",
                    owner=owner,
                    authority="pair",
                    mode=self.mode,
                    why=w,
                ):
                    self.store.log(
                        event="auto_stop_refused",
                        job=tag,
                        pid=l["pid"],
                        key=l["key"],
                        why=w,
                    )
        if not good:
            return
        pairs = list(dict.fromkeys((owner, l["key"]) for l in good))
        explicit = all(self.store.pair_explicit(o, k) for o, k in pairs)
        grace = engine.auto_grace(self.store, {k for _o, k in pairs})
        me = "/user/%d/" % os.getuid()
        slug = tag.replace(".", "-")
        carved, loose = {}, []
        for l in good:
            cg = cgroup.proc_cgroup(l["pid"]) or ""
            host = cg[len(me) :].strip("/") if cg.startswith(me) else None
            if (
                host
                and cgroup.valid_rel(host + "/job-" + slug)
                and inspect.starttime(l["pid"]) == l["start"]
            ):
                carved.setdefault(host, []).append(l["pid"])
            else:
                loose.append(l)
        why = "closed job %s: %s" % (tag, self.store.pair_decision(*pairs[0])[2])
        with self.store.decision_context(
            "stop",
            scope="job-" + slug,
            owner=owner,
            authority="pair",
            mode=self.mode,
            why=why,
        ) as decision:
            for host, pids in carved.items():
                scope = "%s/job-%s" % (host, slug)
                with self.store.decision_context(
                    "containment",
                    scope=scope,
                    owner=owner,
                    authority="pair",
                    mode=self.mode,
                    why="carve closed-job survivors into a private leaf",
                ):
                    dest = cgroup.mkleaf(scope)
                    for p in pids:
                        cgroup.move(p, dest)
                    self.store.log(
                        event="containment",
                        scope=scope,
                        pids=pids,
                        owner=owner,
                    )
                try:
                    self.note_stop(
                        engine.stop(
                            dest,
                            self.cfg,
                            self.store,
                            None,
                            timeout=grace,
                            allow_sigkill=explicit,
                            decision_kind="stop",
                            decision_authority="pair",
                            decision_why=why,
                            decision_owner=owner,
                        )
                    )
                except engine.Refused as e:
                    self.store.log(
                        event="auto_stop_refused", scope=cgroup.rel(dest), why=str(e)
                    )
            if loose:
                engine.signal_survivors(self.cfg, loose, grace, explicit)
                self.store.log(
                    event="stop", scope="job-" + slug, pids=[l["pid"] for l in loose]
                )
            self.note_auto_stop(
                "job-" + slug,
                why,
                pairs,
                apps=[l["key"] for l in good],
                decision=decision,
                owner=owner,
            )

    def attribute(self, owner, leftovers, root=None, job=None):
        """Log would_attribute / would_stop for each distinct leftover key. Returns {key: decision}."""
        out = {}
        for key in dict.fromkeys(l["key"] for l in leftovers):
            pids = [l["pid"] for l in leftovers if l["key"] == key]
            out[key] = self.store.pair_decision(owner, key)
            self.store.log(
                event="would_attribute",
                owner=owner,
                leftover=key,
                pids=pids[:8],
                root=root,
                job=job,
            )
            if out[key][0] == "stop":
                self.store.log(
                    event="would_stop",
                    owner=owner,
                    leftover=key,
                    confidence=round(out[key][1], 2),
                    why=out[key][2],
                    mode=self.mode,
                )
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
        shell, tag, status, word = (
            msg.get("shell_pid"),
            msg.get("tag"),
            msg.get("status"),
            msg.get("word"),
        )
        if (
            not isinstance(shell, int)
            or isinstance(shell, bool)
            or not isinstance(status, int)
            or isinstance(status, bool)
            or not isinstance(tag, str)
            or not isinstance(word, str)
            or len(word) > 32
            or not 0 <= status <= 255
        ):
            return {"error": "bad request"}
        if shell <= 1 or inspect.uid_of(shell) != os.getuid():
            return {"error": "shell gone or not yours"}
        if not tag.startswith("%d." % shell) or not lineage._TAG.fullmatch(tag):
            return {"error": "bad request"}
        if status in STOPPED_JOB:
            return {"ok": True, "ignored": "stopped, not closed"}
        if len(self.jobs) >= MAX_PENDING and tag not in self.jobs:
            del self.jobs[min(self.jobs, key=lambda t: self.jobs[t]["t"])]
        self.jobs[tag] = {
            "shell": shell,
            "status": status,
            "word": lineage.clean(word, 32),
            "t": time.time(),
        }
        self.add_deadline(time.time() + JOB_SETTLE, "job", tag)
        return {"ok": True}

    def resolve_owner(self, info, left):
        """Real application ancestor for a terminal job: the job root, a leftover's root, or the
        first valid ancestor in a leftover's chain. Generic/digit/shell/trivial/scriptless names
        are skipped; '' means nothing real owned the job and the close is launcher noise."""
        cands = [info.get("root_key")]
        for l in left:
            cands.append(l.get("root_key"))
            cands.extend(l.get("chain") or ())
        for c in cands:
            if not c:
                continue
            c = c.replace(knowledge.SEP, "")[:256]
            if c and not policy.bad_owner(c, self.deny):
                return c
        return ""

    def decide_job(self, tag):
        """After the settle: who survived the job, whose are they, and is a question due."""
        j = self.jobs.pop(tag, None)
        if j is None:
            return
        self.lineage.observe(inspect.ProcTable.scan())
        self.guarded(
            self.after_observe
        )  # observe resets closed/born: consume them here too
        left = self.lineage.leftovers_of(tag)
        if not left:
            return
        info = self.lineage.job_info(tag) or {}
        owner = self.resolve_owner(info, left)
        launcher = not info or j["t"] - info["first"] < JOB_LAUNCHER
        keys = list(dict.fromkeys(l["key"] for l in left))
        for k in keys:
            self.store.observe_close(
                owner, k, launcher=launcher
            )  # noise for launchers and bad owners
        if self.authorize(authorization.JOB_SURVIVORS).verdict == authorization.ACT:
            standalone = [l for l in left if self.store.standalone(l["key"])]
            if standalone:
                self.guarded(lambda: self.adopt_standalone(standalone))
        if not owner or launcher:
            self.store.log(
                event="launcher_learned",
                job=tag,
                owner=owner,
                leftovers=keys[:8],
                why="no application ancestor" if not owner else "launcher",
            )
            return
        dec = self.attribute(owner, left, job=tag)
        members = [
            {"pid": l["pid"], "start": l.get("start"), "apps": [l["key"]]} for l in left
        ]
        veto = self.store.match_veto(members=members)
        facts = authorization.Facts(
            vetoed=self.store.describe_veto(veto) if veto else ""
        )
        if (
            self.authorize(authorization.JOB_SURVIVORS, facts).verdict
            == authorization.ACT
        ):
            self.guarded(lambda: self.auto_stop_survivors(tag, owner, left, dec))
        ask = [k for k in keys if dec[k][0] == "ask" and self.store.can_ask((owner, k))]
        if ask:
            self.make_question(j, tag, owner, left, ask)

    def candidates(self, owner, left):
        """Owners to offer, job root first, then recorded ancestors, then historical owners.
        Invalid owners (policy.bad_owner) are never offered."""
        prot = self.cfg["protected"].get("comm", [])
        out, seen = [], set()

        def add(kind, key):
            if (
                key
                and key not in seen
                and len(out) < MAX_CANDIDATES
                and not policy.bad_owner(key, self.deny)
            ):
                seen.add(key)
                out.append(
                    {
                        "id": len(out) + 1,
                        "kind": kind,
                        "key": key,
                        "label": lineage.clean(key, 48),
                    }
                )

        add("job", owner)
        for l in left:
            for k, cid in zip(l["chain"], l["chain_ids"]):
                e = self.lineage.entries.get(cid)
                if (
                    k in SHELL_KEYS
                    or policy.comm_protected(k, prot)
                    or self.store.is_persistent(k)
                    or (
                        e is not None
                        and (e["sid"] == e["pid"] or self.lineage.ptmx_host(e["pid"]))
                    )
                ):
                    continue
                add("ancestor", k)
        for l in left:
            for o in self.store.owners_of(l["key"]):
                add("historic", o)
        return out

    def kill_done(self, msg):
        shell, word = msg.get("shell_pid"), msg.get("word")
        if (
            not isinstance(shell, int)
            or isinstance(shell, bool)
            or word not in KILL_WORDS
        ):
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
            if (
                not key
                or key in SHELL_KEYS
                or policy.comm_protected(key, prot)
                or self.store.is_persistent(key)
            ):
                continue
            # the recorded owner: the app root it was a member of, else the nearest real ancestor
            owner = next(
                (
                    c
                    for c in [r["root_key"], r["parent_key"]] + list(r["chain"])
                    if c
                    and c != key
                    and c not in SHELL_KEYS
                    and not policy.comm_protected(c, prot)
                    and not self.store.is_persistent(c)
                    and not policy.bad_owner(c, self.deny)
                ),
                None,
            )
            if owner is None:
                continue
            owner = owner.replace(knowledge.SEP, "")[:256]
            self.store.observe_kill_inferred(owner, key)
            if self.store.pair_decision(owner, key)[0] == "ask" and self.store.can_ask(
                (owner, key)
            ):
                asks.append((owner, key, r))
        self.gone = [g for g in self.gone if not any(g[1] is u for u in used)]
        if asks:
            owner, key, r = asks[0]
            left = [
                {
                    "key": key,
                    "comm": key.split(":")[-1],
                    "chain": list(r["chain"]),
                    "chain_ids": [None] * len(r["chain"]),
                }
            ]
            self.make_question(
                {"shell": k["shell"], "word": k["word"]},
                None,
                owner,
                left,
                [key],
                kind="closed",
            )

    def make_question(self, j, tag, owner, left, ask_keys, kind="job"):
        shell = j["shell"]
        for qid in [i for i, q in self.pending.items() if q["shell_pid"] == shell]:
            self.drop_question(qid)
        while len(self.pending) >= MAX_PENDING:
            self.drop_question(
                min(self.pending, key=lambda i: self.pending[i]["created"])
            )
        qid, self.next_qid = self.next_qid, self.next_qid + 1
        cnt = {}
        for l in left:
            if l["key"] in ask_keys:
                cnt.setdefault(
                    l["key"], {"key": l["key"], "comm": l["comm"], "count": 0}
                )["count"] += 1
        q = {
            "id": qid,
            "kind": kind,
            "nonce": secrets.token_hex(8),
            "shell_pid": shell,
            "tag": tag,
            "word": j["word"],
            "owner": owner,
            "ask_keys": list(ask_keys),
            "candidates": self.candidates(owner, left),
            "leftovers": list(cnt.values()),
            "created": time.time(),
            "shown": False,
        }
        self.pending[qid] = q
        self.add_deadline(q["created"] + PENDING_TTL, "expire", qid)
        self.write_q(q)
        self.store.log(
            event="question_ready",
            id=qid,
            shell=shell,
            owner=owner,
            leftovers=list(cnt),
        )

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
            fd = os.open(
                "%s/q.%d" % (d, q["shell_pid"]),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"id": q["id"]}) + "\n")
        except OSError as e:
            self.store.log(event="question_file_failed", error=str(e))

    def drop_question(self, qid):
        q = self.pending.pop(qid, None)
        if q and not any(
            o["shell_pid"] == q["shell_pid"] for o in self.pending.values()
        ):
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
        return {
            "question": {
                "id": q["id"],
                "kind": q["kind"],
                "nonce": q["nonce"],
                "shell_pid": shell,
                "job": q["word"],
                "candidates": q["candidates"],
                "leftovers": q["leftovers"],
                "choices": list(knowledge.CHOICES),
                "expires_in": max(0, int(PENDING_TTL - (time.time() - q["created"]))),
            }
        }

    def answer_question(self, msg):
        nonce, choice, owner = msg.get("nonce"), msg.get("choice"), msg.get("owner")
        if (
            not isinstance(nonce, str)
            or not 0 < len(nonce) < 65
            or choice not in knowledge.CHOICES
            or (owner is not None and not isinstance(owner, str))
        ):
            return {"error": "bad request"}
        q = next(
            (
                x
                for x in self.pending.values()
                if hmac.compare_digest(x["nonce"], nonce)
            ),
            None,
        )
        if q is None or time.time() - q["created"] >= PENDING_TTL:
            if q is not None:
                self.drop_question(q["id"])
            with self.store.decision_context(
                "refusal",
                owner=owner,
                authority="user",
                mode=self.mode,
                why="answer did not match a live question",
            ):
                self.store.log(
                    event="answer_refused", reason="unknown or expired nonce"
                )
            return {"error": "unknown or expired nonce"}
        keys = [c["key"] for c in q["candidates"]]
        if owner is None:
            owner = q["owner"]
        elif owner not in keys:
            with self.store.decision_context(
                "refusal",
                owner=owner,
                authority="user",
                mode=self.mode,
                why="answer owner is not a candidate",
            ):
                self.store.log(
                    event="answer_refused", reason="owner is not a candidate"
                )
            return {"error": "owner is not a candidate"}
        with self.store.decision_context(
            "answer",
            owner=owner,
            authority="user",
            mode=self.mode,
            why="user answered %s" % choice,
        ):
            for k in q["ask_keys"]:
                self.store.answer(owner, k, choice)
            self.drop_question(q["id"])
            self.store.log(
                event="answer", choice=choice, owner=owner, leftovers=q["ask_keys"][:8]
            )
            self.store.save()
        return {
            "ok": True,
            "choice": choice,
            "owner": owner,
            "leftovers": q["ask_keys"],
        }

    # ---- empty leaves ----
    def _empty_leaf_dirs(self):
        base = cgroup.base()
        return [
            d
            for parent in cgroup.LEAF_PARENTS
            for d in cgroup.subdirs(base + "/" + parent)
        ] + [
            d
            for d in cgroup.subdirs(base)
            if os.path.basename(d).startswith(engine.EMPTY_PREFIXES)
            and os.path.basename(d) != "manager"
        ]

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
            if (
                rel in watched
                or rel in self.leaf_nowatch
                or len(self.leaf_watch) >= MAX_LEAF_WATCH
            ):
                continue
            try:
                if self.leaf_ep is None:
                    self.leaf_ep = select.epoll()
                    self.sel.register(
                        self.leaf_ep.fileno(), selectors.EVENT_READ, "leaves"
                    )
                f = open(d + "/cgroup.events")
                f.read()  # arm: EPOLLPRI fires on the next change after a read
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
        if self.authorize(authorization.GC_REMOVE_EMPTY).verdict != authorization.ACT:
            return False
        leaf = cgroup.rel(path)
        if engine.remove_empty(path):
            self.empty_seen.discard(leaf)
            self.store.log(event="gc_removed_empty", scope=leaf, why=why)
            return True
        return False

    def _gc_empty(self, path, leaf, dry_run, res, now_empty):
        """Empty leaf: removed on the second consecutive GC pass that sees it empty (a scope that
        was just created is empty until its first process arrives)."""
        dec = self.authorize(authorization.GC_REMOVE_EMPTY)
        if dry_run or dec.verdict != authorization.ACT:
            res.append([leaf, "empty", "would"])
            if not dry_run and self.store.changed("gc_empty:" + leaf, True):
                self.store.log(
                    event="gc_would_remove_empty", scope=leaf, mode=self.mode
                )
            return
        res.append([leaf, "empty", "remove"])
        if leaf in self.empty_seen:
            self.remove_leaf(path, "empty")
        else:
            now_empty.add(leaf)

    def _queue_gc_review(self, path, leaf, why):
        """Queue a pair review for known leftover ownership, otherwise a scope-level GC review."""
        before = self.store.data.get("review_seq", 0)
        pids = cgroup.tree_procs(path)
        infos = self._infos(pids)
        owners = {}
        for info in infos:
            owner = info.get("origin")
            if owner and not policy.bad_owner(owner, self.store.deny):
                owners.setdefault(owner, []).append(
                    {"pid": info["pid"], "key": info["key"]}
                )
        if owners and leaf.startswith(engine.LEFTOVER + "/"):
            for owner, members in owners.items():
                review = self.store.add_review(owner, members, leaf)
                if review and review["id"] > before:
                    self.store.log(
                        event="review_created",
                        id=review["id"],
                        owner=owner,
                        scope=leaf,
                        survivors=review["survivors"],
                        pids=review["pids"],
                        source="gc",
                    )
                    before = review["id"]
        else:
            review = self.store.add_scope_review(leaf, why)
            if review and review["id"] > before:
                self.store.log(
                    event="gc_review_created", id=review["id"], scope=leaf, why=why
                )
        self._save_if_idle()
        return self.store.review_holds_scope(leaf)

    def gc_pass(self, dry_run=False):
        self.store.expire_reviews()
        self._save_if_idle()
        if self.store.apply_feedback():
            self._save_if_idle()
        self.store.decay()
        self.store.enforce_caps()
        # candidate selection: leftover/* leaves are stop candidates only where the ladder allows
        leftover_leaves = (
            self.authorize(authorization.LEFTOVER_LEAVES).verdict == authorization.ACT
        )
        cands = engine.gc_candidates(
            self.cfg,
            self.units,
            self.store,
            self.idle_since,
            usage=self.gc_usage,
            skip=self.gc_skip,
            noted=self.gc_noted,
            lin=self.lineage,
            auto=leftover_leaves,
        )
        res, now_empty = [], set()
        remove_empty = (
            self.authorize(authorization.GC_REMOVE_EMPTY).verdict == authorization.ACT
        )
        if not dry_run and remove_empty:
            self.sync_leaf_watches()
        for path, why in cands:
            leaf = cgroup.rel(path)
            if why == "empty":
                self._gc_empty(path, leaf, dry_run, res, now_empty)
                continue
            dec = self.authorize(
                authorization.GC_STOP,
                authorization.Facts(
                    scope=leaf, leftover=leaf.startswith(engine.LEFTOVER + "/")
                ),
            )
            res.append(
                [
                    leaf,
                    why,
                    "would"
                    if (dry_run or dec.verdict != authorization.ACT)
                    else "stop",
                ]
            )
            if dry_run:
                continue
            if dec.verdict == authorization.WOULD_ACT:
                self.log_would_stop("gc_would_stop", leaf, why)
                if self.mode == "adopt" and (
                    leaf.startswith("shared/")
                    or engine.unit_for_leaf(self.units, os.path.basename(path))
                ):
                    res[-1][2] = "review"
                    self._queue_gc_review(path, leaf, why)
                continue
            if (
                dec.verdict != authorization.ACT
            ):  # keep: a future veto/hold blocks silently here
                continue
            if (
                self.mode == "auto"
                and leaf.startswith(engine.LEFTOVER + "/")
                and why.startswith("idle")
            ):
                res[-1][2] = "review"
                self._queue_gc_review(path, leaf, why)
                continue
            if self.mode == "auto":
                require_pair = (
                    dec.authority == authorization.AUTHORITY_PAIR
                    and why.startswith("pair stop")
                )
                self.guarded(lambda: self.auto_stop_path(path, why, require_pair))
                continue
            with self.store.decision_context(
                "stop",
                scope=leaf,
                authority=dec.authority or "mode",
                mode=self.mode,
                why=why,
            ) as decision:
                try:
                    rep = engine.stop(
                        path,
                        self.cfg,
                        self.store,
                        engine.unit_for_leaf(self.units, os.path.basename(path)),
                        hook=policy.hook_for(self.cfg, os.path.basename(path)),
                        decision_authority=dec.authority,
                        decision_why=why,
                    )
                except engine.Refused as e:
                    self.store.log(event="gc_refused", scope=leaf, why=str(e))
                    continue
                self.note_stop(rep)
                stopped = [
                    d["key"]
                    for d in rep.get("decisions", [])
                    if d.get("action") == "kill"
                ]
                if stopped:
                    self.note_auto_stop(leaf, why, [], apps=stopped, decision=decision)
                if rep["removed"]:
                    self.store.log(event="gc_stopped", scope=leaf, why=why)
                elif any(d["action"] == "skip" for d in rep["decisions"]):
                    self.gc_skip.add(leaf)
                    self.store.log(
                        event="gc_kept", scope=leaf, why="kept: protected member"
                    )
                else:
                    self.store.log(
                        event="gc_incomplete", scope=leaf, why=rep.get("error", "busy")
                    )
        if not dry_run:
            self.empty_seen = now_empty
            self.store.forget_sigs(
                "gc_empty:", {"gc_empty:" + r[0] for r in res if r[1] == "empty"}
            )
        self.last_result["gc"] = res
        return res

    def session_ended(self):
        """True once every login session of this user has gone (after at least one was seen)."""
        st = policy.session_state()
        if st is not None:  # elogind's per-user state file: no cgroup scan
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
        top = cgroup.subdirs(cgroup.base())
        # leftover/* leaves count as scopes of their own; shared/ is never stopped (auto only)
        if self.authorize(authorization.LEFTOVER_LEAVES).verdict == authorization.ACT:
            top = [
                d for d in top if os.path.basename(d) != engine.LEFTOVER
            ] + cgroup.subdirs(cgroup.base() + "/" + engine.LEFTOVER)
        for d in top:
            if os.path.basename(d) == "manager":
                continue
            unit = engine.unit_for_leaf(self.units, os.path.basename(d))
            dec = self.authorize(
                authorization.SESSION_END,
                authorization.Facts(
                    scope=cgroup.rel(d),
                    shared=os.path.basename(d) == "shared",
                    unit_survive_logout=bool(
                        unit and unit.get("kill", {}).get("survive_logout")
                    ),
                ),
            )
            if dec.verdict == authorization.KEEP:
                self.store.log(event="session_end_kept", scope=cgroup.rel(d))
                continue
            if dec.verdict == authorization.WOULD_ACT:
                self.log_would_stop("would_stop", cgroup.rel(d), "session ended")
                continue
            if dec.authority == authorization.AUTHORITY_PAIR:
                # keep everything unless every member's pair is confidently "stop"
                if not self.auto_stop_path(d, "session ended", True):
                    self.store.log(event="session_end_kept", scope=cgroup.rel(d))
                continue
            scope = cgroup.rel(d)
            with self.store.decision_context(
                "stop",
                scope=scope,
                authority=dec.authority or "mode",
                mode=self.mode,
                why="session ended",
            ) as decision:
                try:
                    rep = engine.stop(
                        d,
                        self.cfg,
                        self.store,
                        unit,
                        hook=policy.hook_for(self.cfg, os.path.basename(d)),
                        decision_authority=dec.authority,
                        decision_why="session ended",
                    )
                    self.note_stop(rep)
                    stopped = [
                        x["key"]
                        for x in rep.get("decisions", [])
                        if x.get("action") == "kill"
                    ]
                    if stopped:
                        self.note_auto_stop(
                            scope, "session ended", [], apps=stopped, decision=decision
                        )
                except engine.Refused as error:
                    self.store.log(event="stop_refused", scope=scope, why=str(error))
        self.session_seen = False  # wait for the next login before acting again

    def guarded(self, fn):
        try:
            fn()
        except Exception as e:  # a failed pass must not stop the daemon
            self.store.log(
                event="error",
                where=getattr(fn, "__name__", "?"),
                error="%s: %s" % (type(e).__name__, e),
            )

    def _save_if_idle(self):
        """Defer routine writes until the end of a daemon pass."""
        if not self._in_tick:
            self.store.save_if_dirty()

    # ---- socket API ----
    def handle(self, msg):
        if not isinstance(msg, dict):
            return {"error": "bad request"}
        c = msg.get("cmd")
        if c == "doctor":
            from ..doctor import diagnose

            if self.config_error:
                return diagnose(
                    self.cfg,
                    self.store,
                    self.units,
                    config_error=self.config_error,
                )
            return diagnose(self.cfg, self.store, self.units)
        if c == "reload":
            reason = msg.get("reason", "reload command")
            if not isinstance(reason, str) or len(reason) > 256:
                return {"error": "bad request"}
            result = self.reload_config(reason)
            return result
        if c == "status":
            self.store.expire_reviews()
            self._save_if_idle()
            return {
                "mode": self.mode,
                "profile": self.cfg.get("_profile_name", "auto"),
                "profile_reason": self.profile_reason,
                "uptime_s": int(time.time() - self.started),
                "owners": [
                    {"scope": l, "owner": p} for l, p, _s in self.owners.values()
                ],
                "idle_tracked": {
                    k: int(time.time() - v) for k, v in self.idle_since.items()
                },
                "last_adopt": self.last_result["adopt"],
                "last_gc": self.last_result["gc"],
                "pairs": self.store.pairs_summary(),
                "standalone": sorted(self.store.data["standalone"])[:50],
                "lineage": {
                    "entries": len(self.lineage.entries),
                    "ghosts": len(self.lineage.ghosts),
                    "jobs": len(self.lineage.jobs),
                },
                "pending_questions": len(self.pending),
                "reviews": self.store.review_count,
                "recovery": self.store.recovery,
                "latest_decision": self.store.latest_decision(),
                "feedback_invalid": self.store.data.get("feedback_invalid", 0),
                "hold": self.store.hold_reason(),
                "hold_state": self.store.hold_status(),
                "config_error": self.config_error,
                "config": list(self.cfg.get("_sources", [])),
                "unit_errors": list(self.cfg.get("_unit_errors", [])),
                "auto": self.auto_status(),
            }
        if c == "review":
            self.store.expire_reviews()
            self._save_if_idle()
            return {"reviews": self.store.open_reviews()}
        if c == "register":
            leaf, owner = msg.get("scope"), msg.get("owner")
            if (
                not isinstance(leaf, str)
                or not cgroup.valid_rel(leaf)
                or not isinstance(owner, int)
                or isinstance(owner, bool)
            ):
                return {"error": "bad request"}
            if owner <= 1 or inspect.uid_of(owner) != os.getuid():
                return {"error": "owner gone or not yours"}
            return {"watching": self.watch_owner(leaf, owner)}
        if c == "attach":
            return self.attach(msg)
        if c == "job_done":
            return self.job_done(msg)
        if c == "kill_done":
            return self.kill_done(msg)
        if c == "ask":
            return self.ask_question(msg)
        if c == "answer":
            return self.answer_question(msg)
        if c == "gc":
            was_in_tick = self._in_tick
            was_deferred = self.store.defer_writes
            self._in_tick = True
            self.store.defer_writes = True
            try:
                candidates = self.gc_pass(dry_run=msg.get("dry_run") is True)
            finally:
                self._in_tick = was_in_tick
                self.store.defer_writes = was_deferred
            if not was_deferred:
                self.store.save_if_dirty()
            return {"candidates": candidates}
        if c == "feedback":
            if msg.get("v") in (1, 2):
                result = self.store.apply_feedback_command(
                    {key: value for key, value in msg.items() if key != "cmd"}
                )
                if result is None:
                    return {"error": "bad request"}
                if not result.get("duplicate"):
                    self.store.save()
                return result
            if not self.store.apply_op(msg.get("op"), msg.get("key")):
                return {"error": "bad request"}
            self.store.save()
            return {"ok": True}
        return {"error": "unknown command"}

    def auto_status(self):
        base = cgroup.base()
        return {
            "auto_adopted_scopes": len(self.auto_scopes),
            "leftover_leaves": len(cgroup.subdirs(base + "/" + engine.LEFTOVER)),
            "auto_stops": list(self.auto_stops),
        }

    def attach(self, msg):
        """taema run from a shell that lacks the taema group: attach the caller's pids through the
        helper, which this daemon (started with the group) may call. Only pids of this uid."""
        scope, pids = msg.get("scope"), msg.get("pids")
        if (
            not isinstance(scope, str)
            or not isinstance(pids, list)
            or not 0 < len(pids) <= 64
            or any(
                not isinstance(p, int) or isinstance(p, bool) or p <= 1 for p in pids
            )
        ):
            return {"error": "bad request"}
        name = scope[len("scope-") :] if scope.startswith("scope-") else scope
        if (
            not cgroup.valid_rel(name)
            or "/" in name
            or len(name) > 32
            or not cgroup.valid_rel(scope)
        ):
            return {"error": "bad request"}
        me = os.getuid()
        if any(inspect.uid_of(p) != me for p in pids):
            return {"error": "pid gone or not yours"}
        done = []
        with self.store.decision_context(
            "containment",
            scope="scope-" + name,
            owner=pids[0] if pids else None,
            authority="user",
            mode=self.mode,
            why="attach caller processes to an explicit scope",
        ):
            for p in dict.fromkeys(pids):
                try:
                    engine.helper_attach(self.cfg, p, name)
                except engine.Refused as e:
                    self.store.log(event="refusal", scope="scope-" + name, why=str(e))
                    return {"error": "attach failed: %s" % e, "attached": done}
                done.append(p)
            self.store.log(event="attach", scope="scope-" + name, pids=done[:8])
        return {"ok": True, "attached": done}

    def _read_request(self, conn):
        """Bytes up to a newline (or EOF) within 0.5 s total and 64 KiB."""
        deadline = time.monotonic() + 0.5
        buf = b""
        while b"\n" not in buf and len(buf) <= 65536:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("request too slow")
            conn.settimeout(left)
            chunk = conn.recv(65537 - len(buf))
            if not chunk:
                break
            buf += chunk
        if len(buf) > 65536:
            raise ValueError("request too large")
        return buf

    def serve(self, srv):
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            pid, uid, _gid = struct.unpack(
                "3i",
                conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if uid != os.getuid():
                reply = {"error": "forbidden"}
            else:
                data = self._read_request(conn)
                if not data.strip():
                    reply = {"error": "empty"}
                else:
                    message = json.loads(data.decode("utf-8"))
                    if protocol.is_v2(message):
                        identifier = protocol.request_id(message)
                        try:
                            command = protocol.decode_v2(message)
                        except protocol.ProtocolError as error:
                            reply = protocol.error_reply(identifier, error)
                        else:
                            reply = protocol.reply_v2(identifier, self.handle(command))
                    elif protocol.is_legacy(message):
                        reply = self.handle(message)
                    elif isinstance(message, dict) and "v" in message:
                        reply = protocol.error_reply(
                            protocol.request_id(message),
                            protocol.ProtocolError(
                                "unsupported_version",
                                "Unsupported protocol version.",
                                "Use v=2.",
                            ),
                        )
                    else:
                        reply = {"error": "bad request"}
        except (
            Exception
        ) as e:  # bad input of any shape gets an error reply, never a crash
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
            from ..cli.commands import sock_path

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
        if (
            self.srv is None
            or want != self.sock_path
            or not os.path.exists(self.sock_path)
        ):
            self.bind(want)
            self.store.log(event="socket_bound", path=want)

    def thaw_held_scopes(self):
        """Thaw frozen managed scopes covered by a global, snooze, or scope hold."""
        state = self.store.hold_status()
        global_hold = state["global"] or state["snooze_until"] is not None
        held_scopes = state["scopes"]
        if not global_hold and not held_scopes:
            return
        stack = list(cgroup.subdirs(cgroup.base()))
        while stack:
            path = stack.pop()
            if os.path.basename(path) == "manager":
                continue
            scope = cgroup.rel(path)
            stack.extend(cgroup.subdirs(path))
            if not global_hold and not any(
                scope == held or scope.startswith(held + "/") for held in held_scopes
            ):
                continue
            freeze = os.path.join(path, "cgroup.freeze")
            try:
                with open(freeze, encoding="ascii") as source:
                    frozen = source.read().strip() == "1"
                if not frozen:
                    continue
                reason = self.store.hold_reason(scope) or "runtime hold"
                with self.store.decision_context(
                    "thaw",
                    scope=scope,
                    authority="hold",
                    mode=self.mode,
                    why="hold thawed a managed freeze: %s" % reason,
                ):
                    with open(freeze, "w", encoding="ascii") as target:
                        target.write("0\n")
                    self.store.log(event="thaw", scope=scope, reason=reason)
            except OSError as error:
                self.store.log(
                    event="thaw_failed",
                    scope=scope,
                    reason="%s: %s" % (self.store.hold_reason(scope) or "hold", error),
                )

    def _on_signal(self, signum, _frame):
        if signum == getattr(signal, "SIGUSR1", None):
            self.toggle_hold_requested = True
        elif signum == getattr(signal, "SIGHUP", None):
            self.reload_requested = True
        else:
            self.stopping = True

    def reload_config(self, reason="configuration reload"):
        """Install a validated config and units snapshot, retaining the current one on error."""
        old_cfg, old_units, old_store = self.cfg, self.units, self.store
        try:
            cfg = policy.load_config()
            units = policy.load_units(cfg)
            old_state_dir = old_cfg.get("paths", {}).get("state_dir")
            new_state_dir = cfg.get("paths", {}).get("state_dir")
            if policy.expand(old_state_dir) != policy.expand(new_state_dir):
                old_holds = old_store.hold_status(
                    include_pending=True, include_runtime=False
                )
                old_store.apply_feedback()
                new_store = knowledge.Store(
                    policy.state_dir(cfg),
                    cfg.get("seeds"),
                    deny=policy.owner_deny(cfg),
                    mode=cfg.get("mode", "observe"),
                )
                new_store.apply_feedback()
                new_store.expire_reviews()
                new_holds = new_store.hold_status(
                    include_pending=False, include_runtime=False
                )
                new_store.data["held"] = old_holds["global"] or new_holds["global"]
                new_store.data["held_scopes"] = sorted(
                    set(old_holds["scopes"]) | set(new_holds["scopes"])
                )
                snoozes = [
                    until
                    for until in (old_holds["snooze_until"], new_holds["snooze_until"])
                    if until is not None
                ]
                new_store.data["snooze_until"] = max(snoozes, default=0)
                new_store.dirty = True
                new_store.save_if_dirty()
                old_store.save()
                self.store = new_store
                self.restore_runtime_hold()
        except Exception as error:
            self.cfg, self.units, self.store = old_cfg, old_units, old_store
            self.config_error = str(error)
            self._config_watch_paths = policy.config_watch_paths(self.cfg)
            self._config_fingerprint = policy.file_fingerprint(self._config_watch_paths)
            self.store.log(event="config_invalid", error=self.config_error)
            self._save_if_idle()
            return {
                "error": "configuration reload failed",
                "config_error": self.config_error,
            }

        previous_mode = old_cfg.get("mode", "observe")
        previous_profile = old_cfg.get("_profile_name", "auto")
        self.cfg = cfg
        self.units = units
        self.deny = policy.owner_deny(cfg)
        self.store.seeds = cfg.get("seeds") or {}
        self.store.deny = tuple(self.deny)
        self.store.db.deny = tuple(self.deny)
        self.store.mode = cfg.get("mode", "observe")
        self.lineage.cfg = cfg
        self.iv_adopt = policy.timer(cfg, "adopt_interval", 15)
        self.iv_gc = policy.timer(cfg, "gc_interval", 60)
        self.config_error = None
        active_profile = cfg.get("_profile_name", "auto")
        if active_profile != previous_profile:
            self.profile_reason = reason or cfg.get(
                "_profile_reason", "profile changed"
            )
            self.store.log(
                event="profile_changed",
                old=previous_profile,
                new=active_profile,
                reason=self.profile_reason,
                profile=active_profile,
            )
        if cfg.get("mode", "observe") != previous_mode:
            self.store.log(
                event="mode_changed",
                old=previous_mode,
                new=cfg.get("mode", "observe"),
                reason=reason or "configuration reload",
                profile=active_profile,
            )
        self._config_watch_paths = policy.config_watch_paths(cfg)
        self._config_fingerprint = policy.file_fingerprint(self._config_watch_paths)
        self.store.log(
            event="config_reloaded",
            mode=self.mode,
            sources=list(cfg.get("_sources", [])),
        )
        self._save_if_idle()
        return {"reloaded": True, "sources": list(cfg.get("_sources", []))}

    def poll_config_reload(self):
        """Reload on SIGHUP or a changed config, drop-in, unit, or watched directory mtime."""
        paths = policy.config_watch_paths(self.cfg)
        fingerprint = policy.file_fingerprint(paths)
        requested = self.reload_requested
        self.reload_requested = False
        if requested or fingerprint != self._config_fingerprint:
            return self.reload_config(
                "SIGHUP" if requested else "configuration file change"
            )
        return None

    def toggle_hold(self):
        """Apply a queued SIGUSR1 toggle between daemon actions."""
        if not self.toggle_hold_requested:
            return
        self.toggle_hold_requested = False
        state = self.store.hold_status(include_runtime=False)
        active = state["global"] or state["snooze_until"] is not None
        self.store.apply_feedback_command(
            {
                "v": 2,
                "id": secrets.token_hex(16),
                "op": "hold",
                "held": not active,
                "reason": "SIGUSR1 toggled actions %s"
                % ("on hold" if not active else "back on"),
            }
        )

    def next_timeout(self, now=None):
        """Seconds until the next timer is due (adopt, gc), capped at MAX_SLEEP."""
        now = time.time() if now is None else now
        due = min(
            [
                self.last["adopt"] + self.iv_adopt,
                self.last["gc"] + self.iv_gc,
                now + MAX_SLEEP,
            ]
            + [d[0] for d in self.deadlines]
        )
        return max(0.0, min(MAX_SLEEP, due - now))

    def tick(self):
        """Run what is due, skipping the pass when SQLite's writer slot is busy."""
        self._in_tick = True
        self.store.defer_writes = True
        skip_pass = False
        try:
            self.guarded(self.poll_config_reload)
            if not self.store.db.write_available():
                skip_pass = True
                self.guarded(self.thaw_held_scopes)
                self.store.log(event="store_busy", where="tick", retry=True)
                return
            self.guarded(self.check_socket)
            self.guarded(self.store.apply_feedback)
            self.guarded(self.toggle_hold)
            self.guarded(self.thaw_held_scopes)
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
        finally:
            self._in_tick = False
            self.store.defer_writes = False
            if not skip_pass:
                self.guarded(self.store.save_if_dirty)
                self.guarded(self.store.export_daily_if_due)

    def run(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGHUP, self._on_signal)
        signal.signal(signal.SIGUSR1, self._on_signal)
        wake_r, wake_w = socket.socketpair()  # a signal wakes select() at once
        wake_r.setblocking(False)
        wake_w.setblocking(False)
        self.sel.register(wake_r, selectors.EVENT_READ, "wake")
        try:
            signal.set_wakeup_fd(wake_w.fileno(), warn_on_full_buffer=False)
        except ValueError:  # not the main thread
            pass
        self.guarded(self.check_socket)
        self.store.log(
            event="daemon_start", mode=self.mode, units=[u["_file"] for u in self.units]
        )
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


def run(cfg=None):
    cfg = policy.load_config() if cfg is None else cfg
    return Daemon(cfg).run()
