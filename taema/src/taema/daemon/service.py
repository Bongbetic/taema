"""taemad: owner watch (pidfd), adopt loop, GC loop, session-end watch, unix socket API.

Single threaded. Every lifecycle decision point asks the one authorization ladder
(taema.authorization.authorize) instead of checking the mode itself: observe logs only, adopt
moves, enforce also kills, auto moves and gives every app root its own scope; auto stops only what
a learned pair or matched survivor signature authorises (engine.auto_stop_ok, re-checked at actuation).
"""

import collections
from dataclasses import dataclass, replace
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
import subprocess
import sys
import tempfile
import time

from ..model import authorization
from ..core import (
    cgroup,
    memory,
    process as inspect,
    lineage,
    signature as survivor_signature,
)
from ..governor import engine
from ..store import knowledge
from ..config import policy
from .. import events as event_views, protocol

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
MAX_SUBSCRIBERS = 16
MAX_SUBSCRIBER_QUEUE = 4096
RESTORE_START_TIMEOUT = 15.0
MAX_EVENT_REPLAY = 1000
SUBSCRIBER_CLOSE_TTL = 1.0
MAX_COLLECTOR_EVENTS = 4096


@dataclass(frozen=True, slots=True)
class OwnerExited:
    fd: int
    watch: tuple[str, int, int]


@dataclass(frozen=True, slots=True)
class LeafChanged:
    fd: int
    leaf: str


@dataclass(frozen=True, slots=True)
class LeafEmpty:
    fd: int
    leaf: str


@dataclass(frozen=True, slots=True)
class LeafFrozen:
    fd: int
    leaf: str


@dataclass(frozen=True, slots=True)
class ProcessReconcile:
    pass


@dataclass(frozen=True, slots=True)
class LeafReconcile:
    pass


@dataclass(frozen=True, slots=True)
class MemoryReconcile:
    pass


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
            learn=cfg.get("learn"),
        )
        self.store.apply_feedback()
        self.restore_runtime_hold()
        self.store.expire_reviews()
        self.store.save_if_dirty()
        self.units = policy.load_units(cfg)
        self.thaw_held_scopes()
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
        self.mem_enabled = memory.enabled(cfg)
        self.last = {"adopt": 0.0, "gc": 0.0, "memory": 0.0}
        self.iv_adopt = policy.timer(cfg, "adopt_interval", 15)
        self.iv_gc = policy.timer(cfg, "gc_interval", 60)
        self.iv_memory = 60.0
        self.memory_peaks = {}
        self.last_memory_prune = 0.0
        saved_samples = self.store.latest_memory_samples() if self.mem_enabled else {}
        self.memory_last_samples = {}
        for key, sample in saved_samples.items():
            record = memory.MemorySample.from_db_row(sample)
            if record.peak is not None:
                self.memory_peaks[key] = record.peak
            self.memory_last_samples[key] = record
        self.gate_sig = (
            None  # fork gate: (last pid, session pid sets) of the last adopt pass
        )
        self.gate_skips = 0
        self.leaf_ep = (
            None  # epoll on leaf cgroup.events (EPOLLPRI), itself in self.sel
        )
        self.leaf_watch = {}  # fd -> (leaf rel, open cgroup.events file)
        self.leaf_frozen = {}  # leaf rel -> latest cgroup.events frozen state
        self.leaf_nowatch = (
            set()
        )  # leaves that could not be watched: the GC pass checks them
        self.collector_events = collections.deque()
        self._collector_event_set = set()
        self.collector_event_drops = 0
        self.empty_seen = set()  # leaves seen empty by the previous GC pass
        self.last_result = {"adopt": None, "gc": None}
        self.lineage = lineage.Lineage(
            cfg, units=self.units, identity_sink=self.store.record_identities
        )
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
        self.started = time.time()
        self.stopping = False
        self.toggle_hold_requested = False
        self.session_seen = False
        self.subscribers = {}
        self._summary_path = os.path.join(self.qdir(), "summary")
        self._summary_dirty = True
        self._last_event = "ready"
        self.store.add_event_listener(self._publish_event)

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

    @property
    def effective_authority(self):
        return policy.effective_authority(self.cfg)

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
        f = facts if facts is not None else authorization.Facts()
        suppress_stops = bool(self.cfg.get("_profile_suppress_stops"))
        f = replace(
            f,
            suppress_stops=suppress_stops,
            learn_authority=self.effective_authority["value"],
        )
        if f.scope:
            path = (
                f.scope
                if os.path.isabs(f.scope)
                else os.path.join(cgroup.base(), f.scope)
            )
            unit = engine.unit_for_leaf(self.units, os.path.basename(path))
            veto = (
                engine.veto_for_scope(self.store, path, unit=unit)
                if not f.vetoed
                else None
            )
            unit_veto = (
                "kill.never_stop"
                if unit and unit.get("kill", {}).get("never_stop")
                else ""
            )
            held = self.store.hold_reason(f.scope) if not f.held else ""
            if veto or held or unit_veto:
                f = replace(
                    f,
                    vetoed=f.vetoed or (self.store.describe_veto(veto) if veto else ""),
                    veto_source=f.veto_source
                    or (veto.get("source", "user") if veto else ""),
                    veto_target=f.veto_target
                    or (self.store.describe_veto(veto) if veto else ""),
                    unit_veto=f.unit_veto or unit_veto,
                    held=f.held or held,
                )
        dec = authorization.authorize(trigger, self.mode, f)
        if dec.slot == authorization.VETO and f.unit_veto:
            with self.store.decision_context(
                "refusal",
                scope=f.scope or None,
                authority="unit",
                mode=self.mode,
                why=dec.reason,
            ):
                self.store.log(
                    event="unit_vetoed",
                    trigger=trigger,
                    scope=f.scope or None,
                    target=f.unit_veto,
                )
        elif dec.slot == authorization.VETO:
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
                    target=f.veto_target or f.vetoed or dec.reason,
                    source=f.veto_source or "user",
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
    def queue_collector_event(self, event):
        """Queue one immutable collector event, coalescing duplicates within the pending batch."""
        if not isinstance(
            event,
            (
                OwnerExited,
                LeafChanged,
                LeafEmpty,
                LeafFrozen,
                ProcessReconcile,
                LeafReconcile,
                MemoryReconcile,
            ),
        ):
            raise TypeError("unsupported collector event: %s" % type(event).__name__)
        if event in self._collector_event_set:
            return True
        if len(self.collector_events) >= MAX_COLLECTOR_EVENTS:
            self.collector_event_drops += 1
            return False
        self.collector_events.append(event)
        self._collector_event_set.add(event)
        return True

    def drain_collector_events(self):
        """Apply queued collector events; each handler rechecks current state before acting."""
        while self.collector_events:
            event = self.collector_events.popleft()
            self._collector_event_set.discard(event)
            self.guarded(lambda event=event: self._dispatch_collector_event(event))

    def _dispatch_collector_event(self, event):
        if isinstance(event, OwnerExited):
            self.on_owner_exit(event.fd, expected=event.watch)
        elif isinstance(event, LeafChanged):
            self._on_leaf_changed(event)
        elif isinstance(event, LeafEmpty):
            self._on_leaf_empty(event)
        elif isinstance(event, LeafFrozen):
            self._on_leaf_frozen(event)
        elif isinstance(event, ProcessReconcile):
            self.guarded(self.adopt_pass)
            if self.session_ended():
                self.guarded(self.end_session)
        elif isinstance(event, LeafReconcile):
            self.guarded(self.gc_pass)
        elif isinstance(event, MemoryReconcile):
            self.guarded(self.memory_pass)

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

    def poll_owner_watches(self):
        """Recover pidfd readiness if the selector event was missed or dropped."""
        if not self.owners:
            return
        poller = select.poll()
        for fd in tuple(self.owners):
            poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        for fd, _mask in poller.poll(0):
            watch = self.owners.get(fd)
            if watch is not None:
                self.queue_collector_event(OwnerExited(fd, watch))

    def on_owner_exit(self, fd, expected=None):
        watch = self.owners.get(fd)
        if watch is None or (expected is not None and watch != expected):
            return False
        leaf, pid, _st = self.owners.pop(fd)
        self.sel.unregister(fd)
        os.close(fd)
        self.stop_leaf(leaf, "owner %d exited" % pid, owner=pid)
        return True

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
                stopped_pids = self.note_stop(rep)
                stopped = self.stopped_apps(rep, stopped_pids)
                if stopped:
                    self.note_auto_stop(
                        leaf,
                        why,
                        [],
                        apps=stopped,
                        decision=decision,
                        restore=rep.get("restore"),
                    )
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
        """Remember only processes confirmed gone after a stop signal."""
        now = time.time()
        stopped = set((rep or {}).get("stopped", []))
        for d in (rep or {}).get("decisions", []):
            if d.get("action") == "kill" and d.get("pid") in stopped:
                self.stopped[d["key"]] = now
        while len(self.stopped) > 256:
            oldest = min(self.stopped, key=self.stopped.get)
            del self.stopped[oldest]
        return stopped

    @staticmethod
    def stopped_apps(rep, stopped_pids=None):
        """App keys whose planned kill pids were confirmed gone after signalling."""
        stopped_pids = set(
            (rep or {}).get("stopped", []) if stopped_pids is None else stopped_pids
        )
        return sorted(
            {
                item["key"]
                for item in (rep or {}).get("decisions", [])
                if item.get("action") == "kill"
                and item.get("pid") in stopped_pids
                and isinstance(item.get("key"), str)
            }
        )

    def expire_respawns(self):
        """A stopped key that did not reappear within timers.respawn_window was a good stop."""
        w = policy.timer(self.cfg, "respawn_window", 60)
        now = time.time()
        for k in [k for k, t in self.stopped.items() if now - t > w]:
            del self.stopped[k]
            self.store.gc_outcome(k, False)
        self.store.expire_auto_stops(
            now,
            respawn_window=self.store.respawn_window,
            revive_window=self.store.revive_window,
        )

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
                valid_owner = lin.ghosts.get(rid, {}).get(
                    "identity_validated", False
                ) and not policy.bad_owner(owner, self.deny)
                terminal = lin.ghosts.get(rid, {}).get("terminal", False)
                for key in dict.fromkeys(l["key"] for l in left):
                    self.store.observe_close(
                        owner, key, launcher=False
                    )  # weight 0: only counts closes
                signature = None
                decisions = {}
                if valid_owner and left:
                    signature = self.survivor_signature(owner, left)
                    decisions = self.attribute(
                        owner, left, root=rid[0], signature=signature
                    )
                    if not terminal:
                        self.store.observe_signature_close(signature)
                elif left and not terminal:
                    self.queue_provenance_review(
                        self._provenance_scope(rid),
                        left,
                        reason="closed process has no validated application owner",
                    )
                if left and not lin.ghosts.get(rid, {}).get("terminal"):
                    dec = self.authorize(authorization.GUI_CLOSE)
                    if dec.verdict == authorization.ACT:
                        self.guarded(
                            lambda: self.gui_close(
                                rid,
                                owner if valid_owner else "",
                                left,
                                authority=dec.authority or "mode",
                                signature=signature,
                                decisions=decisions,
                            )
                        )
                    elif dec.verdict == authorization.WOULD_ACT:
                        self.guarded(
                            lambda: self.would_contain_gui_close(
                                rid, owner if valid_owner else "", left
                            )
                        )

    @staticmethod
    def _provenance_scope(root):
        return "%s/provenance-%d-%d" % (engine.LEFTOVER, root[0], root[1])

    def survivor_signature(self, owner, members):
        """Build a stable signature from resolved members and live runtime/tty context."""
        runtime_classes = set()
        tty = False
        for member in members:
            entry = self.lineage.entries.get((member.get("pid"), member.get("start")))
            if entry is None:
                continue
            runtime = getattr(entry.get("identity"), "runtime", None)
            if runtime:
                runtime_classes.add(runtime)
            tty = tty or bool(entry.get("tty"))
        return survivor_signature.signature(
            owner,
            members,
            survivor_signature.runtime_dir_hash(),
            "+".join(sorted(runtime_classes)),
            tty,
        )

    def _review_memory(self, scope):
        if not memory.enabled(self.cfg):
            return None
        path = cgroup.resolve(scope)
        return cgroup.memory_current(path) if path else None

    @staticmethod
    def _review_provenance(owner, members):
        ancestors = []
        for member in members:
            for key in member.get("chain", []):
                if key and key != owner and key not in ancestors:
                    ancestors.append(key)
        return "last seen under %s" % (", ".join(ancestors[:3]) or owner)

    def queue_provenance_review(self, scope, left, reason):
        """Record uncertain ownership for inspection; no candidate receives an answer."""
        members = [
            {"pid": item["pid"], "start": item.get("start"), "key": item["key"]}
            for item in left
        ]
        review = self.store.add_provenance_review(
            members, scope, self.candidates("", left), reason=reason
        )
        if review:
            self.store.log(
                event="provenance_review_created",
                id=review["id"],
                scope=scope,
                survivors=review["survivors"],
                candidates=[item["key"] for item in review["candidates"]],
                reason=reason,
            )
        return review

    # ---- auto mode: silent GUI closes, survivors of closed jobs, regret ----
    def check_regret(self, lin, now):
        """Attribute respawn and regret to the recorded owner/member relationship."""
        for eid in lin.born:
            e = lin.entries.get(eid)
            if not e:
                continue
            owner, leftover = e.get("root_key"), e.get("key")
            if not isinstance(owner, str) or not isinstance(leftover, str):
                continue
            for stopped_owner, stopped_key, pending in self.store.pending_auto_stops():
                if stopped_owner != owner or stopped_key != leftover:
                    continue
                timestamp = pending.get("ts")
                if not isinstance(timestamp, (int, float)) or isinstance(
                    timestamp, bool
                ):
                    continue
                age = now - timestamp
                if age < 0 or age > self.store.regret_window:
                    continue
                signature_id = pending.get("signature_id")
                if signature_id:
                    root = e.get("root")
                    members = [
                        {
                            "pid": member["pid"],
                            "start": member.get("start"),
                            "key": member["key"],
                        }
                        for member in lin.entries.values()
                        if member.get("root") == root
                        and member.get("root_key") == owner
                        and member.get("key") != owner
                    ]
                    observed = self.survivor_signature(owner, members)
                    matched = self.store.match_signature(observed)
                    if not matched or matched.get("id") != signature_id:
                        continue
                if age <= self.store.respawn_window:
                    self.store.auto_stop_respawn(owner, leftover, signature_id)
                if self.store.regret(
                    owner,
                    leftover,
                    signature_id,
                    window=self.store.regret_window,
                    suspend=self.store.regret_suspend,
                ):
                    self.store.log(
                        event="regret",
                        owner=owner,
                        leftover=leftover,
                        signature=signature_id,
                    )

    def note_auto_stop(
        self,
        scope,
        why,
        pairs,
        apps=(),
        decision=None,
        owner=None,
        signature_id=None,
        restore=None,
    ):
        """Remember an auto stop: knowledge, undo history, status ring, and decisions.log."""
        now = time.time()
        stop_id = (decision or {}).get("id")
        seen_signatures = set()
        for o, k in pairs:
            pair = self.store.data.get("pairs", {}).get(self.store.pkey(o, k), {})
            pair_signature = signature_id or pair.get("sig")
            count_signature = bool(
                pair_signature and pair_signature not in seen_signatures
            )
            if pair_signature:
                seen_signatures.add(pair_signature)
            self.store.auto_stopped(
                o,
                k,
                signature_id=pair_signature,
                stop_id=stop_id,
                count_signature_probation=count_signature,
            )
        for key in apps:
            self.stopped[key] = now
        self.store.record_auto_action(
            scope,
            why,
            pairs,
            apps,
            decision=decision,
            owner=owner,
            authority=(decision or {}).get("authority", "mode"),
            signature_id=signature_id,
            restore=restore,
        )
        self._save_if_idle()
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
        adopted = not bool(ops)
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
                    adopted = True
        except engine.Refused as e:
            self.store.log(event="standalone_adopt_refused", error=str(e))
        return adopted

    def _live_standalone_members(self, members, scope=None):
        path = cgroup.resolve(scope) if scope else None
        result = []
        for member in members:
            if not isinstance(member, dict):
                continue
            pid, start, key = member.get("pid"), member.get("start"), member.get("key")
            if (
                not isinstance(pid, int)
                or isinstance(pid, bool)
                or not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(key, str)
                or inspect.starttime(pid) != start
            ):
                continue
            if scope:
                current = cgroup.proc_cgroup(pid)
                if not path or not current or not cgroup.is_prefix(path, current):
                    continue
            result.append({"pid": pid, "start": start, "key": key})
        return result

    def _adopt_answered_standalones(self):
        changed = False
        for review in self.store.data.get("reviews", []):
            if (
                not isinstance(review, dict)
                or review.get("state") != "answered"
                or review.get("answer") != "standalone"
                or review.get("adopted")
            ):
                continue
            members = self._live_standalone_members(
                review.get("members", []), scope=review.get("scope")
            )
            if self.adopt_standalone(members, review.get("owner")):
                review["adopted"] = True
                self.store.dirty = True
                changed = True
        return changed

    def _stop_gui_survivors(self, owner, items, decisions, scope, signature=None):
        """Stop only pair-authorized GUI survivors; contain every survivor left behind."""
        if self.mode != "adopt" or not owner:
            return set()
        effective = self.effective_authority["value"]
        good = []
        for item in items:
            decision = decisions.get(item["key"]) or self.store.pair_decision(
                owner, item["key"]
            )
            if not decision or decision[0] != "stop":
                continue
            explicit = self.store.explicit_stop(decision)
            veto = self.store.match_veto(
                scope=scope,
                members=[
                    {
                        "pid": item["pid"],
                        "start": item.get("start"),
                        "apps": [item["key"]],
                        "owner": owner,
                        "owners": [owner],
                        "leftover": item["key"],
                        "path": inspect.exe(item["pid"]) or "",
                        "cgroup": cgroup.proc_cgroup(item["pid"]) or "",
                    }
                ],
                owner=owner,
                leftover=item["key"],
                signature=(signature or {}).get("id")
                if isinstance(signature, dict)
                else signature,
            )
            facts = authorization.Facts(
                scope=scope,
                leftover=True,
                pair_action="stop",
                pair_reason=decision[2],
                pair_explicit=explicit,
                vetoed=self.store.describe_veto(veto) if veto else "",
                veto_source=veto.get("source", "user") if veto else "",
                veto_target=self.store.describe_veto(veto) if veto else "",
            )
            gate = self.authorize(authorization.JOB_SURVIVORS, facts)
            if gate.verdict != authorization.ACT:
                continue
            info = self._infos([item["pid"]], origin=owner)[0]
            ok, why = engine.auto_stop_ok(
                self.store,
                owner,
                item["key"],
                info,
                decision=decision,
                authority=effective,
                scope=scope,
                signature=(signature or {}).get("id")
                if isinstance(signature, dict)
                else signature,
            )
            if ok:
                good.append((item, decision))
            else:
                with self.store.decision_context(
                    "refusal",
                    scope=scope,
                    owner=owner,
                    authority="pair",
                    mode=self.mode,
                    why=why,
                ):
                    self.store.log(
                        event="auto_stop_refused",
                        scope=scope,
                        pid=item["pid"],
                        key=item["key"],
                        why=why,
                    )
        if not good:
            return set()

        good_items = [item for item, _decision in good]
        restore = engine.restore_snapshot(
            [item["pid"] for item in good_items], self.cfg
        )
        explicit = all(self.store.explicit_stop(decision) for _, decision in good)
        matched_signature = self.store.match_signature(
            signature or self.survivor_signature(owner, good_items)
        )
        signature_id = (matched_signature or {}).get("id")
        probationary = any(
            self.store.stop_in_probation(owner, item["key"]) for item in good_items
        ) or self.store.signature_in_probation(signature_id)
        allow_sigkill = explicit and not probationary
        why = "closed app %s: %s" % (owner, good[0][1][2])
        with self.store.decision_context(
            "stop",
            scope=scope,
            owner=owner,
            authority="pair",
            mode=self.mode,
            why=why,
        ) as audit_decision:
            sent = engine.signal_survivors(
                self.cfg,
                good_items,
                engine.auto_grace(self.store, {item["key"] for item in good_items}),
                allow_sigkill,
            )
            sent_items = [item for item in good_items if item["pid"] in sent]
            if sent_items:
                sent_pairs = list(
                    dict.fromkeys((owner, item["key"]) for item in sent_items)
                )
                self.store.log(
                    event="stop",
                    scope=scope,
                    owner=owner,
                    pids=[item["pid"] for item in sent_items],
                    why=why,
                )
                self.note_auto_stop(
                    scope,
                    why,
                    sent_pairs,
                    apps=[item["key"] for item in sent_items],
                    decision=audit_decision,
                    owner=owner,
                    signature_id=signature_id,
                    restore=(
                        {"argv": restore["argv"], "cwd": restore["cwd"]}
                        if restore and restore["pid"] in sent
                        else None
                    ),
                )
        return {item["pid"] for item in sent_items}

    def gui_close(
        self, rid, owner, left, authority="mode", signature=None, decisions=None
    ):
        """A GUI root vanished (not a terminal job): standalone leftovers get their own scope, the rest
        go to leftover/<owner>-<id> with a pending review that holds the scope until answered or expiry."""
        decisions = decisions or {}
        standalone = [l for l in left if self.store.standalone(l["key"])]
        rest = [l for l in left if not self.store.standalone(l["key"])]
        if standalone:
            self.adopt_standalone(standalone, owner)
        if rest:
            valid_owner = bool(owner) and not policy.bad_owner(owner, self.deny)
            name = (
                "%s/%s" % (engine.LEFTOVER, engine.leaf_slug(owner, rid[0]))
                if valid_owner
                else self._provenance_scope(rid)
            )
            stopped = self._stop_gui_survivors(
                owner if valid_owner else "", rest, decisions, name, signature
            )
            rest = [item for item in rest if item["pid"] not in stopped]
        if rest:
            valid_owner = bool(owner) and not policy.bad_owner(owner, self.deny)
            name = (
                "%s/%s" % (engine.LEFTOVER, engine.leaf_slug(owner, rid[0]))
                if valid_owner
                else self._provenance_scope(rid)
            )
            try:
                ops = engine.run_ops(
                    self.cfg,
                    self.store,
                    [
                        {
                            "op": "move",
                            "scope": name,
                            "owner": owner if valid_owner else None,
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
                    review = (
                        self.store.add_review(
                            owner,
                            contained,
                            name,
                            signature=signature,
                            memory=self._review_memory(name),
                            provenance=self._review_provenance(owner, contained),
                        )
                        if valid_owner
                        else self.store.add_provenance_review(
                            contained,
                            name,
                            self.candidates("", left),
                            reason="closed process has no validated application owner",
                        )
                    )
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

    def _pair_scope_facts(self, path):
        """Resolve all member decisions for a pair-authorized scope stop."""
        infos = self._infos(cgroup.tree_procs(path))
        decisions = [
            self.store.pair_decision(info.get("origin"), info["key"])
            if info.get("origin")
            else ("ask", 0.0, "pair authority: owner is unknown")
            for info in infos
        ]
        if not decisions:
            action, reason, explicit = (
                "ask",
                "pair authority: scope has no members",
                False,
            )
        elif all(item[0] == "stop" for item in decisions):
            action = "stop"
            reason = "; ".join(item[2] for item in decisions[:3])
            explicit = all(self.store.explicit_stop(item) for item in decisions)
        else:
            denied = next(item for item in decisions if item[0] != "stop")
            action, reason, explicit = denied[0], denied[2], False
        scope = cgroup.rel(path)
        return authorization.Facts(
            scope=scope,
            leftover=scope.startswith(engine.LEFTOVER + "/"),
            pair_action=action,
            pair_reason=reason,
            pair_explicit=explicit,
        )

    def auto_stop_path(
        self,
        path,
        why,
        require_pair,
        authority=None,
        trigger=authorization.GC_STOP,
    ):
        """Stop one scope on auto authority. require_pair: every member must pass auto_stop_ok (a pair
        decided stop); otherwise only the idle checks (known CPU, no edges, no pty host, not protected) apply.
        SIGKILL only when every pair was answered explicitly. Returns True when the scope was removed."""
        leaf = cgroup.rel(path)
        infos = self._infos(cgroup.tree_procs(path))
        if not infos:
            return False
        pairs = [(i["origin"], i["key"]) for i in infos if i["origin"]]
        stop_owner = (
            pairs[0][0]
            if pairs and all(pair[0] == pairs[0][0] for pair in pairs)
            else None
        )
        signature_id = (
            self.survivor_signature(stop_owner, infos)["id"] if stop_owner else None
        )
        unit = engine.unit_for_leaf(self.units, os.path.basename(path))
        unit_name = (unit or {}).get("unit", {}).get("name")
        vetoes = engine.vetoes_for_scope(
            self.store,
            path,
            unit=unit,
            owner=stop_owner,
            signature=signature_id,
        )
        if vetoes:
            veto = vetoes[0]
            with self.store.decision_context(
                "refusal",
                scope=leaf,
                owner=stop_owner,
                authority="veto",
                mode=self.mode,
                why="veto blocked automatic stop",
            ):
                self.store.log(
                    event="vetoed",
                    trigger=trigger,
                    scope=leaf,
                    target=self.store._target(veto),
                    source=veto.get("source", "user"),
                )
            return False
        for i in infos:
            if require_pair:
                ok, w = engine.auto_stop_ok(
                    self.store,
                    i["origin"],
                    i["key"],
                    i,
                    authority=authority or self.effective_authority["value"],
                    scope=leaf,
                    signature=signature_id,
                    unit=unit_name,
                )
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
        explicit = (
            require_pair
            and bool(pairs)
            and all(self.store.pair_explicit(o, k) for o, k in pairs)
        )
        probationary = require_pair and any(
            self.store.stop_in_probation(o, k) for o, k in pairs
        )
        grace = engine.auto_grace(self.store, {i["key"] for i in infos})
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
                    allow_sigkill=explicit and not probationary,
                    decision_authority=decision["authority"],
                    decision_why=why,
                    decision_owner=decision["owner"],
                    signature=signature_id,
                )
            except engine.Refused as e:
                self.store.log(event="auto_stop_refused", scope=leaf, why=str(e))
                return False
            stopped_pids = self.note_stop(rep)
            stopped_apps = self.stopped_apps(rep, stopped_pids)
            stopped_pairs = [
                pair for pair in dict.fromkeys(pairs) if pair[1] in stopped_apps
            ]
            if stopped_apps:
                self.note_auto_stop(
                    leaf,
                    why,
                    stopped_pairs,
                    apps=stopped_apps,
                    decision=decision,
                    owner=decision["owner"],
                    restore=rep.get("restore"),
                )
            return rep["removed"]

    def auto_stop_survivors(
        self, tag, owner, left, dec, signature_id=None, authority=None
    ):
        """Survivors whose pair or matched signature says stop: those passing auto_stop_ok
        are carved into <host scope>/job-<id> (when the host scope is under user/<uid>, no sudo) and
        stopped there, else signalled in place. Everyone else is left alone."""
        want = [l for l in left if dec.get(l["key"], ("",))[0] == "stop"]
        if not want:
            return
        allowed = []
        for l in want:
            veto = self.store.match_veto(
                members=[
                    {
                        "pid": l["pid"],
                        "start": l.get("start"),
                        "apps": [l["key"]],
                        "owner": owner,
                        "owners": [owner],
                        "leftover": l["key"],
                        "path": inspect.exe(l["pid"]) or "",
                        "cgroup": cgroup.proc_cgroup(l["pid"]) or "",
                    }
                ],
                scope=l.get("scope") or cgroup.rel(cgroup.proc_cgroup(l["pid"]) or ""),
                owner=owner,
                leftover=l["key"],
                signature=signature_id,
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
                        source=veto.get("source", "user"),
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
            ok, w = engine.auto_stop_ok(
                self.store,
                owner,
                l["key"],
                infos[l["pid"]],
                decision=dec.get(l["key"]),
                authority=authority or self.effective_authority["value"],
                scope=l.get("scope"),
                signature=signature_id,
            )
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
        restore = engine.restore_snapshot([item["pid"] for item in good], self.cfg)
        pairs = list(dict.fromkeys((owner, l["key"]) for l in good))
        explicit = bool(pairs) and all(
            self.store.explicit_stop(dec.get(k)) or self.store.pair_explicit(o, k)
            for o, k in pairs
        )
        probationary = any(
            self.store.stop_in_probation(o, k) for o, k in pairs
        ) or self.store.signature_in_probation(signature_id)
        allow_sigkill = explicit and not probationary
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
        why = "closed job %s: %s" % (tag, dec[pairs[0][1]][2])
        stopped = set()
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
                    report = engine.stop(
                        dest,
                        self.cfg,
                        self.store,
                        None,
                        timeout=grace,
                        allow_sigkill=allow_sigkill,
                        decision_kind="stop",
                        decision_authority="pair",
                        decision_why=why,
                        decision_owner=owner,
                    )
                    stopped.update(self.note_stop(report))
                except engine.Refused as e:
                    self.store.log(
                        event="auto_stop_refused", scope=cgroup.rel(dest), why=str(e)
                    )
            if loose:
                stopped.update(
                    engine.signal_survivors(self.cfg, loose, grace, allow_sigkill)
                )
            stopped_items = [item for item in good if item["pid"] in stopped]
            if stopped_items:
                self.store.log(
                    event="stop",
                    scope="job-" + slug,
                    pids=sorted({item["pid"] for item in stopped_items}),
                )
                stopped_pairs = list(
                    dict.fromkeys((owner, item["key"]) for item in stopped_items)
                )
                stopped_apps = sorted({item["key"] for item in stopped_items})
                self.note_auto_stop(
                    "job-" + slug,
                    why,
                    stopped_pairs,
                    apps=stopped_apps,
                    decision=decision,
                    owner=owner,
                    signature_id=signature_id,
                    restore=(
                        {"argv": restore["argv"], "cwd": restore["cwd"]}
                        if restore and restore["pid"] in stopped
                        else None
                    ),
                )

    def attribute(self, owner, leftovers, root=None, job=None, signature=None):
        """Log would_attribute / would_stop for each distinct leftover key. Returns {key: decision}."""
        out = {}
        inherited = self.store.signature_decisions(signature) if signature else {}
        for key in dict.fromkeys(l["key"] for l in leftovers):
            pids = [l["pid"] for l in leftovers if l["key"] == key]
            out[key] = inherited.get(key) or self.store.pair_decision(owner, key)
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
            if not owner and not launcher:
                scope = "%s/job-%s" % (
                    engine.LEFTOVER,
                    tag.replace("/", "-")[:96],
                )
                self.queue_provenance_review(
                    scope,
                    left,
                    reason="terminal job has no validated application owner",
                )
            self.store.log(
                event="launcher_learned",
                job=tag,
                owner=owner,
                leftovers=keys[:8],
                why="no application ancestor" if not owner else "launcher",
            )
            return
        signature = self.survivor_signature(owner, left)
        dec = self.attribute(owner, left, job=tag, signature=signature)
        self.store.observe_signature_close(signature)
        members = [
            {"pid": l["pid"], "start": l.get("start"), "apps": [l["key"]]} for l in left
        ]
        for member in members:
            member["owner"] = owner
            member["owners"] = [owner]
            member["leftover"] = member["apps"][0]
        veto = self.store.match_veto(
            members=members, owner=owner, signature=signature["id"]
        )
        if veto and any(action == "stop" for action, _confidence, _why in dec.values()):
            self.store.signature_outcome(signature["id"], "veto")
        stop_keys = [key for key, decision in dec.items() if decision[0] == "stop"]
        facts = authorization.Facts(
            vetoed=self.store.describe_veto(veto) if veto else "",
            veto_source=veto.get("source", "user") if veto else "",
            veto_target=self.store.describe_veto(veto) if veto else "",
            pair_action="stop" if stop_keys else "",
            pair_reason=dec[stop_keys[0]][2] if stop_keys else "",
            pair_explicit=any(
                self.store.explicit_stop(dec[key])
                or self.store.pair_explicit(owner, key)
                for key in stop_keys
            ),
        )
        if (
            self.authorize(authorization.JOB_SURVIVORS, facts).verdict
            == authorization.ACT
        ):
            self.guarded(
                lambda: self.auto_stop_survivors(
                    tag,
                    owner,
                    left,
                    dec,
                    signature_id=signature["id"],
                    authority=self.effective_authority["value"],
                )
            )
        ask = [
            k
            for k in keys
            if dec[k][0] == "ask"
            and self.store.can_ask((owner, k), signature=signature)
        ]
        if ask:
            self.make_question(j, tag, owner, left, ask, signature=signature)

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
            for k, cid in zip(l.get("chain", []), l.get("chain_ids", [])):
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
                    "pid": r["pid"],
                    "start": r.get("start"),
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

    def make_question(self, j, tag, owner, left, ask_keys, kind="job", signature=None):
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
            "signature": signature,
            "ask_keys": list(ask_keys),
            "members": [
                {"key": item["key"], "pid": item["pid"], "start": item.get("start")}
                for item in left
                if item.get("key") in ask_keys
            ],
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
            ok = [
                p for p in pairs if self.store.can_ask(p, signature=q.get("signature"))
            ]
            if not ok:
                self.drop_question(q["id"])
                return {"question": None, "reason": "rate_limited"}
            allowed = {leftover for _owner, leftover in ok}
            q["ask_keys"] = [key for key in q["ask_keys"] if key in allowed]
            q["leftovers"] = [
                item for item in q["leftovers"] if item.get("key") in allowed
            ]
            q["members"] = [item for item in q["members"] if item.get("key") in allowed]
            q["shown"] = True
            self.store.mark_asked(ok, signature=q.get("signature"))
        return {
            "question": {
                "id": q["id"],
                "kind": q["kind"],
                "nonce": q["nonce"],
                "shell_pid": shell,
                "job": q["word"],
                "candidates": q["candidates"],
                "leftovers": q["leftovers"],
                "signature": (q.get("signature") or {}).get("id"),
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
        if policy.bad_owner(owner, self.deny):
            with self.store.decision_context(
                "refusal",
                owner=owner,
                authority="user",
                mode=self.mode,
                why="answer owner is not a validated application identity",
            ):
                self.store.log(
                    event="answer_refused", reason="owner identity is unvalidated"
                )
            return {"error": "owner identity is unvalidated"}
        if not self.store.apply_answer(
            owner,
            q["ask_keys"],
            choice,
            signature=q.get("signature"),
            source="prompt",
            apply_pairs=not (q.get("signature") and choice in ("stop", "keep")),
        ):
            return {"error": "answer could not be applied"}
        if choice == "standalone":
            members = self._live_standalone_members(q.get("members", []))
            self.adopt_standalone(members, owner)
        self.drop_question(q["id"])
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
        rel, f = self.leaf_watch.pop(fd)
        self.leaf_frozen.pop(rel, None)
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

    def collect_leaf_events(self):
        """Turn ready cgroup.events watches into typed queue entries."""
        if self.leaf_ep is None:
            return
        for fd, _ev in self.leaf_ep.poll(0):
            watch = self.leaf_watch.get(fd)
            if watch is None:
                continue
            self.queue_collector_event(LeafChanged(fd, watch[0]))

    @staticmethod
    def _leaf_event_values(text):
        return {
            fields[0]: fields[1]
            for line in text.splitlines()
            if len(fields := line.split()) == 2
        }

    def _read_leaf_event_values(self, fd, leaf):
        watch = self.leaf_watch.get(fd)
        if watch is None or watch[0] != leaf:
            return None
        f = watch[1]
        try:
            f.seek(0)
            text = f.read()
        except OSError:
            text = ""
        return self._leaf_event_values(text) if text else {}

    def _on_leaf_changed(self, event):
        values = self._current_leaf_event_values(event.fd, event.leaf)
        if values is None:
            return
        if values.get("populated") == "0":
            self.queue_collector_event(LeafEmpty(event.fd, event.leaf))
        if values.get("frozen") in ("0", "1"):
            self.queue_collector_event(LeafFrozen(event.fd, event.leaf))

    def _current_leaf_event_values(self, fd, leaf):
        """Return current watch state, dropping a watch whose cgroup.events file vanished."""
        values = self._read_leaf_event_values(fd, leaf)
        if values is None:
            return None
        if not values:
            self._drop_leaf_watch(fd)
            return None
        return values

    def _remove_if_currently_empty(self, fd, leaf, values):
        if values.get("populated") != "0":
            return False
        self._drop_leaf_watch(fd)
        self.remove_leaf(cgroup.base() + "/" + leaf, "populated 0")
        return True

    def _on_leaf_empty(self, event):
        values = self._current_leaf_event_values(event.fd, event.leaf)
        if values is None:
            return
        self._remove_if_currently_empty(event.fd, event.leaf, values)

    def _on_leaf_frozen(self, event):
        values = self._current_leaf_event_values(event.fd, event.leaf)
        if values is None:
            return
        if self._remove_if_currently_empty(event.fd, event.leaf, values):
            return
        if values.get("frozen") in ("0", "1"):
            self.leaf_frozen[event.leaf] = values["frozen"] == "1"

    def _reconcile_leaf_frozen(self):
        """Refresh watched frozen state from cgroup.events during each GC interval."""
        for fd, (leaf, _f) in tuple(self.leaf_watch.items()):
            values = self._current_leaf_event_values(fd, leaf)
            if values is None:
                continue
            if values.get("frozen") in ("0", "1"):
                self.leaf_frozen[leaf] = values["frozen"] == "1"

    def on_leaf_events(self):
        """Collect and drain cgroup.events changes for direct callers and tests."""
        self.collect_leaf_events()
        self.drain_collector_events()

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
                review = self.store.add_review(
                    owner,
                    members,
                    leaf,
                    memory=self._review_memory(leaf),
                    provenance=self._review_provenance(owner, members),
                )
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

    def _gc_signature(self, path, pids):
        """Build the same survivor signature used by the automatic-stop path."""
        infos = self._infos(pids)
        owners = {info["origin"] for info in infos if info.get("origin")}
        if len(owners) != 1 or not infos:
            return None
        return self.survivor_signature(next(iter(owners)), infos)["id"]

    def gc_pass(self, dry_run=False):
        self.store.prune_vetoes(trigger="gc")
        self.store.expire_reviews()
        self._save_if_idle()
        applied_feedback = self.store.apply_feedback()
        adopted = self._adopt_answered_standalones()
        if applied_feedback or adopted:
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
            authority=self.effective_authority["value"],
            signature_for_scope=self._gc_signature,
        )
        res, now_empty = [], set()
        remove_empty = (
            self.authorize(authorization.GC_REMOVE_EMPTY).verdict == authorization.ACT
        )
        if not dry_run and remove_empty:
            self.sync_leaf_watches()
        # EPOLLPRI is edge-triggered from the last read. A missed readiness event can
        # otherwise leave this cache stale until another transition, so reconcile it
        # once per scheduled GC pass (normally every 60 seconds).
        self._reconcile_leaf_frozen()
        for path, why in cands:
            leaf = cgroup.rel(path)
            if why == "empty":
                self._gc_empty(path, leaf, dry_run, res, now_empty)
                continue
            facts = (
                self._pair_scope_facts(path)
                if leaf.startswith(engine.LEFTOVER + "/")
                and self.mode in ("adopt", "auto")
                else authorization.Facts(
                    scope=leaf, leftover=leaf.startswith(engine.LEFTOVER + "/")
                )
            )
            if why.startswith("leftover expired after"):
                facts = replace(facts, pair_action="expiry", pair_reason=why)
            dec = self.authorize(authorization.GC_STOP, facts)
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
                    or (
                        leaf.startswith(engine.LEFTOVER + "/")
                        and why.startswith("idle")
                    )
                ):
                    res[-1][2] = "review"
                    self._queue_gc_review(path, leaf, why)
                continue
            if (
                dec.verdict != authorization.ACT
            ):  # keep: a future veto/hold blocks silently here
                if (
                    self.mode in ("adopt", "auto")
                    and leaf.startswith(engine.LEFTOVER + "/")
                    and why.startswith("idle")
                ):
                    res[-1][2] = "review"
                    self._queue_gc_review(path, leaf, why)
                continue
            if (
                self.mode == "auto"
                and leaf.startswith(engine.LEFTOVER + "/")
                and why.startswith("idle")
            ):
                res[-1][2] = "review"
                self._queue_gc_review(path, leaf, why)
                continue
            if dec.authority == authorization.AUTHORITY_PAIR and why.startswith(
                "pair stop"
            ):
                self.guarded(
                    lambda: self.auto_stop_path(
                        path,
                        why,
                        True,
                        authority=self.effective_authority["value"],
                    )
                )
                continue
            if self.mode == "auto":
                require_pair = (
                    dec.authority == authorization.AUTHORITY_PAIR
                    and why.startswith("pair stop")
                )
                self.guarded(
                    lambda: self.auto_stop_path(
                        path,
                        why,
                        require_pair,
                        authority=self.effective_authority["value"],
                    )
                )
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
                stopped_pids = self.note_stop(rep)
                stopped = self.stopped_apps(rep, stopped_pids)
                if stopped:
                    self.note_auto_stop(
                        leaf,
                        why,
                        [],
                        apps=stopped,
                        decision=decision,
                        restore=rep.get("restore"),
                    )
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
            scope = cgroup.rel(d)
            pair_facts = (
                self._pair_scope_facts(d)
                if self.mode == "auto"
                or (self.mode == "adopt" and scope.startswith(engine.LEFTOVER + "/"))
                else authorization.Facts()
            )
            dec = self.authorize(
                authorization.SESSION_END,
                replace(
                    pair_facts,
                    scope=scope,
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
                if not self.auto_stop_path(
                    d,
                    "session ended",
                    True,
                    authority=self.effective_authority["value"],
                    trigger=authorization.SESSION_END,
                ):
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
                    stopped_pids = self.note_stop(rep)
                    stopped = self.stopped_apps(rep, stopped_pids)
                    if stopped:
                        self.note_auto_stop(
                            scope,
                            "session ended",
                            [],
                            apps=stopped,
                            decision=decision,
                            restore=rep.get("restore"),
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
            self._write_summary_if_dirty()

    def _undo_action_effect(self, decision):
        """Reverse one non-stop action from its bounded, typed decision payload."""
        payload = decision.get("undo")
        if not isinstance(payload, dict):
            return {"ok": False, "error": "undo payload is unavailable"}
        operation = payload.get("operation")
        scope = payload.get("scope") or decision.get("scope")
        if not isinstance(scope, str) or not cgroup.valid_rel(scope):
            return {"ok": False, "error": "undo scope is invalid"}
        if scope == "manager" or scope.startswith("manager/"):
            return {"ok": False, "error": "managed service scope cannot be undone"}
        path = os.path.join(cgroup.base(), scope)

        if operation == "thaw":
            freeze = os.path.join(path, "cgroup.freeze")
            try:
                with open(freeze, encoding="ascii") as source:
                    frozen = source.read().strip() == "1"
                if frozen:
                    with open(freeze, "w", encoding="ascii") as target:
                        target.write("0\n")
                    self.store.log(
                        event="thaw",
                        scope=scope,
                        source="undo",
                        target_decision_id=decision["id"],
                    )
                return {"ok": True, "thawed": frozen, "scope": scope}
            except FileNotFoundError:
                return {"ok": True, "thawed": False, "scope": scope, "gone": True}
            except OSError as error:
                return {"ok": False, "error": "could not thaw %s: %s" % (scope, error)}

        if operation == "restore_priorities":
            resources = payload.get("resources", [])
            oom_values = payload.get("oom_score_adj", [])
            if (
                not isinstance(resources, list)
                or len(resources) > 16
                or not isinstance(oom_values, list)
                or len(oom_values) > 64
                or not resources
                and not oom_values
            ):
                return {"ok": False, "error": "priority undo payload is invalid"}
            allowed_files = {"cpu.idle", "cpu.weight", "io.weight", "io.bfq.weight"}
            for item in resources:
                if not isinstance(item, dict) or item.get("file") not in allowed_files:
                    return {"ok": False, "error": "priority resource is invalid"}
                value = item.get("value")
                if not isinstance(value, str) or not value or len(value) > 128:
                    return {"ok": False, "error": "priority value is invalid"}
                name = item["file"]
                if name == "cpu.idle":
                    valid_value = value.strip() in ("0", "1")
                elif name == "cpu.weight":
                    valid_value = (
                        value.strip().isdecimal() and 1 <= int(value.strip()) <= 10000
                    )
                else:
                    lines = value.strip().splitlines()
                    valid_value = bool(lines) and len(lines) <= 16
                    for line in lines:
                        fields = line.split()
                        if len(fields) != 2 or not fields[1].isdecimal():
                            valid_value = False
                            break
                        weight = int(fields[1])
                        device = fields[0]
                        if not 1 <= weight <= 10000:
                            valid_value = False
                            break
                        if device != "default":
                            major, separator, minor = device.partition(":")
                            if (
                                not separator
                                or not major.isdecimal()
                                or not minor.isdecimal()
                                or len(major) > 10
                                or len(minor) > 10
                            ):
                                valid_value = False
                                break
                if not valid_value:
                    return {"ok": False, "error": "priority value is invalid"}
            safe_oom_values = []
            for item in oom_values:
                if not isinstance(item, dict):
                    return {"ok": False, "error": "oom priority value is invalid"}
                pid, start, value = (
                    item.get("pid"),
                    item.get("start"),
                    item.get("value"),
                )
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
                    or inspect.starttime(pid) != start
                ):
                    return {"ok": False, "error": "oom priority target is stale"}
                safe_oom_values.append((pid, start, value))
            try:
                for item in resources:
                    with open(
                        os.path.join(path, item["file"]), "w", encoding="ascii"
                    ) as target:
                        target.write(item["value"].rstrip() + "\n")
                for pid, start, value in safe_oom_values:
                    engine.helper_oom_restore(self.cfg, pid, start, value)
            except (OSError, engine.Refused) as error:
                return {
                    "ok": False,
                    "error": "could not restore priorities: %s" % error,
                }
            self.store.log(event="priority_restored", scope=scope)
            return {"ok": True, "scope": scope, "resources": len(resources)}

        if operation == "adopt_standalone":
            members = payload.get("members")
            if not isinstance(members, list) or len(members) > 64:
                return {"ok": False, "error": "standalone undo payload is invalid"}
            safe = [
                member
                for member in members
                if isinstance(member, dict)
                and isinstance(member.get("pid"), int)
                and not isinstance(member.get("pid"), bool)
                and isinstance(member.get("start"), int)
                and not isinstance(member.get("start"), bool)
                and isinstance(member.get("key"), str)
                and member.get("key")
            ]
            live = self._live_standalone_members(safe, scope=scope)
            if live and not self.adopt_standalone(live):
                return {"ok": False, "error": "could not adopt standalone members"}
            return {"ok": True, "scope": scope, "adopted": len(live)}

        return {"ok": False, "error": "undo operation is unsupported"}

    def _await_restore_startup(self, fd):
        """Wait for the runner to confirm attachment and successful exec via close-on-exec pipe."""
        data = bytearray()
        deadline = time.monotonic() + RESTORE_START_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, "timed out waiting for restored command startup"
            try:
                server = self.srv
                wait_fds = [fd] + ([server] if server is not None else [])
                ready, _, _ = select.select(wait_fds, [], [], remaining)
                if not ready:
                    return False, "timed out waiting for restored command startup"
                if server is not None and server in ready:
                    # The restore runner registers and attaches through this socket before
                    # exec. Service that RPC while waiting so the single-threaded daemon
                    # does not deadlock against its own child.
                    self.guarded(lambda: self.serve(server))
                if fd not in ready:
                    continue
                chunk = os.read(fd, 4096)
            except OSError as error:
                return False, "could not confirm restored command startup: %s" % error
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 4096:
                return False, "restored command startup response was too large"
        if data == b"R":
            return True, None
        if data.startswith(b"E"):
            detail = data[1:].decode("utf-8", errors="replace").strip()
            return False, detail or "restored command failed during startup"
        if data.startswith(b"R"):
            detail = data[1:].decode("utf-8", errors="replace").strip()
            return False, detail or "restored command failed after attaching"
        return False, "launcher exited before confirming attachment and exec"

    @staticmethod
    def _stop_restore_launcher(child):
        """Stop a launcher that failed to reach the exec acknowledgment."""
        poll = getattr(child, "poll", None)
        if not callable(poll) or poll() is not None:
            return
        try:
            child.terminate()
            try:
                child.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1.0)
        except (OSError, subprocess.SubprocessError):
            pass

    def _launch_restored(self, decision_id):
        """Relaunch one opted-in root through `taema run` with a fresh scope and safe env."""
        decision = self.store.decision(decision_id)
        if not decision or decision.get("kind") not in ("stop", "auto_stop"):
            return {"error": "restore requires a retained stop decision"}
        payload = decision.get("undo")
        if not isinstance(payload, dict):
            return {"error": "restore data is unavailable"}
        if payload.get("restored_at") is not None:
            return {"error": "this decision has already been restored"}
        argv, cwd = decision.get("argv"), decision.get("cwd")
        if not argv or not cwd:
            return {
                "restore_unavailable": "[learn].remember_argv was false when the app stopped"
            }
        if (
            not isinstance(argv, list)
            or not 0 < len(argv) <= 256
            or not isinstance(argv[0], str)
            or not argv[0]
            or not all(isinstance(arg, str) and "\0" not in arg for arg in argv)
            or not isinstance(cwd, str)
            or not os.path.isabs(cwd)
            or not os.path.isdir(cwd)
        ):
            return {"error": "saved command or working directory is invalid"}
        if not isinstance(decision_id, int) or isinstance(decision_id, bool):
            return {"error": "restore decision id is invalid"}
        scope = "restore-%d" % decision_id
        package_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        runner_env = inspect.restore_environment(os.environ)
        runner_env["PYTHONPATH"] = package_root
        runner_env["TAEMA_RESTORE_LAUNCH"] = "1"
        runner = [
            sys.executable,
            "-m",
            "taema",
            "run",
            "--bind",
            scope,
            "--",
            *argv,
        ]
        try:
            read_fd, write_fd = os.pipe()
        except OSError as error:
            return {"error": "could not prepare restored command startup: %s" % error}
        runner_env["TAEMA_RESTORE_ACK_FD"] = str(write_fd)
        restored_at = self.store.now()
        if not self.store.mark_decision_restored(decision_id, at=restored_at):
            os.close(read_fd)
            os.close(write_fd)
            return {"error": "this decision has already been restored"}
        self.store.save()
        child = None
        try:
            child = subprocess.Popen(
                runner,
                cwd=cwd,
                env=runner_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                pass_fds=(write_fd,),
            )
        except (OSError, ValueError) as error:
            os.close(read_fd)
            self.store.clear_decision_restored(decision_id, restored_at)
            self.store.log(
                event="restore_failed", decision_id=decision_id, error=str(error)
            )
            self.store.save()
            return {"error": "could not relaunch stopped app: %s" % error}
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass
        try:
            started, startup_error = self._await_restore_startup(read_fd)
        finally:
            os.close(read_fd)
        if not started:
            self._stop_restore_launcher(child)
            self.store.clear_decision_restored(decision_id, restored_at)
            self.store.log(
                event="restore_failed", decision_id=decision_id, error=startup_error
            )
            self.store.save()
            return {"error": "could not relaunch stopped app: %s" % startup_error}
        return {"restored": True, "pid": child.pid, "scope": "scope-" + scope}

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
            effective_authority = self.effective_authority
            return {
                "mode": self.mode,
                "authority": effective_authority["value"],
                "authority_source": effective_authority["source"],
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
                    {key: value for key, value in msg.items() if key != "cmd"},
                    undo_handler=(
                        self._undo_action_effect if msg.get("op") == "undo" else None
                    ),
                )
                if result is None:
                    return {"error": "bad request"}
                if not result.get("duplicate"):
                    self.store.save()
                self._adopt_answered_standalones()
                self.store.save_if_dirty()
                if msg.get("op") == "undo" and not result.get("duplicate"):
                    target = self.store.decision(result.get("target_decision_id"))
                    if target and target.get("kind") in ("stop", "auto_stop"):
                        action = target.get("undo") or {}
                        for app in action.get("apps", []):
                            self.stopped.pop(app, None)
                    if msg.get("restore") is True:
                        result.update(
                            self._launch_restored(result.get("target_decision_id"))
                        )
                if msg.get("op") in ("veto", "undo") and not result.get("duplicate"):
                    self.thaw_held_scopes()
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

    def _summary_text(self):
        state = self.store.hold_status()
        held = []
        if state.get("global"):
            held.append("global")
        scopes = state.get("scopes", [])
        held.extend("scope:" + scope for scope in scopes[:3])
        if len(scopes) > 3:
            held.append("+%d scopes" % (len(scopes) - 3))
        if state.get("snooze_until"):
            held.append("snooze")
        hold = ",".join(held) or "none"
        reason = state.get("reason") or self.profile_reason
        reason = " ".join(str(reason).split())[:96]
        profile = " ".join(str(self.cfg.get("_profile_name", "auto")).split())[:64]
        latest = " ".join(str(self._last_event).split())[:64]
        line = "taema mode=%s profile=%s reason=%s hold=%s reviews=%d event=%s" % (
            self.mode,
            profile,
            json.dumps(reason, ensure_ascii=False),
            hold[:128],
            self.store.review_count,
            latest,
        )
        return line[:1023] + "\n"

    def _write_summary_if_dirty(self):
        if not self._summary_dirty:
            return False
        directory = os.path.dirname(self._summary_path)
        temporary = None
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
            fd, temporary = tempfile.mkstemp(prefix=".summary-", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(self._summary_text())
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self._summary_path)
            os.chmod(self._summary_path, 0o600)
        except OSError:
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            return False
        self._write_review_flag()
        self._summary_dirty = False
        return True

    def _write_review_flag(self):
        path = os.path.join(self.qdir(), "review")
        count = self.store.review_count
        try:
            if count:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="ascii") as output:
                    output.write("%d\n" % count)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(path, 0o600)
            else:
                os.unlink(path)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True

    def _publish_event(self, event):
        self._summary_dirty = True
        self._last_event = str(event.get("event", "unknown"))
        view = event_views.view_event(event)
        topics = set(view["topics"])
        for conn, subscriber in tuple(self.subscribers.items()):
            if subscriber["closing"] or not topics.intersection(subscriber["topics"]):
                continue
            if subscriber["queued_events"] >= MAX_SUBSCRIBER_QUEUE:
                self._close_slow_subscriber(conn, subscriber)
                continue
            subscriber["queue"].append(({"event": view}, True))
            subscriber["queued_events"] += 1
            self._update_subscriber_interest(conn, subscriber)

    def _wire_subscriber_item(self, subscriber, item):
        failure = item.get("_failure")
        if failure:
            error = protocol.ProtocolError(*failure)
            reply = protocol.error_reply(subscriber["id"], error)
        else:
            reply = protocol.reply_v2(subscriber["id"], item)
        return (
            json.dumps(reply, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode()

    def _update_subscriber_interest(self, conn, subscriber):
        if conn.fileno() < 0:
            return
        events = selectors.EVENT_READ
        if subscriber["current"] is not None or subscriber["queue"]:
            events |= selectors.EVENT_WRITE
        try:
            self.sel.modify(conn, events, ("subscriber", conn))
        except (KeyError, OSError, ValueError):
            try:
                self.sel.register(conn, events, ("subscriber", conn))
            except (KeyError, OSError, ValueError):
                self._drop_subscriber(conn)

    def _close_slow_subscriber(self, conn, subscriber):
        subscriber["closing"] = True
        subscriber["close_deadline"] = time.monotonic() + SUBSCRIBER_CLOSE_TTL
        subscriber["queue"].clear()
        subscriber["queued_events"] = 0
        failure = {
            "_failure": (
                "slow_consumer",
                "Subscriber event queue exceeded 4096 events.",
                "Reconnect from the last processed sequence.",
            )
        }
        if subscriber["current"] is None or subscriber["offset"] == 0:
            subscriber["current"] = self._wire_subscriber_item(subscriber, failure)
            subscriber["offset"] = 0
        else:
            subscriber["queue"].append((failure, False))
        self._update_subscriber_interest(conn, subscriber)

    def _drop_subscriber(self, conn):
        self.subscribers.pop(conn, None)
        try:
            self.sel.unregister(conn)
        except (KeyError, OSError, ValueError):
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _read_subscriber(self, conn):
        try:
            conn.recv(4096)
        except BlockingIOError:
            return
        except OSError:
            self._drop_subscriber(conn)
            return
        self._drop_subscriber(conn)

    def _write_subscriber(self, conn):
        subscriber = self.subscribers.get(conn)
        if subscriber is None:
            return
        while True:
            if subscriber["current"] is None:
                if not subscriber["queue"]:
                    break
                item, is_event = subscriber["queue"].popleft()
                if is_event:
                    subscriber["queued_events"] -= 1
                subscriber["current"] = self._wire_subscriber_item(subscriber, item)
                subscriber["offset"] = 0
            try:
                sent = conn.send(subscriber["current"][subscriber["offset"] :])
            except BlockingIOError:
                break
            except OSError:
                self._drop_subscriber(conn)
                return
            if sent <= 0:
                self._drop_subscriber(conn)
                return
            subscriber["offset"] += sent
            if subscriber["offset"] >= len(subscriber["current"]):
                subscriber["current"] = None
                subscriber["offset"] = 0
        if (
            subscriber["closing"]
            and not subscriber["queue"]
            and subscriber["current"] is None
        ):
            self._drop_subscriber(conn)
        else:
            self._update_subscriber_interest(conn, subscriber)

    def _expire_subscribers(self):
        now = time.monotonic()
        for conn, subscriber in tuple(self.subscribers.items()):
            deadline = subscriber.get("close_deadline")
            if deadline is not None and deadline <= now:
                self._drop_subscriber(conn)

    def _start_subscription(self, conn, identifier, command):
        if (
            sum(not item["closing"] for item in self.subscribers.values())
            >= MAX_SUBSCRIBERS
        ):
            return {"error": "subscriber limit reached"}
        topics = set(command["topics"])
        since_seq = command["since_seq"]
        history = self.store.events_since(since_seq, limit=MAX_EVENT_REPLAY)
        stale = since_seq > history["latest_seq"] or (
            since_seq < history["latest_seq"]
            and (history["oldest_seq"] is None or since_seq < history["oldest_seq"] - 1)
        )
        replay = [
            {"event": event_views.view_event(event)}
            for event in history["events"]
            if topics.intersection(event_views.event_topics(event))
        ]
        resync = stale or history["more"] or len(replay) > MAX_EVENT_REPLAY
        subscriber = {
            "id": identifier,
            "topics": topics,
            "queue": collections.deque(),
            "queued_events": 0,
            "current": None,
            "offset": 0,
            "closing": False,
            "close_deadline": None,
        }
        subscriber["queue"].append(
            (
                {"subscribed": True, "topics": sorted(topics), "since_seq": since_seq},
                False,
            )
        )
        if resync:
            subscriber["queue"].append(
                ({"resync": True, "latest_seq": history["latest_seq"]}, False)
            )
        else:
            subscriber["queue"].extend((event, True) for event in replay)
            subscriber["queued_events"] = len(replay)
        conn.setblocking(False)
        self.subscribers[conn] = subscriber
        self._update_subscriber_interest(conn, subscriber)
        return None

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
        keep_open = False
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
                            if command["cmd"] == "subscribe":
                                result = self._start_subscription(
                                    conn, identifier, command
                                )
                                if result is None:
                                    keep_open = True
                                else:
                                    reply = protocol.reply_v2(identifier, result)
                            else:
                                reply = protocol.reply_v2(
                                    identifier, self.handle(command)
                                )
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
        if keep_open:
            return
        if self._summary_dirty and not self._in_tick:
            self._write_summary_if_dirty()
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
        """Thaw frozen managed scopes covered by a hold or any active veto."""
        state = self.store.hold_status()
        global_hold = state["global"] or state["snooze_until"] is not None
        held_scopes = state["scopes"]
        active_vetoes = self.store._active_vetoes()
        if not global_hold and not held_scopes and not active_vetoes:
            return
        stack = list(cgroup.subdirs(cgroup.base()))
        while stack:
            path = stack.pop()
            if os.path.basename(path) == "manager":
                continue
            scope = cgroup.rel(path)
            stack.extend(cgroup.subdirs(path))
            held = global_hold or any(
                scope == held_scope or scope.startswith(held_scope + "/")
                for held_scope in held_scopes
            )
            unit = engine.unit_for_leaf(self.units, os.path.basename(path))
            veto = engine.veto_for_scope(
                self.store,
                path,
                unit=unit,
            )
            if not held and not veto:
                continue
            freeze = os.path.join(path, "cgroup.freeze")
            try:
                with open(freeze, encoding="ascii") as source:
                    frozen = source.read().strip() == "1"
                if not frozen:
                    continue
                reason = (
                    self.store.describe_veto(veto)
                    if veto
                    else self.store.hold_reason(scope) or "runtime hold"
                )
                authority = "veto" if veto else "hold"
                why = (
                    "veto thawed a managed freeze: %s"
                    if veto
                    else "hold thawed a managed freeze: %s"
                ) % reason
                with self.store.decision_context(
                    "thaw",
                    scope=scope,
                    authority=authority,
                    mode=self.mode,
                    why=why,
                ):
                    with open(freeze, "w", encoding="ascii") as target:
                        target.write("0\n")
                    self.store.log(
                        event="thaw",
                        scope=scope,
                        reason=reason,
                        target=self.store._target(veto) if veto else None,
                        source=veto.get("source") if veto else "hold",
                    )
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
                    learn=cfg.get("learn"),
                )
                new_store._event_seq = max(new_store._event_seq, old_store._event_seq)
                new_store.add_event_listener(self._publish_event)
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
        self.store.configure_learning(cfg.get("learn"), self.store.mode)
        self.lineage.cfg = cfg
        self.lineage.units = tuple(units)
        self.lineage.identity_sink = self.store.record_identities
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
        """Seconds until the next timer is due (adopt, gc, memory), capped at MAX_SLEEP."""
        if self.collector_events:
            return 0.0
        now = time.time() if now is None else now
        due_times = [
            self.last["adopt"] + self.iv_adopt,
            self.last["gc"] + self.iv_gc,
            now + MAX_SLEEP,
        ] + [d[0] for d in self.deadlines]
        if self.mem_enabled:
            due_times.append(self.last.get("memory", now) + self.iv_memory)
        monotonic_now = time.monotonic()
        due_times.extend(
            now + max(0, item["close_deadline"] - monotonic_now)
            for item in self.subscribers.values()
            if item.get("close_deadline") is not None
        )
        due = min(due_times)
        return max(0.0, min(MAX_SLEEP, due - now))

    def tick(self):
        """Run what is due, skipping the pass when SQLite's writer slot is busy."""
        self._in_tick = True
        self.store.defer_writes = True
        skip_pass = False
        try:
            self._expire_subscribers()
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
                self.guarded(self.poll_owner_watches)
                if self.queue_collector_event(ProcessReconcile()):
                    self.last["adopt"] = now
            if now - self.last["gc"] >= self.iv_gc:
                if self.queue_collector_event(LeafReconcile()):
                    self.last["gc"] = now
            if (
                self.mem_enabled
                and now - self.last.get("memory", 0.0) >= self.iv_memory
            ):
                if self.queue_collector_event(MemoryReconcile()):
                    self.last["memory"] = now
            self.drain_collector_events()
        finally:
            self._in_tick = False
            self.store.defer_writes = False
            if not skip_pass:
                self.guarded(self.store.save_if_dirty)
                self.guarded(self.store.export_daily_if_due)
            self._write_summary_if_dirty()

    def memory_pass(self, now=None):
        """Sample live cgroups and persist only material changes or the 10-minute heartbeat."""
        if not memory.enabled(self.cfg):
            return 0
        now = time.time() if now is None else float(now)
        snapshot = memory.snapshot(cfg=self.cfg, peak_cache=self.memory_peaks, now=now)
        live = set()
        samples = []
        for scope in snapshot["scopes"]:
            key = scope["name"]
            live.add(key)
            if scope.get("current_bytes") is None:
                continue
            previous = self.memory_last_samples.get(key)
            sample = memory.sample_record(scope, now)
            if memory.sample_due(previous, sample, now):
                samples.append(sample)
                self.memory_last_samples[key] = sample
        for key in tuple(self.memory_last_samples):
            if key not in live:
                self.memory_last_samples.pop(key, None)
                self.memory_peaks.pop(key, None)
        prune_due = now - self.last_memory_prune >= memory.SAMPLE_INTERVAL
        if not samples and not prune_due:
            return 0
        saved = self.store.record_memory_samples(
            [sample.as_db_row() for sample in samples], now=now
        )
        if prune_due:
            self.last_memory_prune = now
        return saved

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
        self._write_summary_if_dirty()
        while not self.stopping:
            for key, mask in self.sel.select(timeout=self.next_timeout()):
                if key.data == "srv":
                    self.guarded(lambda: self.serve(self.srv))
                elif key.data == "wake":
                    try:
                        wake_r.recv(4096)
                    except OSError:
                        pass
                elif key.data == "leaves":
                    self.guarded(self.collect_leaf_events)
                elif isinstance(key.data, tuple) and key.data[0] == "subscriber":
                    conn = key.data[1]
                    if mask & selectors.EVENT_READ:
                        self.guarded(lambda: self._read_subscriber(conn))
                    if mask & selectors.EVENT_WRITE and conn.fileno() >= 0:
                        self.guarded(lambda: self._write_subscriber(conn))
                else:
                    fd = key.fd
                    watch = self.owners.get(fd)
                    if watch is not None:
                        self.queue_collector_event(OwnerExited(fd, watch))
            self.drain_collector_events()
            self.tick()
        for conn in tuple(self.subscribers):
            self._drop_subscriber(conn)
        for qid in list(self.pending):
            self.drop_question(qid)
        self.store.log(event="daemon_stop")
        self.store.save()
        self._write_summary_if_dirty()
        return 0


def run(cfg=None):
    cfg = policy.load_config() if cfg is None else cfg
    return Daemon(cfg).run()
