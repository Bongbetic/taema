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
import re
import secrets
import select
import selectors
import signal
import shlex
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
    oom,
    qos,
    process as inspect,
    lineage,
    signature as survivor_signature,
)
from ..governor import engine, freezing, guard as pressure_guard, memory_budget
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
MAX_RECLAIM_SCOPES = 32
RECLAIM_CPU_PERCENT = 1.0
MAX_QOS_OOM_RECORDS = 4096
MAX_QOS_OOM_UNDO_INPUT = 16384


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


@dataclass(frozen=True, slots=True)
class ReclaimReconcile:
    pass


@dataclass(frozen=True, slots=True)
class PressureHigh:
    trigger: str


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
        self.config_error = None
        self.profile_reason = cfg.get("_profile_reason", "automatic profile selection")
        self.reload_requested = False
        self._config_watch_paths = policy.config_watch_paths(cfg)
        self._config_fingerprint = policy.file_fingerprint(self._config_watch_paths)
        self.sel = selectors.DefaultSelector()
        self.owners = {}  # pidfd -> (scope leaf name, owner pid, owner starttime)
        self.idle_since = {}
        self.gc_usage = {}  # rel -> cpu usage_usec when the idle window started
        self.freeze_usage = {}  # rel -> (usage_usec, sample_time, member pids)
        self.manual_freeze_usage = {}  # rel -> manual request CPU sample
        self.freeze_idle_since = {}
        self.last_listener_check = 0.0
        self.gc_skip = set()  # leaves with a protected member: not retried
        self.gc_noted = set()  # leaves already logged as kept
        self.srv = None
        self.sock_path = None
        self.mem_enabled = memory.enabled(cfg)
        self.last = {
            "adopt": 0.0,
            "gc": 0.0,
            "memory": 0.0,
            "reclaim": 0.0,
            "freeze": 0.0,
        }
        self.iv_adopt = policy.timer(cfg, "adopt_interval", 15)
        self.iv_gc = policy.timer(cfg, "gc_interval", 60)
        self.iv_memory = 60.0
        self.iv_reclaim = max(
            1.0, float(cfg.get("mem", {}).get("reclaim_interval", 60))
        )
        self.memory_peaks = {}
        self.memory_scope_seen = set()
        self.memory_scope_allocations = {}
        self.last_memory_prune = 0.0
        self.reclaim_usage = {}  # scope -> aggregate cpu usage_usec and sample time
        self.reclaim_idle_since = {}
        self.reclaim_state = {}  # scope -> cooldown/refault state
        self.saved_vm_scopes = set()  # VM save success, until the guest resumes
        self.saved_vm_members = {}  # scope -> member pids observed after save
        self.memory_save_attempts = {}  # scope -> last save-state hook attempt
        self.reclaim_cursor = 0
        self.qos_pending = {}  # scope -> (candidate class, first observed time)
        self.qos_usage = {}  # app scope -> (aggregate cpu usage_usec, sample time)
        self.qos_idle_since = {}  # app scopes independently observed idle of GC eligibility
        self.qos_next_background_sample = 0.0
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
        self.pressure_monitor = None
        self.pressure_watch_signature = None
        self.pressure_watch_failures = ()
        self.collector_events = collections.deque()
        self._collector_event_set = set()
        self.collector_event_drops = 0
        self.last_guard_check = 0.0
        self.guard_last_steps = {}
        self.guard_state = {
            "active": False,
            "trigger": None,
            "triggers": [],
            "started_at": None,
            "steps": [],
            "bytes_freed": 0,
            "last_trigger": None,
            "last_bytes_freed": 0,
            "last_duration_ms": None,
        }
        self.guard_trigger_until = 0.0
        self.guard_started_monotonic = 0.0
        self.oom_handlers_cache = None
        self.oom_handlers_checked_at = 0.0
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
        self.thaw_all_managed_scopes("daemon restart recovery")
        self.thaw_held_scopes()

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

    def memory_reclaim_enabled(self):
        config = self.cfg.get("mem", {})
        return (
            self.mem_enabled
            and isinstance(config, dict)
            and config.get("reclaim", True) is True
        )

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
            force_veto = trigger == authorization.MANUAL_RECLAIM and f.force_veto
            veto = (
                engine.veto_for_scope(self.store, path, unit=unit)
                if not f.vetoed and not force_veto
                else None
            )
            unit_veto = (
                "kill.never_stop"
                if trigger not in (authorization.RECLAIM, authorization.MANUAL_RECLAIM)
                and unit
                and unit.get("kill", {}).get("never_stop")
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
                ReclaimReconcile,
                PressureHigh,
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
        elif isinstance(event, ReclaimReconcile):
            self.guarded(self.reclaim_pass)
        elif isinstance(event, PressureHigh):
            self.guarded(lambda: self.guard_pass(event.trigger))

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
                self.store,
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
                    engine.signal_survivors(
                        self.cfg, loose, grace, allow_sigkill, self.store
                    )
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
        if choice in ("keep", "standalone"):
            self._restore_qos_for_keys(q["ask_keys"])
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

    def _qos_state(self):
        scopes = self.store.data.get("qos_scopes")
        if not isinstance(scopes, dict):
            scopes = {}
            self.store.data["qos_scopes"] = scopes
            self.store.dirty = True
        exempt = self.store.data.get("qos_exempt")
        if not isinstance(exempt, dict):
            exempt = {}
            self.store.data["qos_exempt"] = exempt
            self.store.dirty = True
        return scopes, exempt

    def _restore_qos_scope(self, scope, exempt=False, classification=None):
        scopes, exemptions = self._qos_state()
        record = scopes.get(scope)
        if not isinstance(record, dict):
            record = {}
        resources = record.get("originals", [])
        oom_values = record.get("oom_score_adj", [])
        if record.get("applied") and (resources or oom_values):
            result = self._undo_action_effect(
                {
                    "id": "qos-restore",
                    "scope": scope,
                    "undo": {
                        "operation": "restore_priorities",
                        "resources": resources,
                        "oom_score_adj": oom_values,
                    },
                }
            )
            if not isinstance(result, dict) or result.get("ok") is not True:
                self.store.log(
                    event="qos_restore_failed",
                    scope=scope,
                    why=(result or {}).get("error", "priority restore failed"),
                )
                return False
        scopes.pop(scope, None)
        self.qos_pending.pop(scope, None)
        if exempt:
            held_class = classification or record.get("class")
            if isinstance(held_class, str) and held_class:
                if not record and exemptions.get(scope) == held_class:
                    return True
                exemptions[scope] = held_class
        else:
            exemptions.pop(scope, None)
        self.store.dirty = True
        return True

    def _restore_qos_for_keys(self, keys):
        keys = {key for key in keys if isinstance(key, str) and key}
        if not keys:
            return 0
        scopes, _exempt = self._qos_state()
        restored = 0
        for scope in tuple(scopes):
            if not isinstance(scope, str):
                continue
            path = cgroup.resolve(scope)
            if not path:
                continue
            members = {
                policy.app_key(pid, units=self.units) for pid in cgroup.tree_procs(path)
            }
            if keys.intersection(members):
                record = scopes.get(scope)
                resource_class = (
                    record.get("class") if isinstance(record, dict) else None
                )
                if self._restore_qos_scope(
                    scope, exempt=True, classification=resource_class
                ):
                    restored += 1
        return restored

    def _qos_scope_kept(self, path):
        """Honor explicit keep/standalone answers before applying scope priorities."""
        for pid in cgroup.tree_procs(path):
            key = policy.app_key(pid, units=self.units)
            if not key:
                continue
            if (
                self.store.standalone(key)
                or self.store.peek(key).get("user_keep", 0.0) > 0
                or self.store.is_persistent(key)
            ):
                return True
            for owner in self.store.owners_of(key):
                if self.store.pair_decision(owner, key)[0] in ("keep", "standalone"):
                    return True
        return False

    def _qos_controller_parents(self, path):
        base = cgroup.base()
        parent = os.path.dirname(path)
        relative = os.path.relpath(parent, base)
        parents = [base]
        current = base
        if relative != ".":
            for segment in relative.split(os.sep):
                current = os.path.join(current, segment)
                parents.append(current)
        return parents

    def _qos_hard_safety(self, path, pids=None):
        for pid in cgroup.tree_procs(path) if pids is None else pids:
            reason = policy.protected_reason(pid, self.cfg)
            if reason:
                return reason
        return ""

    def _qos_authorization(self, scope, path):
        return self.authorize(
            authorization.QOS,
            authorization.Facts(scope=scope, hard_safety=self._qos_hard_safety(path)),
        )

    def _qos_oom_target(self, resource_class):
        key = {
            "leftover": "oom_adj_leftover",
            "shared": "oom_adj_shared",
        }.get(resource_class)
        if key is None:
            return None
        guard = self.cfg.get("guard", {})
        if not isinstance(guard, dict):
            return None
        target = guard.get(key, policy._DEFAULTS["guard"][key])
        if type(target) is not int or not oom.MIN_SCORE <= target <= oom.MAX_SCORE:
            if self.store.changed("qos_oom_config:" + key, repr(target)):
                self.store.log(
                    event="qos_refused",
                    why="guard.%s must be an integer from -1000 to 1000" % key,
                )
            return None
        return target

    def _qos_oom_group_write(self, path, resource_class):
        guard = self.cfg.get("guard", {})
        if (
            resource_class != "leftover"
            or not isinstance(guard, dict)
            or guard.get("oom_group_leftover", True) is not True
        ):
            return None
        control = os.path.join(path, "memory.oom.group")
        try:
            with open(control, encoding="ascii") as source:
                current = source.read().strip()
        except OSError:
            if self.store.changed("qos_oom_group:" + path, "missing"):
                self.store.log(
                    event="qos_controls_unavailable",
                    scope=cgroup.rel(path),
                    control="memory.oom.group",
                )
            return None
        if current == "1":
            return None
        if current != "0":
            if self.store.changed("qos_oom_group:" + path, current):
                self.store.log(
                    event="qos_refused",
                    scope=cgroup.rel(path),
                    why="memory.oom.group has an invalid value",
                )
            return None
        return qos.ResourceWrite("memory.oom.group", "1", current)

    def _qos_restore_disabled_oom_group(self, scope, path, record):
        """Restore a taema-owned group flag after live config turns it off."""
        guard = self.cfg.get("guard", {})
        if (
            record.get("class") != "leftover"
            or not isinstance(guard, dict)
            or guard.get("oom_group_leftover", True) is True
        ):
            return True
        originals = record.get("originals", [])
        group = next(
            (
                item
                for item in originals
                if isinstance(item, dict) and item.get("file") == "memory.oom.group"
            ),
            None,
        )
        if group is None:
            return True
        original = group.get("value")
        if not isinstance(original, str) or original.strip() not in ("0", "1"):
            self.store.log(
                event="qos_restore_failed",
                scope=scope,
                why="memory.oom.group original value is invalid",
            )
            return False
        try:
            control = os.path.join(path, "memory.oom.group")
            with open(control, encoding="ascii") as source:
                current = source.read().strip()
            if current == "1":
                qos.write_control(path, "memory.oom.group", original.strip())
        except OSError as error:
            self.store.log(
                event="qos_restore_failed",
                scope=scope,
                why="could not restore memory.oom.group: %s" % error,
            )
            return False
        record["originals"] = [
            item
            for item in originals
            if not (isinstance(item, dict) and item.get("file") == "memory.oom.group")
        ]
        self.store.dirty = True
        return True

    @staticmethod
    def _qos_live_oom_records(values):
        """Keep only valid OOM originals that still identify this user's process."""
        if not isinstance(values, list):
            return []
        live = []
        for item in values:
            if not isinstance(item, dict):
                continue
            pid, start, original, applied = (
                item.get("pid"),
                item.get("start"),
                item.get("value"),
                item.get("applied"),
            )
            if (
                not isinstance(pid, int)
                or isinstance(pid, bool)
                or pid <= 1
                or not isinstance(start, int)
                or isinstance(start, bool)
                or start <= 0
                or not isinstance(original, int)
                or isinstance(original, bool)
                or not -1000 <= original <= 1000
                or not isinstance(applied, int)
                or isinstance(applied, bool)
                or not original < applied <= 1000
            ):
                continue
            try:
                if (
                    inspect.starttime(pid) != start
                    or inspect.uid_of(pid) != os.getuid()
                ):
                    continue
            except (OSError, ProcessLookupError, ValueError):
                continue
            live.append(item)
        return live

    def _qos_oom_candidates(self, path, resource_class, existing=()):
        target = self._qos_oom_target(resource_class)
        if target is None:
            return []
        known = {
            (item.get("pid"), item.get("start"))
            for item in existing
            if isinstance(item, dict)
        }
        candidates = []
        for pid in cgroup.tree_procs(path):
            if policy.protected_reason(pid, self.cfg):
                continue
            try:
                start = inspect.starttime(pid)
                if (pid, start) in known:
                    continue
                if inspect.uid_of(pid) != os.getuid():
                    continue
                original = oom.read_score(pid)
            except (OSError, ValueError, ProcessLookupError):
                continue
            applied = max(original, target)
            if applied > original:
                candidates.append(
                    {
                        "pid": pid,
                        "start": start,
                        "value": original,
                        "applied": applied,
                    }
                )
        return candidates

    def _register_qos_oom(self, scope, path, candidates):
        registered = []
        for item in candidates:
            decision = self._qos_authorization(scope, path)
            if decision.verdict != authorization.ACT:
                for prior in registered:
                    try:
                        engine.helper_oom_restore(
                            self.cfg,
                            prior["pid"],
                            prior["start"],
                            prior["value"],
                            prior["applied"],
                        )
                    except engine.Refused as error:
                        self.store.log(
                            event="qos_restore_failed",
                            scope=scope,
                            pid=prior["pid"],
                            why="could not clear unused OOM record: %s" % error,
                        )
                raise engine.Refused(decision.reason or "OOM shaping is not authorized")
            pid, start, original, applied = (
                item["pid"],
                item["start"],
                item["value"],
                item["applied"],
            )
            try:
                if (
                    inspect.starttime(pid) != start
                    or inspect.uid_of(pid) != os.getuid()
                    or oom.read_score(pid) != original
                ):
                    continue
                engine.helper_oom_record(self.cfg, pid, start, original, applied)
            except (OSError, ValueError, engine.Refused) as error:
                self.store.log(
                    event="qos_refused",
                    scope=scope,
                    pid=pid,
                    why="OOM priority record refused: %s" % error,
                )
                continue
            registered.append(item)
        return registered

    def _qos_tree_cpu_usage(self, path):
        # cpu.stat is hierarchical and includes descendant usage.
        return engine._cpu_usage(path)

    def _qos_unit_class(self, path):
        """Resolve explicit runtime/foreground classes before inferring background from CPU."""
        unit = engine.unit_for_leaf(self.units, os.path.basename(path))
        if not unit:
            return None
        metadata = unit.get("unit", {})
        resource_class = metadata.get("qos_class", metadata.get("class"))
        if resource_class in (
            "interactive",
            "foreground",
            "infrastructure",
            "protected",
            "container",
            "vm",
        ):
            return "normal"
        if resource_class == "background":
            return "background"
        if unit.get("gc", {}).get("keep_while_children") is True:
            # Runtime scopes that retain live child workloads stay at normal weight.
            return "normal"
        return None

    def _observe_qos_background(self, scope, path, pids, now):
        """Track low-CPU app scopes independently from the GC candidate set."""
        if "/" in scope or not scope.startswith("app-") or not pids:
            self.qos_usage.pop(scope, None)
            self.qos_idle_since.pop(scope, None)
            return
        if self._qos_unit_class(path) == "normal":
            self.qos_usage.pop(scope, None)
            self.qos_idle_since.pop(scope, None)
            return
        if self._qos_hard_safety(path):
            self.qos_usage.pop(scope, None)
            self.qos_idle_since.pop(scope, None)
            return
        snapshot = inspect.LazySnapshot().get()
        if not getattr(snapshot, "ok", True) or inspect.edges(set(pids), snapshot):
            self.qos_usage.pop(scope, None)
            self.qos_idle_since.pop(scope, None)
            return
        usage = self._qos_tree_cpu_usage(path)
        previous = self.qos_usage.get(scope)
        self.qos_usage[scope] = (usage, now) if usage is not None else None
        if usage is None:
            self.qos_usage.pop(scope, None)
            self.qos_idle_since.pop(scope, None)
            return
        if previous is None or previous[0] is None or now <= previous[1]:
            self.qos_idle_since.pop(scope, None)
            return
        elapsed = now - previous[1]
        if elapsed < qos.BACKGROUND_SAMPLE_SECONDS:
            return
        cpu_percent = 100.0 * max(0, usage - previous[0]) / (elapsed * 1_000_000)
        if cpu_percent > qos.BACKGROUND_CPU_PERCENT:
            self.qos_idle_since.pop(scope, None)
        else:
            self.qos_idle_since.setdefault(scope, previous[1])

    def _enable_qos_controllers(self, scope, path):
        all_enabled = True
        for parent in self._qos_controller_parents(path):
            reason = qos.enable_controllers(parent)
            if reason:
                all_enabled = False
                if self.store.changed("qos_controller:" + parent, reason):
                    self.store.log(
                        event="qos_controller_unavailable",
                        scope=scope,
                        parent=cgroup.rel(parent),
                        reason=reason,
                    )
        return all_enabled

    def _apply_qos_class(
        self, scope, path, resource_class, now=None, only_controls=None
    ):
        now = time.time() if now is None else float(now)
        scopes, _exemptions = self._qos_state()
        previous = scopes.get(scope)
        if not isinstance(previous, dict) or previous.get("class") != resource_class:
            previous = {}
        decision = self._qos_authorization(scope, path)
        if decision.verdict == authorization.KEEP:
            if self.store.changed("qos_refused:" + scope, decision.reason):
                self.store.log(
                    event="qos_refused",
                    scope=scope,
                    reason=decision.reason,
                )
            return False
        observing = decision.verdict == authorization.WOULD_ACT
        if observing:
            plan = qos.plan(path, resource_class)
            oom_candidates = self._qos_oom_candidates(
                path, resource_class, previous.get("oom_score_adj", [])
            )
            group_write = self._qos_oom_group_write(path, resource_class)
            controls = list(plan.available)
            if group_write is not None:
                controls.append(group_write.name)
            would_signature = (
                resource_class,
                tuple(controls),
                tuple(
                    (item["pid"], item["start"], item["value"], item["applied"])
                    for item in oom_candidates
                ),
            )
            if (controls or oom_candidates) and self.store.changed(
                "qos_would:" + scope, would_signature
            ):
                self.store.log(
                    event="qos_would",
                    scope=scope,
                    resource_class=resource_class,
                    controls=controls,
                    oom_pids=[item["pid"] for item in oom_candidates],
                )
            scopes[scope] = {
                "class": resource_class,
                "active": False,
                "applied": False,
                "originals": [],
                "oom_score_adj": [],
                "available": list(plan.available),
                "deprioritized": bool(plan.available or oom_candidates or group_write),
            }
            self.store.dirty = True
            return True

        # Authorization is checked immediately before changing parent delegation too.
        decision = self._qos_authorization(scope, path)
        if decision.verdict != authorization.ACT:
            if self.store.changed("qos_refused:" + scope, decision.reason):
                self.store.log(event="qos_refused", scope=scope, reason=decision.reason)
            return False
        controllers_ready = self._enable_qos_controllers(scope, path)
        plan = qos.plan(path, resource_class)
        if only_controls is not None:
            previously_available = set(previous.get("available", []))
            # Controller enablement can expose controls between the preflight plan
            # and this plan. Treat those as newly available in this same pass.
            newly_available = set(plan.available) - previously_available
            plan = qos.QoSPlan(
                tuple(
                    item
                    for item in plan.writes
                    if item.name in only_controls or item.name in newly_available
                ),
                plan.available,
            )
        previous_oom_values = self._qos_live_oom_records(
            previous.get("oom_score_adj", [])
        )
        if previous_oom_values != previous.get("oom_score_adj", []):
            previous["oom_score_adj"] = previous_oom_values
            self.store.dirty = True
        previous_resources = previous.get("originals", [])
        previous_resource_names = {
            item.get("file") for item in previous_resources if isinstance(item, dict)
        }
        group_write = self._qos_oom_group_write(path, resource_class)
        if group_write is not None and group_write.name not in previous_resource_names:
            plan = qos.QoSPlan(plan.writes + (group_write,), plan.available)
        new_oom_values = []
        decision = self._qos_authorization(scope, path)
        if decision.verdict != authorization.ACT:
            if self.store.changed("qos_refused:" + scope, decision.reason):
                self.store.log(event="qos_refused", scope=scope, reason=decision.reason)
            return False
        try:
            candidates = self._qos_oom_candidates(
                path, resource_class, previous_oom_values
            )
            remaining_records = max(0, MAX_QOS_OOM_RECORDS - len(previous_oom_values))
            if len(candidates) > remaining_records:
                self.store.log(
                    event="qos_controls_unavailable",
                    scope=scope,
                    control="oom_score_adj",
                    reason="the bounded restore record is full",
                )
                candidates = candidates[:remaining_records]
            new_oom_values = self._register_qos_oom(scope, path, candidates)
        except engine.Refused as error:
            self.store.log(event="qos_refused", scope=scope, why=str(error))
            return False
        oom_values_by_pid = {
            (item.get("pid"), item.get("start")): item
            for item in previous_oom_values
            if isinstance(item, dict)
        }
        for item in new_oom_values:
            oom_values_by_pid[(item["pid"], item["start"])] = item
        oom_values = [oom_values_by_pid[key] for key in sorted(oom_values_by_pid)]
        if plan.writes or new_oom_values:
            originals_by_file = {
                item["file"]: item["value"]
                for item in previous.get("originals", [])
                if isinstance(item, dict)
                and isinstance(item.get("file"), str)
                and isinstance(item.get("value"), str)
            }
            rollback = [
                {"file": item.name, "value": item.original} for item in plan.writes
            ]
            for item in plan.writes:
                originals_by_file.setdefault(item.name, item.original)
            originals = [
                {"file": name, "value": value}
                for name, value in sorted(originals_by_file.items())
            ]
            undo = {
                "operation": "restore_priorities",
                "resources": originals,
                "oom_score_adj": oom_values,
                "qos": True,
            }
            rollback = {
                "operation": "restore_priorities",
                "resources": [
                    {"file": item.name, "value": item.original} for item in plan.writes
                ],
                "oom_score_adj": new_oom_values,
            }
            try:
                with self.store.decision_context(
                    "qos",
                    scope=scope,
                    authority=decision.authority or "mode",
                    mode=self.mode,
                    why="deprioritize %s scope" % resource_class,
                    undo=undo,
                ):
                    qos.apply(path, plan)
                    for item in new_oom_values:
                        decision = self._qos_authorization(scope, path)
                        if decision.verdict != authorization.ACT:
                            raise engine.Refused(
                                decision.reason or "OOM shaping is not authorized"
                            )
                        pid = item["pid"]
                        if (
                            policy.protected_reason(pid, self.cfg)
                            or inspect.starttime(pid) != item["start"]
                            or inspect.uid_of(pid) != os.getuid()
                            or oom.read_score(pid) != item["value"]
                        ):
                            raise engine.Refused(
                                "OOM priority target changed before shaping"
                            )
                        oom.write_score(
                            pid, item["applied"], item["start"], item["value"]
                        )
                    self.store.log(
                        event="qos_applied",
                        scope=scope,
                        resource_class=resource_class,
                        controls=list(plan.available),
                        oom_pids=[item["pid"] for item in new_oom_values],
                    )
            except (OSError, ValueError, engine.Refused) as error:
                try:
                    rollback_result = self._undo_action_effect(
                        {"id": "qos-rollback", "scope": scope, "undo": rollback}
                    )
                    if not isinstance(rollback_result, dict) or not rollback_result.get(
                        "ok"
                    ):
                        self.store.log(
                            event="qos_restore_failed",
                            scope=scope,
                            why=(rollback_result or {}).get(
                                "error", "priority rollback failed"
                            ),
                        )
                except (OSError, engine.Refused):
                    pass
                self.store.log(event="qos_refused", scope=scope, error=str(error))
                return False
        else:
            originals = previous.get("originals", [])
            if not plan.available and self.store.changed(
                "qos_unavailable:" + scope, resource_class
            ):
                self.store.log(
                    event="qos_controls_unavailable",
                    scope=scope,
                    resource_class=resource_class,
                )
        scopes[scope] = {
            "class": resource_class,
            "active": True,
            "applied": bool(originals or oom_values),
            "originals": originals,
            "oom_score_adj": oom_values,
            "available": list(plan.available),
            "controllers_ready": controllers_ready,
            "controller_retry_at": (
                0.0 if controllers_ready else now + qos.CONTROLLER_RETRY_SECONDS
            ),
            "deprioritized": bool(plan.available or oom_values or originals),
        }
        self.store.dirty = True
        return True

    def qos_pass(self, now=None):
        """Reconcile managed scope classes after a stable two-second observation."""
        now = time.time() if now is None else float(now)
        scopes, exemptions = self._qos_state()
        base = cgroup.base()
        paths = {}
        pending = list(cgroup.subdirs(base))
        while pending:
            path = pending.pop()
            scope = cgroup.rel(path)
            paths[scope] = path
            pending.extend(cgroup.subdirs(path))

        for transient_state in (
            self.qos_pending,
            self.qos_usage,
            self.qos_idle_since,
        ):
            for scope in tuple(transient_state):
                if scope not in paths:
                    transient_state.pop(scope, None)

        for scope in tuple(scopes):
            if scope not in paths:
                scopes.pop(scope, None)
                exemptions.pop(scope, None)
                self.qos_pending.pop(scope, None)
                self.qos_usage.pop(scope, None)
                self.qos_idle_since.pop(scope, None)
                self.store.dirty = True

        config = self.cfg.get("qos", policy._DEFAULTS["qos"])
        enabled = isinstance(config, dict) and config.get("enabled", True) is True
        background_scopes = [
            (scope, path, cgroup.tree_procs(path))
            for scope, path in paths.items()
            if "/" not in scope
            and scope.startswith("app-")
            and self._qos_unit_class(path) != "normal"
            and cgroup.tree_procs(path)
            and os.path.isfile(os.path.join(path, "cpu.stat"))
        ]
        if enabled and background_scopes:
            if now >= self.qos_next_background_sample:
                for scope, path, pids in background_scopes:
                    self._observe_qos_background(scope, path, pids, now)
                self.qos_next_background_sample = now + qos.BACKGROUND_SAMPLE_SECONDS
        else:
            self.qos_next_background_sample = 0.0
            if not enabled:
                self.qos_usage.clear()
                self.qos_idle_since.clear()
        idle_times = {**self.idle_since, **self.qos_idle_since}
        for scope, path in paths.items():
            record = scopes.get(scope)
            if not isinstance(record, dict):
                record = None
            pids = cgroup.tree_procs(path)
            if not enabled:
                if record:
                    self._restore_qos_scope(scope)
                else:
                    self.qos_pending.pop(scope, None)
                    exemptions.pop(scope, None)
                continue
            if not pids:
                self.qos_usage.pop(scope, None)
                self.qos_idle_since.pop(scope, None)
                if record:
                    self._restore_qos_scope(scope)
                else:
                    self.qos_pending.pop(scope, None)
                    exemptions.pop(scope, None)
                continue

            unit_class = self._qos_unit_class(path)
            resource_class = (
                None
                if unit_class == "normal"
                else unit_class or qos.classify(scope, idle_times, now)
            )
            if record and record.get("active"):
                decision = self._qos_authorization(scope, path)
                if decision.verdict == authorization.KEEP:
                    self._restore_qos_scope(scope)
                    continue
            if resource_class is not None and self._qos_scope_kept(path):
                self._restore_qos_scope(
                    scope, exempt=True, classification=resource_class
                )
                continue
            exempt_class = exemptions.get(scope)
            if exempt_class is not None and exempt_class == resource_class:
                self.qos_pending.pop(scope, None)
                continue
            if exempt_class is not None:
                exemptions.pop(scope, None)
                self.store.dirty = True

            if resource_class is None and not record:
                self.qos_pending.pop(scope, None)
                continue

            if self.mode == "observe" and record and record.get("active"):
                if not self._restore_qos_scope(scope):
                    continue
                record = None
            elif (
                resource_class is not None
                and record
                and record.get("class") == resource_class
                and record.get("active") is (self.mode != "observe")
            ):
                plan = qos.plan(path, resource_class)
                if self.mode == "observe":
                    self.qos_pending.pop(scope, None)
                    oom_candidates = self._qos_oom_candidates(
                        path, resource_class, record.get("oom_score_adj", [])
                    )
                    group_write = self._qos_oom_group_write(path, resource_class)
                    controls = list(plan.available)
                    if group_write is not None and group_write.name not in {
                        item.get("file")
                        for item in record.get("originals", [])
                        if isinstance(item, dict)
                    }:
                        controls.append(group_write.name)
                    signature = (
                        resource_class,
                        tuple(controls),
                        tuple(
                            (item["pid"], item["start"], item["value"], item["applied"])
                            for item in oom_candidates
                        ),
                    )
                    if (controls or oom_candidates) and self.store.changed(
                        "qos_would:" + scope, signature
                    ):
                        self.store.log(
                            event="qos_would",
                            scope=scope,
                            resource_class=resource_class,
                            controls=controls,
                            oom_pids=[item["pid"] for item in oom_candidates],
                        )
                    continue
                recorded_controls = set(record.get("available", []))
                if not self._qos_restore_disabled_oom_group(scope, path, record):
                    continue
                newly_available = set(plan.available) - recorded_controls
                recorded_resources = {
                    item.get("file")
                    for item in record.get("originals", [])
                    if isinstance(item, dict)
                }
                group_write = self._qos_oom_group_write(path, resource_class)
                group_available = (
                    group_write is not None
                    and group_write.name not in recorded_resources
                )
                new_oom_candidates = self._qos_oom_candidates(
                    path, resource_class, record.get("oom_score_adj", [])
                )
                controller_retry_due = not record.get(
                    "controllers_ready", False
                ) and now >= record.get("controller_retry_at", 0.0)
                if (
                    not newly_available
                    and not group_available
                    and not new_oom_candidates
                    and not controller_retry_due
                ):
                    self.qos_pending.pop(scope, None)
                    continue
                candidate = self.qos_pending.get(scope)
                if candidate is None or candidate[0] != resource_class:
                    self.qos_pending[scope] = (resource_class, now)
                    continue
                if now - candidate[1] < qos.DEBOUNCE_SECONDS:
                    continue
                self.qos_pending.pop(scope, None)
                self._apply_qos_class(
                    scope,
                    path,
                    resource_class,
                    now=now,
                    only_controls=newly_available,
                )
                continue

            candidate = self.qos_pending.get(scope)
            if candidate is None or candidate[0] != resource_class:
                self.qos_pending[scope] = (resource_class, now)
                continue
            if now - candidate[1] < qos.DEBOUNCE_SECONDS:
                continue
            self.qos_pending.pop(scope, None)
            if resource_class is None:
                if record:
                    self._restore_qos_scope(scope)
                continue
            if record and record.get("class") != resource_class:
                if not self._restore_qos_scope(scope):
                    continue
            self._apply_qos_class(scope, path, resource_class, now=now)

        self.store.save_if_dirty(min_interval=0.5)

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
                or len(oom_values) > MAX_QOS_OOM_UNDO_INPUT
                or not resources
                and not oom_values
            ):
                return {"ok": False, "error": "priority undo payload is invalid"}
            allowed_files = {
                "cpu.idle",
                "cpu.weight",
                "io.weight",
                "io.bfq.weight",
                "memory.oom.group",
            }
            for item in resources:
                if not isinstance(item, dict) or item.get("file") not in allowed_files:
                    return {"ok": False, "error": "priority resource is invalid"}
                value = item.get("value")
                if not isinstance(value, str) or not value or len(value) > 8192:
                    return {"ok": False, "error": "priority value is invalid"}
                name = item["file"]
                if name in ("cpu.idle", "memory.oom.group"):
                    valid_value = value.strip() in ("0", "1")
                elif name == "cpu.weight":
                    valid_value = (
                        value.strip().isdecimal() and 1 <= int(value.strip()) <= 10000
                    )
                else:
                    lines = value.strip().splitlines()
                    valid_value = bool(lines) and len(lines) <= 128
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
                pid, start, value, applied = (
                    item.get("pid"),
                    item.get("start"),
                    item.get("value"),
                    item.get("applied"),
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
                    or not isinstance(applied, int)
                    or isinstance(applied, bool)
                    or not value < applied <= 1000
                ):
                    return {"ok": False, "error": "oom priority value is invalid"}
                try:
                    if (
                        inspect.starttime(pid) != start
                        or inspect.uid_of(pid) != os.getuid()
                    ):
                        continue
                except (OSError, ProcessLookupError, ValueError):
                    continue
                safe_oom_values.append((pid, start, value, applied))
            if len(safe_oom_values) > MAX_QOS_OOM_RECORDS:
                return {"ok": False, "error": "priority undo payload is invalid"}
            try:
                for item in resources:
                    commands = (
                        item["value"].strip().splitlines()
                        if item["file"] == "io.weight"
                        else [item["value"].rstrip()]
                    )
                    for command in commands:
                        qos.write_control(path, item["file"], command)
                for pid, start, value, applied in safe_oom_values:
                    engine.helper_oom_restore(self.cfg, pid, start, value, applied)
            except (OSError, engine.Refused) as error:
                return {
                    "ok": False,
                    "error": "could not restore priorities: %s" % error,
                }
            self.store.log(event="priority_restored", scope=scope)
            if payload.get("qos") is True:
                scopes, exemptions = self._qos_state()
                current = scopes.pop(scope, {})
                held_class = current.get("class")
                if isinstance(held_class, str) and held_class:
                    exemptions[scope] = held_class
                self.qos_pending.pop(scope, None)
                self.store.dirty = True
            return {
                "ok": True,
                "scope": scope,
                "resources": len(resources),
                "oom_score_adj": len(safe_oom_values),
            }

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
        if c == "memory_budget":
            return self._memory_budget_report()
        if c == "freeze":
            scope = msg.get("scope")
            if (
                not isinstance(scope, str)
                or not cgroup.valid_rel(scope)
                or scope == "manager"
                or scope.startswith("manager/")
            ):
                return {"error": "invalid freeze scope", "code": "invalid_request"}
            result = self.freeze_scope(scope, manual=True, reason="manual freeze")
            if not result.get("ok"):
                return {"error": result.get("error", "freeze refused")}
            return result
        if c == "thaw":
            scope, all_scopes = msg.get("scope"), msg.get("all") is True
            if all_scopes == (scope is not None):
                return {"error": "choose one scope or --all", "code": "invalid_request"}
            if all_scopes:
                results = self.thaw_all_managed_scopes("manual thaw all")
                failed = [item for item in results if not item.get("ok")]
                if failed:
                    return {"error": failed[0].get("error", "thaw failed")}
                return {
                    "thawed": [item["scope"] for item in results if item.get("thawed")]
                }
            if (
                not isinstance(scope, str)
                or not cgroup.valid_rel(scope)
                or scope == "manager"
                or scope.startswith("manager/")
            ):
                return {"error": "invalid thaw scope", "code": "invalid_request"}
            result = self._thaw_scope(
                scope, "manual thaw", authority="manual", managed_only=False
            )
            if not result.get("ok"):
                return {"error": result.get("error", "thaw refused")}
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
                "frozen_scopes": [
                    {"scope": scope, **record}
                    for scope, record in sorted(
                        self.store.data.get("frozen_scopes", {}).items()
                    )
                    if isinstance(record, dict)
                ],
                "config_error": self.config_error,
                "config": list(self.cfg.get("_sources", [])),
                "unit_errors": list(self.cfg.get("_unit_errors", [])),
                "auto": self.auto_status(),
                "guard": self.guard_status(),
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
                memory_results = (
                    self.reclaim_pass(dry_run=msg.get("dry_run") is True)
                    if msg.get("memory") is True
                    else None
                )
            finally:
                self._in_tick = was_in_tick
                self.store.defer_writes = was_deferred
            if not was_deferred:
                self.store.save_if_dirty()
            reply = {"candidates": candidates}
            if memory_results is not None:
                reply["memory"] = memory_results
            return reply
        if c == "reclaim":
            was_in_tick = self._in_tick
            was_deferred = self.store.defer_writes
            self._in_tick = True
            self.store.defer_writes = True
            try:
                result = self.reclaim_scope(
                    msg.get("scope"),
                    force_veto=msg.get("force_veto") is True,
                    dry_run=msg.get("dry_run") is True,
                )
            finally:
                self._in_tick = was_in_tick
                self.store.defer_writes = was_deferred
            if not was_deferred:
                self.store.save_if_dirty()
            return result
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
                    if msg.get("op") in (
                        "answer",
                        "teach",
                        "review_answer",
                    ) and result.get("choice") in ("keep", "standalone"):
                        scope = result.get("scope")
                        if isinstance(scope, str):
                            self._restore_qos_scope(scope, exempt=True)
                        self._restore_qos_for_keys(result.get("leftovers", []))
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

    def guard_status(self):
        """Return only the guard state intended for the status view model."""
        state = self.guard_state
        return {
            "active": state.get("active") is True,
            "trigger": state.get("trigger"),
            "triggers": list(state.get("triggers", [])),
            "started_at": state.get("started_at"),
            "steps": list(state.get("steps", [])),
            "bytes_freed": int(state.get("bytes_freed", 0)),
            "last_trigger": state.get("last_trigger"),
            "last_bytes_freed": int(state.get("last_bytes_freed", 0)),
            "last_duration_ms": state.get("last_duration_ms"),
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

    def _freeze_config_enabled(self):
        freeze = self.cfg.get("freeze", {})
        experimental = self.cfg.get("experimental", {})
        return (
            isinstance(freeze, dict)
            and freeze.get("enabled", True) is True
            and isinstance(experimental, dict)
            and experimental.get("freeze", False) is True
        )

    def _freeze_auto_enabled(self):
        if not self._freeze_config_enabled():
            return False
        freeze = self.cfg.get("freeze", {})
        return self.mode in ("auto", "enforce") or (
            self.mode == "adopt" and freeze.get("adopt", False) is True
        )

    @staticmethod
    def _freeze_value(path):
        try:
            with open(os.path.join(path, "cgroup.freeze"), encoding="ascii") as source:
                value = source.read().strip()
        except OSError:
            return None
        return value if value in ("0", "1") else None

    @staticmethod
    def _wait_for_cgroup_frozen(path, timeout=1.0):
        deadline = time.monotonic() + timeout
        while True:
            try:
                with open(
                    os.path.join(path, "cgroup.events"), encoding="ascii"
                ) as source:
                    values = Daemon._leaf_event_values(source.read())
            except OSError:
                return False
            if values.get("frozen") == "1":
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def _freeze_safety_reason(self, scope, path, snapshot=None):
        """Return a fail-closed reason when a leftover cannot safely be frozen."""
        return self._freeze_safety_facts(scope, path, snapshot)[0]

    def _freeze_safety_facts(self, scope, path, snapshot=None):
        """Return the safety reason and monitored listeners for one freeze inspection."""
        if (
            not cgroup.valid_rel(scope)
            or scope == "manager"
            or scope.startswith("manager/")
            or scope.count("/") != 1
            or not scope.startswith("leftover/")
        ):
            return "not a top-level leftover scope", []
        if not os.path.isdir(path):
            return "scope is unavailable", []
        if cgroup.subdirs(path):
            return "scope is not a leaf", []
        pids = cgroup.tree_procs(path)
        if not pids:
            return "scope is empty", []
        if snapshot is None:
            snapshot = inspect.Snapshot()
        if not getattr(snapshot, "ok", False):
            return "socket state unknown", []
        fd_reason, member_socket_inodes, pty_host = freezing.member_fd_facts(
            pids, snapshot, inspect.PROC
        )
        if fd_reason:
            return fd_reason, []
        if pty_host:
            return "pty host", []
        wake_on_connect = (
            self.cfg.get("freeze", {}).get("wake_on_connect", False) is True
        )
        socket_reason = freezing.socket_safety_reason(
            pids,
            snapshot,
            member_socket_inodes,
            wake_on_connect=wake_on_connect,
        )
        if socket_reason:
            return socket_reason, []
        edge_map = inspect.edges(set(pids), snapshot)
        if edge_map:
            return "outside dependency edge", []
        listeners = ()
        if wake_on_connect:
            listeners, listener_error = freezing.listener_descriptors(
                pids, snapshot, member_socket_inodes
            )
            if listener_error:
                return listener_error, []
        for pid in pids:
            entry = self.lineage.entry(pid)
            if (
                not entry
                or not isinstance(entry.get("start"), int)
                or entry["start"] <= 0
            ):
                return "process identity unknown", []
            member_cgroup = cgroup.proc_cgroup(pid)
            if not member_cgroup:
                return "process cgroup unknown", []
            if not cgroup.is_prefix(path, member_cgroup):
                return "process moved during inspection", []
            env_rules = self.cfg.get("protected", {}).get("env_prefix", {})
            if env_rules:
                try:
                    with open(
                        os.path.join(inspect.PROC, str(pid), "environ"), "rb"
                    ) as source:
                        source.read()
                except OSError:
                    return "protected environment state unknown", []
            protected = policy.protected_reason(pid, self.cfg)
            if protected:
                return "protected member: %s" % protected, []
            key = entry.get("key")
            if not isinstance(key, str) or not key:
                return "member identity unknown", []
            facts = self.store.peek(key)
            if (
                self.store.is_persistent(key)
                or self.store.standalone(key)
                or facts.get("user_keep", 0.0) > 0
            ):
                return "member has a keep or standalone decision", []
            if self.store.default_action(key)[0] == "share":
                return "member is configured to be kept", []
            for owner in self.store.owners_of(
                key, limit=max(1, len(self.store.data.get("pairs", {})))
            ):
                if self.store.pair_decision(owner, key)[0] in ("keep", "standalone"):
                    return "member has a keep or standalone decision", []
        return "", listeners

    def _clear_freeze_samples(self, scope):
        self.freeze_usage.pop(scope, None)
        self.manual_freeze_usage.pop(scope, None)
        self.freeze_idle_since.pop(scope, None)

    def _thaw_scope(self, scope, reason, *, authority="mode", managed_only=True):
        """Thaw one safe, validated scope and clear its recovery record after success."""
        if (
            not isinstance(scope, str)
            or not cgroup.valid_rel(scope)
            or scope == "manager"
            or scope.startswith("manager/")
        ):
            return {"ok": False, "error": "invalid or managed scope"}
        record = self.store.data.get("frozen_scopes", {}).get(scope)
        if managed_only and record is None:
            return {"ok": False, "error": "scope is not frozen by taema"}
        path = os.path.join(cgroup.base(), scope)
        value = self._freeze_value(path)
        if value is None:
            if not os.path.exists(path):
                with self.store.decision_context(
                    "thaw",
                    scope=scope,
                    authority=authority,
                    mode=self.mode,
                    why=reason,
                ):
                    self.store.clear_frozen_scope(scope)
                    self.store.log(
                        event="thaw",
                        scope=scope,
                        reason=reason,
                        source=(record or {}).get("source", "external"),
                        thawed=False,
                        stale=True,
                    )
                self._clear_freeze_samples(scope)
                self._save_if_idle()
                return {"ok": True, "scope": scope, "thawed": False, "stale": True}
            self.store.log(
                event="thaw_failed",
                scope=scope,
                reason="%s: freeze state is unavailable" % reason,
            )
            return {"ok": False, "error": "freeze state is unavailable"}
        try:
            with self.store.decision_context(
                "thaw",
                scope=scope,
                authority=authority,
                mode=self.mode,
                why=reason,
            ):
                if value == "1":
                    with open(
                        os.path.join(path, "cgroup.freeze"), "w", encoding="ascii"
                    ) as target:
                        target.write("0\n")
                self.store.clear_frozen_scope(scope)
                self.store.log(
                    event="thaw",
                    scope=scope,
                    reason=reason,
                    source=(record or {}).get("source", "external"),
                    thawed=value == "1",
                )
        except OSError as error:
            self.store.log(
                event="thaw_failed", scope=scope, reason="%s: %s" % (reason, error)
            )
            return {"ok": False, "error": "could not thaw %s: %s" % (scope, error)}
        self._clear_freeze_samples(scope)
        self._save_if_idle()
        return {"ok": True, "scope": scope, "thawed": value == "1"}

    def thaw_all_managed_scopes(self, reason, *, sources=None):
        """Thaw recorded Taema freezes, optionally restricted to their origin."""
        managed = self.store.data.get("frozen_scopes", {})
        if not isinstance(managed, dict):
            return []
        results = []
        for scope, record in list(managed.items()):
            if (
                sources is not None
                and (record or {}).get("source", "auto") not in sources
            ):
                continue
            result = self._thaw_scope(scope, reason, managed_only=True)
            results.append(result)
        if results:
            self._save_if_idle()
        return results

    def _frozen_listener_scopes(self):
        """Return managed, still-frozen scopes that need accept-queue monitoring."""
        managed = self.store.data.get("frozen_scopes", {})
        if not isinstance(managed, dict):
            return []
        out = []
        for scope, record in managed.items():
            if (
                not isinstance(scope, str)
                or not cgroup.valid_rel(scope)
                or not isinstance(record, dict)
                or not record.get("listeners")
            ):
                continue
            path = os.path.join(cgroup.base(), scope)
            if self._freeze_value(path) == "1":
                out.append((scope, path, record))
        return out

    def _listener_wake_due(self, now):
        return bool(self._frozen_listener_scopes()) and (
            now - self.last_listener_check >= 2.0
        )

    def _run_listener_wake_if_due(self, now):
        if self._listener_wake_due(now):
            self.guarded(lambda: self.listener_wake_pass(now=now))

    @staticmethod
    def _listener_thaw_reason(reason):
        if reason in (
            "listener has pending connections",
            "established TCP connection",
            "Unix socket peer unknown",
            "Unix socket peer owner unknown",
            "outside Unix socket peer",
            "connected to a window compositor",
            "connected to an audio or video client socket",
        ):
            return "connect"
        return "listener state unknown: " + reason

    def listener_wake_pass(self, now=None):
        """Thaw frozen listeners with queued clients; unknown queue state thaws too."""
        now = time.time() if now is None else now
        frozen = self._frozen_listener_scopes()
        if not frozen:
            self.last_listener_check = 0.0
            return []
        if now - self.last_listener_check < 2.0:
            return []
        self.last_listener_check = now
        snapshot = inspect.Snapshot()
        if not getattr(snapshot, "ok", False):
            return [
                self._thaw_scope(scope, "listener state unknown")
                for scope, _path, _record in frozen
            ]

        current = {}
        for row in snapshot.tcp_listen:
            current[("tcp", row.get("inode"))] = row
        for row in snapshot.unix:
            if row.get("state") == "LISTEN":
                current[("unix", row.get("inode"))] = row

        results = []
        for scope, path, record in frozen:
            if cgroup.subdirs(path):
                results.append(
                    self._thaw_scope(scope, "frozen scope is no longer a leaf")
                )
                continue
            members = cgroup.tree_procs(path)
            if not members:
                results.append(self._thaw_scope(scope, "frozen scope is empty"))
                continue
            fd_reason, member_socket_inodes, pty_host = freezing.member_fd_facts(
                members, snapshot, inspect.PROC
            )
            if fd_reason or pty_host:
                detail = fd_reason or "pty host"
                results.append(
                    self._thaw_scope(scope, "listener state unknown: " + detail)
                )
                continue
            socket_reason = freezing.socket_safety_reason(
                members,
                snapshot,
                member_socket_inodes,
                wake_on_connect=True,
            )
            if socket_reason:
                results.append(
                    self._thaw_scope(scope, self._listener_thaw_reason(socket_reason))
                )
                continue
            saved_listeners = record.get("listeners", [])
            if not isinstance(saved_listeners, list):
                results.append(self._thaw_scope(scope, "listener state unknown"))
                continue
            saved_descriptors = []
            for listener in saved_listeners:
                descriptor = freezing.ListenerDescriptor.from_record(listener)
                if descriptor is None:
                    saved_descriptors = None
                    break
                saved_descriptors.append(descriptor)
            if saved_descriptors is None:
                results.append(self._thaw_scope(scope, "listener state unknown"))
                continue
            listeners, listener_error = freezing.listener_descriptors(
                members, snapshot, member_socket_inodes
            )
            if listener_error:
                results.append(
                    self._thaw_scope(scope, "listener state unknown: " + listener_error)
                )
                continue
            current_descriptors = set(listeners)
            if not set(saved_descriptors).issubset(current_descriptors):
                results.append(self._thaw_scope(scope, "listener disappeared"))
                continue
            reason = ""
            for listener in listeners:
                row = current.get((listener.transport, listener.inode))
                if row is None or listener.inode not in member_socket_inodes:
                    reason = "listener disappeared"
                    break
                recv_q = row.get("recv_q")
                if (
                    not isinstance(recv_q, int)
                    or isinstance(recv_q, bool)
                    or recv_q < 0
                ):
                    reason = "listener state unknown"
                    break
                if recv_q > 0:
                    reason = "connect"
                    break
            if reason:
                results.append(self._thaw_scope(scope, reason))
                continue
            self.store.set_frozen_listeners(
                scope, [listener.to_record() for listener in listeners]
            )
        return results

    def _manual_freeze_cpu_reason(self, scope, path, members):
        """Require a stable, measured 60-second idle window for a manual freeze."""
        now = time.time()
        usage = engine._cpu_usage(path)
        if usage is None:
            self.manual_freeze_usage.pop(scope, None)
            return "CPU state unknown"
        prior = self.manual_freeze_usage.get(scope)
        self.manual_freeze_usage[scope] = (usage, now, members)
        if prior is None or prior[2] != members or now - prior[1] < 60.0:
            return "CPU idle window unavailable; need a stable 60-second sample"
        if usage < prior[0]:
            self.freeze_idle_since.pop(scope, None)
            return "CPU counter changed during idle sample"
        cpu = 100.0 * (usage - prior[0]) / ((now - prior[1]) * 1_000_000)
        limit = self.cfg.get("freeze", {}).get("cpu_idle_max", 0.5)
        if cpu > limit:
            self.freeze_idle_since.pop(scope, None)
            return "CPU %.3f%% is above the %.3f%% idle limit" % (cpu, limit)
        return ""

    def freeze_scope(
        self,
        scope,
        *,
        manual=False,
        reason="eligible idle leftover",
        cpu_verified=False,
    ):
        """Freeze one known-safe leftover, using the authorization ladder first."""
        if not self._freeze_config_enabled():
            return {"ok": False, "error": "freezing is disabled by configuration"}
        trigger = authorization.MANUAL_FREEZE if manual else authorization.FREEZE
        decision = self.authorize(
            trigger, authorization.Facts(scope=scope, leftover=True)
        )
        if decision.verdict != authorization.ACT:
            return {"ok": False, "error": decision.reason}
        path = os.path.join(cgroup.base(), scope)
        members = tuple(sorted(cgroup.tree_procs(path)))
        self.lineage.observe(inspect.ProcTable.scan())
        snapshot = inspect.Snapshot()
        safety, listeners = self._freeze_safety_facts(scope, path, snapshot)
        if safety:
            return {"ok": False, "error": safety}
        value = self._freeze_value(path)
        if value is None:
            return {"ok": False, "error": "freeze control is unavailable"}
        record = self.store.data.get("frozen_scopes", {}).get(scope)
        if value == "1":
            if record is not None:
                self._clear_freeze_samples(scope)
                return {"ok": True, "scope": scope, "frozen": True, "already": True}
            return {"ok": False, "error": "scope is already frozen outside taema"}
        if manual and not cpu_verified:
            cpu_reason = self._manual_freeze_cpu_reason(scope, path, members)
            if cpu_reason:
                return {"ok": False, "error": cpu_reason}
        if tuple(sorted(cgroup.tree_procs(path))) != members:
            return {"ok": False, "error": "scope membership changed during inspection"}
        # Re-read after CPU sampling so an external or concurrent freeze cannot race
        # the inspection above into a duplicate or unauthorized managed record.
        value = self._freeze_value(path)
        if value is None:
            return {"ok": False, "error": "freeze control is unavailable"}
        record = self.store.data.get("frozen_scopes", {}).get(scope)
        if value == "1":
            if record is not None:
                self._clear_freeze_samples(scope)
                return {"ok": True, "scope": scope, "frozen": True, "already": True}
            return {"ok": False, "error": "scope is already frozen outside taema"}
        maximum = self.cfg.get("freeze", {}).get("max_frozen", 32)
        if (
            scope not in self.store.data.get("frozen_scopes", {})
            and len(self.store.data.get("frozen_scopes", {})) >= maximum
        ):
            return {"ok": False, "error": "managed freeze limit reached"}
        source = "manual" if manual else "auto"
        why = reason or "eligible idle leftover"
        try:
            with self.store.decision_context(
                "freeze",
                scope=scope,
                authority=decision.authority or ("manual" if manual else "mode"),
                mode=self.mode,
                why=why,
            ) as audit:
                self.store.set_frozen_scope(
                    scope,
                    time.time(),
                    decision_id=audit["id"],
                    listeners=[listener.to_record() for listener in listeners],
                    source=source,
                )
                # Persist the recovery intent before changing kernel state. A crash from here
                # onward is recoverable on startup, including one between the write and log.
                self.store.save()
                with open(
                    os.path.join(path, "cgroup.freeze"), "w", encoding="ascii"
                ) as target:
                    target.write("1\n")
        except OSError as error:
            if self._freeze_value(path) == "0":
                self.store.clear_frozen_scope(scope)
                self.store.save()
            self.store.log(
                event="freeze_refused", scope=scope, reason="%s: %s" % (why, error)
            )
            return {"ok": False, "error": "could not freeze %s: %s" % (scope, error)}
        if not self._wait_for_cgroup_frozen(path):
            self._thaw_scope(scope, "freeze state unknown")
            self.store.log(
                event="freeze_refused",
                scope=scope,
                reason="kernel did not confirm the frozen state",
            )
            return {"ok": False, "error": "kernel did not confirm the frozen state"}
        self.store.log(event="freeze", scope=scope, reason=why, source=source)
        if self.cfg.get("freeze", {}).get("wake_on_connect", False) is True:
            safety, listeners = self._freeze_safety_facts(scope, path)
            if safety:
                self._thaw_scope(scope, self._listener_thaw_reason(safety))
                self.store.log(
                    event="freeze_refused",
                    scope=scope,
                    reason="post-freeze safety check: " + safety,
                )
                return {
                    "ok": False,
                    "error": "post-freeze safety check failed: " + safety,
                }
            self.store.set_frozen_listeners(
                scope, [listener.to_record() for listener in listeners]
            )
        # A frozen interval is not an idle CPU sample. Drop both trackers so any later
        # thaw path, including one initiated by the stop engine, must begin afresh.
        self._clear_freeze_samples(scope)
        self._save_if_idle()
        return {"ok": True, "scope": scope, "frozen": True}

    def freeze_pass(self, now=None, guard=False):
        """Sample leftover CPU and freeze only scopes idle for the configured grace."""
        now = time.time() if now is None else now
        managed = self.store.data.get("frozen_scopes", {})
        freeze_config = self.cfg.get("freeze", {})
        freeze_allowed = (
            isinstance(freeze_config, dict)
            and freeze_config.get("enabled", True) is True
        )
        guard_config = self.cfg.get("guard", {})
        guard_freeze = (
            guard
            and self._guard_enabled()
            and freeze_allowed
            and (
                self.mode in ("auto", "enforce")
                or (
                    self.mode == "adopt"
                    and isinstance(guard_config, dict)
                    and guard_config.get("freeze_in_adopt", False) is True
                )
            )
        )
        if not self._freeze_config_enabled() and not guard_freeze:
            self.freeze_usage.clear()
            self.manual_freeze_usage.clear()
            self.freeze_idle_since.clear()
            self.thaw_all_managed_scopes("freezing disabled by profile or flag")
            return []
        guard_adopt = (
            guard
            and self.mode == "adopt"
            and isinstance(guard_config, dict)
            and guard_config.get("freeze_in_adopt", False) is True
        )
        guard_auto = guard and self.mode in ("auto", "enforce") and guard_freeze
        if not self._freeze_auto_enabled() and not guard_adopt and not guard_auto:
            self.freeze_usage.clear()
            self.freeze_idle_since.clear()
            self.thaw_all_managed_scopes(
                "automatic freezing disabled by mode", sources={"auto"}
            )
            return []

        base = os.path.join(cgroup.base(), "leftover")
        if not os.path.isdir(base):
            self.freeze_usage.clear()
            self.freeze_idle_since.clear()
            return []
        leaves = {
            "leftover/" + os.path.basename(path): path
            for path in cgroup.subdirs(base)
            if not cgroup.subdirs(path)
        }
        snapshot = None
        for scope in list(managed):
            record = managed.get(scope) or {}
            if record.get("source", "auto") != "auto":
                continue
            path = os.path.join(cgroup.base(), scope)
            if scope not in leaves:
                self._thaw_scope(
                    scope,
                    "freeze eligibility changed: scope is no longer a leaf",
                )
                continue
            if not os.path.isdir(path):
                self._thaw_scope(scope, "frozen scope was removed")
                continue
            if self._freeze_value(path) == "0":
                self.store.clear_frozen_scope(scope)
                self.freeze_usage.pop(scope, None)
                self.freeze_idle_since.pop(scope, None)
                continue
            if snapshot is None:
                snapshot = inspect.Snapshot()
            safety = self._freeze_safety_reason(scope, path, snapshot)
            if safety:
                self._thaw_scope(scope, "freeze eligibility changed: " + safety)

        managed = self.store.data.get("frozen_scopes", {})
        automatic = [
            (scope, record)
            for scope, record in managed.items()
            if isinstance(record, dict) and record.get("source", "auto") == "auto"
        ]
        maximum = self.cfg.get("freeze", {}).get("max_frozen", 32)
        for scope, _record in sorted(
            automatic, key=lambda item: item[1].get("since", 0)
        )[: max(0, len(managed) - maximum)]:
            self._thaw_scope(scope, "automatic freeze limit reduced")
        managed = self.store.data.get("frozen_scopes", {})
        automatic_count = len(managed)
        results = []
        seen = set()
        for scope, path in sorted(leaves.items()):
            seen.add(scope)
            record = managed.get(scope)
            if record is not None:
                continue
            if automatic_count >= maximum:
                self.freeze_usage.pop(scope, None)
                self.freeze_idle_since.pop(scope, None)
                continue
            if snapshot is None:
                snapshot = inspect.Snapshot()
            safety = self._freeze_safety_reason(scope, path, snapshot)
            if safety:
                self.freeze_usage.pop(scope, None)
                self.freeze_idle_since.pop(scope, None)
                continue
            pids = tuple(sorted(cgroup.tree_procs(path)))
            usage = engine._cpu_usage(path)
            prior = self.freeze_usage.get(scope)
            if usage is None or not pids:
                self.freeze_usage.pop(scope, None)
                self.freeze_idle_since.pop(scope, None)
                continue
            self.freeze_usage[scope] = (usage, now, pids)
            if prior is None or prior[2] != pids or now - prior[1] < 60.0:
                self.freeze_idle_since.pop(scope, None)
                continue
            if usage < prior[0]:
                self.freeze_idle_since.pop(scope, None)
                continue
            elapsed = now - prior[1]
            cpu = 100.0 * max(0, usage - prior[0]) / (elapsed * 1_000_000)
            cpu_limit = self.cfg.get("freeze", {}).get("cpu_idle_max", 0.5)
            if cpu > cpu_limit:
                self.freeze_idle_since.pop(scope, None)
                continue
            idle_since = self.freeze_idle_since.setdefault(scope, prior[1])
            after = float(self.cfg.get("freeze", {}).get("after", 120))
            if now - idle_since < after:
                continue
            result = self.freeze_scope(
                scope,
                manual=False,
                reason="CPU %.3f%% idle for %.0fs" % (cpu, now - idle_since),
                cpu_verified=True,
            )
            results.append(result)
            if result.get("ok"):
                automatic_count += 1
        for scope in set(self.freeze_usage) - seen:
            self.freeze_usage.pop(scope, None)
            self.freeze_idle_since.pop(scope, None)
        return results

    def thaw_held_scopes(self):
        """Thaw managed freezes as soon as a matching hold or veto becomes active."""
        managed = self.store.data.get("frozen_scopes", {})
        if not isinstance(managed, dict):
            return
        for scope in list(managed):
            if not isinstance(scope, str) or not cgroup.valid_rel(scope):
                continue
            path = os.path.join(cgroup.base(), scope)
            held = self.store.hold_reason(scope)
            unit = engine.unit_for_leaf(self.units, os.path.basename(path))
            veto = engine.veto_for_scope(self.store, path, unit=unit)
            if veto:
                reason = self.store.describe_veto(veto)
                self._thaw_scope(scope, "veto: " + reason, authority="veto")
            elif held:
                self._thaw_scope(scope, "hold: " + held, authority="hold")

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
                self.thaw_all_managed_scopes("state directory changed")
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
        self.mem_enabled = memory.enabled(cfg)
        self.iv_reclaim = max(
            1.0, float(cfg.get("mem", {}).get("reclaim_interval", 60))
        )
        self.config_error = None
        self.freeze_usage.clear()
        self.freeze_idle_since.clear()
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
        if not self._freeze_config_enabled():
            self.thaw_all_managed_scopes("freezing disabled by profile or flag")
        elif not self._freeze_auto_enabled():
            self.thaw_all_managed_scopes(
                "automatic freezing disabled by mode", sources={"auto"}
            )
        try:
            self.memory_governor_pass(now=time.time())
        except Exception as error:
            self.store.log(event="memory_budget_failed", reason=str(error))
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

    def _guard_enabled(self):
        guard = self.cfg.get("guard", {})
        experimental = self.cfg.get("experimental", {})
        return (
            self.mem_enabled
            and isinstance(guard, dict)
            and guard.get("enabled", True) is True
            and isinstance(experimental, dict)
            and experimental.get("guard", False) is True
        )

    def _guard_handlers(self, now=None):
        now = time.monotonic() if now is None else float(now)
        if (
            self.oom_handlers_cache is None
            or now - self.oom_handlers_checked_at >= 30.0
        ):
            self.oom_handlers_cache = pressure_guard.detect_oom_handlers()
            self.oom_handlers_checked_at = now
        return self.oom_handlers_cache

    def _guard_floor(self):
        available, total = pressure_guard.host_memory()
        handlers = self._guard_handlers()
        earlyoom = handlers.get("earlyoom", ())
        baseline = (
            max(
                pressure_guard.earlyoom_memory_percent(item, total) for item in earlyoom
            )
            if earlyoom
            else None
        )
        configured = self.cfg.get("guard", {}).get("available_floor", "auto")
        try:
            floor = pressure_guard.available_floor_bytes(
                total,
                configured,
                earlyoom_present=bool(earlyoom),
                earlyoom_memory_percent=baseline,
            )
        except ValueError:
            floor = None
        return available, floor

    def _close_pressure_monitor(self):
        monitor = self.pressure_monitor
        if monitor is None:
            self.pressure_watch_signature = None
            return
        try:
            self.sel.unregister(monitor.fileno())
        except (KeyError, OSError, ValueError):
            pass
        monitor.close()
        self.pressure_monitor = None
        self.pressure_watch_signature = None

    def _sync_pressure_monitor(self):
        """Watch user-cgroup PSI trigger fds, keeping unsupported kernels on floor sampling."""
        if not self._guard_enabled():
            self._close_pressure_monitor()
            return
        config = self.cfg.get("guard", {})
        path = os.path.join(cgroup.base(), "memory.pressure")
        settings = {
            "some": config.get("psi_some", policy._DEFAULTS["guard"]["psi_some"]),
            "full": config.get("psi_full", policy._DEFAULTS["guard"]["psi_full"]),
        }
        signature = (path, tuple(sorted(settings.items())))
        if self.pressure_watch_signature == signature:
            return
        self._close_pressure_monitor()
        monitor = pressure_guard.PsiTriggerMonitor()
        failures = monitor.open_triggers(path, settings)
        self.pressure_watch_failures = tuple(failures)
        for failure in failures:
            if self.store.changed("guard_trigger_unavailable:" + failure, failure):
                self.store.log(
                    event="guard_trigger_unavailable",
                    source="memory.pressure",
                    reason=failure,
                )
        if not monitor.metrics:
            monitor.close()
            self.pressure_watch_signature = signature
            return
        try:
            self.sel.register(monitor.fileno(), selectors.EVENT_READ, "pressure")
        except (KeyError, OSError, ValueError) as error:
            monitor.close()
            failure = "memory.pressure: selector registration failed: %s" % error
            self.pressure_watch_failures = self.pressure_watch_failures + (failure,)
            if self.store.changed("guard_trigger_unavailable:" + failure, failure):
                self.store.log(
                    event="guard_trigger_unavailable",
                    source="memory.pressure",
                    reason=failure,
                )
            self.pressure_watch_signature = signature
            return
        self.pressure_monitor = monitor
        self.pressure_watch_signature = signature

    def _collect_pressure_events(self):
        if self.pressure_monitor is None:
            return
        try:
            metrics = self.pressure_monitor.poll()
        except OSError as error:
            self.store.log(event="guard_trigger_unavailable", reason=str(error))
            self._close_pressure_monitor()
            return
        for metric in metrics:
            self.queue_collector_event(PressureHigh(metric))

    def _guard_pressure_high(self):
        if not self._guard_enabled():
            return False
        if time.monotonic() < self.guard_trigger_until:
            return True
        available, floor = self._guard_floor()
        if available is not None and floor is not None and available < floor:
            return True
        config = self.cfg.get("guard", {})
        psi_path = os.path.join(cgroup.base(), "memory.pressure")
        psi = memory.pressure(psi_path)
        for metric, key in (("some", "psi_some"), ("full", "psi_full")):
            value = psi.get(metric + "_avg10")
            setting = config.get(key, policy._DEFAULTS["guard"][key])
            try:
                threshold = pressure_guard.psi_threshold_percent(setting, metric)
            except ValueError:
                continue
            if isinstance(value, (int, float)) and value >= threshold:
                return True
        return False

    def _collect_available_floor_event(self, now=None):
        """Sample the non-evented MemAvailable floor and queue it beside PSI events."""
        if not self._guard_enabled():
            return
        now = time.time() if now is None else float(now)
        if now - self.last_guard_check < 1.0:
            return
        self.last_guard_check = now
        available, floor = self._guard_floor()
        if available is None or floor is None or available >= floor:
            return
        if self.guard_state.get("active"):
            retry_at = self.guard_state.get("retry_at", 0.0)
            if now < retry_at:
                return
            trigger = "retry"
        else:
            trigger = "available"
        self.queue_collector_event(PressureHigh(trigger))

    def _guard_reclaim_step(self, stage):
        managed = self.store.data.get("frozen_scopes", {})
        managed = managed if isinstance(managed, dict) else {}
        candidates = []
        for scope, path in self._memory_paths().items():
            resource_class = self._reclaim_class(scope, path)
            frozen = scope in managed and self._freeze_value(path) == "1"
            if stage == "page_cache":
                if not (
                    frozen
                    or scope.startswith(engine.LEFTOVER + "/")
                    or resource_class == "background"
                ):
                    continue
            elif stage == "anonymous":
                if not frozen:
                    continue
            else:
                continue
            counters = memory.scope_counters(path)
            if not isinstance(counters, dict):
                continue
            size = (
                counters.get("reclaimable_bytes")
                if stage == "page_cache"
                else counters.get("anon_bytes")
            )
            if not isinstance(size, int) or size <= 0:
                continue
            candidates.append((size, scope, path, resource_class or "leftover"))

        candidates.sort(key=lambda item: (-item[0], item[1]))
        results = []
        measured = 0
        for _size, scope, path, resource_class in candidates:
            if not self._guard_pressure_high():
                break
            result = self._reclaim_one(
                scope,
                path,
                time.time(),
                memory.pressure(os.path.join(cgroup.base(), "memory.pressure")),
                resource_class=resource_class,
                guard=True,
                stage=stage,
            )
            results.append(result)
            field = (
                "file_reclaimed_bytes"
                if stage == "page_cache"
                else "anonymous_reclaimed_bytes"
            )
            value = result.get(field)
            if not isinstance(value, int):
                value = result.get("reclaimed_bytes")
            if isinstance(value, int) and value > 0:
                measured += value
        return {
            "performed": sum(item.get("status") == "reclaimed" for item in results),
            "bytes_freed": measured,
            "scopes": [
                item.get("scope")
                for item in results
                if item.get("status") == "reclaimed"
            ],
            "results": results,
        }

    def _guard_freeze_step(self):
        if self.mode == "observe":
            return {
                "performed": 0,
                "bytes_freed": 0,
                "scopes": [],
                "reason": "observe mode",
            }
        guard = self.cfg.get("guard", {})
        freeze = self.cfg.get("freeze", {})
        freeze_allowed = (
            isinstance(freeze, dict) and freeze.get("enabled", True) is True
        )
        guard_auto = (
            self.mode in ("auto", "enforce")
            and freeze_allowed
            and self._guard_enabled()
        )
        allowed_in_adopt = (
            self.mode == "adopt"
            and isinstance(guard, dict)
            and guard.get("freeze_in_adopt", False) is True
            and freeze_allowed
            and self._guard_enabled()
        )
        if not self._freeze_auto_enabled() and not guard_auto and not allowed_in_adopt:
            return {
                "performed": 0,
                "bytes_freed": 0,
                "scopes": [],
                "reason": "freezing is not authorized in this mode",
            }
        results = self.freeze_pass(guard=True)
        scopes = [
            item.get("scope")
            for item in results
            if isinstance(item, dict) and item.get("ok") is True
        ]
        return {
            "performed": len(scopes),
            "bytes_freed": 0,
            "scopes": scopes,
            "results": results,
        }

    def _guard_stop_step(self):
        if self.mode not in ("auto", "enforce"):
            return {
                "performed": 0,
                "bytes_freed": 0,
                "scopes": [],
                "reason": "stop authority is unavailable in this mode",
            }
        candidates = engine.gc_candidates(
            self.cfg,
            self.units,
            self.store,
            self.idle_since,
            now=lambda: time.time(),
            usage=self.gc_usage,
            skip=self.gc_skip,
            noted=self.gc_noted,
            lin=self.lineage,
            auto=True,
            authority=self.effective_authority["value"],
            signature_for_scope=self._gc_signature,
        )
        ranked = []
        for path, why in candidates:
            scope = cgroup.rel(path)
            if why.startswith("pair stop"):
                pair_authorized = True
                unit = None
            else:
                pair_authorized = False
                unit = engine.unit_for_leaf(self.units, os.path.basename(path))
                metadata = (unit or {}).get("unit", {})
                if metadata.get("stop_when_unneeded") is not True:
                    continue
            counters = memory.scope_counters(path)
            current = (
                counters.get("current_bytes") if isinstance(counters, dict) else None
            )
            if not isinstance(current, int):
                continue
            ranked.append((current, scope, path, why, unit, pair_authorized))
        ranked.sort(key=lambda item: (-item[0], item[1]))

        attempted = []
        for current, scope, path, why, unit, pair_authorized in ranked:
            if not self._guard_pressure_high():
                break
            facts = (
                self._pair_scope_facts(path)
                if pair_authorized
                else authorization.Facts(scope=scope)
            )
            decision = self.authorize(authorization.GC_STOP, facts)
            if decision.verdict != authorization.ACT:
                if decision.verdict == authorization.WOULD_ACT:
                    self.log_would_stop("guard_would_stop", scope, why)
                attempted.append(
                    {"scope": scope, "status": "refused", "reason": decision.reason}
                )
                continue
            guarded_reason = "pressure guard: " + why
            if self.mode == "auto" or pair_authorized:
                stopped = self.auto_stop_path(
                    path,
                    guarded_reason,
                    pair_authorized,
                    authority=self.effective_authority["value"],
                    trigger=authorization.GC_STOP,
                )
                status = "stopped" if stopped else "refused"
            else:
                try:
                    with self.store.decision_context(
                        "stop",
                        scope=scope,
                        authority=decision.authority or "unit",
                        mode=self.mode,
                        why=guarded_reason,
                    ) as audit:
                        report = engine.stop(
                            path,
                            self.cfg,
                            self.store,
                            unit,
                            hook=policy.hook_for(self.cfg, os.path.basename(path)),
                            decision_authority=decision.authority,
                            decision_why=guarded_reason,
                            decision_owner=audit.get("owner"),
                        )
                    stopped_pids = self.note_stop(report)
                    self.note_auto_stop(
                        scope,
                        guarded_reason,
                        [],
                        apps=self.stopped_apps(report, stopped_pids),
                        decision=audit,
                    )
                    status = "stopped" if report.get("removed") else "incomplete"
                except engine.Refused as error:
                    status = "refused"
                    attempted.append(
                        {"scope": scope, "status": status, "reason": str(error)}
                    )
                    continue
            attempted.append(
                {"scope": scope, "status": status, "current_bytes": current}
            )
            if status == "stopped":
                return {
                    "performed": 1,
                    "bytes_freed": current,
                    "scopes": [scope],
                    "results": attempted,
                }
        return {
            "performed": 0,
            "bytes_freed": 0,
            "scopes": [],
            "results": attempted,
        }

    def _finish_guard(self, outcome="pressure cleared"):
        """Record the completed pressure episode once its triggering pressure clears."""
        state = self.guard_state
        trigger_name = state.get("trigger")
        steps = list(state.get("steps", []))
        bytes_freed = int(state.get("bytes_freed", 0))
        duration_ms = round((time.monotonic() - self.guard_started_monotonic) * 1000, 2)
        state.update(
            active=False,
            last_trigger=trigger_name,
            last_bytes_freed=bytes_freed,
            last_duration_ms=duration_ms,
            retry_at=0.0,
        )
        state["trigger"] = None
        self.store.log(
            event="guard_finished",
            trigger=trigger_name,
            triggers=list(state.get("triggers", [])),
            steps=steps,
            bytes_freed=bytes_freed,
            duration_ms=duration_ms,
            outcome=outcome,
        )
        return state

    def guard_pass(self, trigger="retry"):
        """Run the ordered, cooldown-bounded memory-pressure ladder once."""
        if not self._guard_enabled():
            if self.guard_state.get("active"):
                return self._finish_guard("guard disabled")
            return None
        guard = self.cfg.get("guard", {})
        if not isinstance(guard, dict):
            return None
        if trigger in ("some", "full"):
            setting = guard.get(
                "psi_some" if trigger == "some" else "psi_full",
                policy._DEFAULTS["guard"][
                    "psi_some" if trigger == "some" else "psi_full"
                ],
            )
            try:
                _metric, _amount, window = pressure_guard.psi_trigger(trigger, setting)
                self.guard_trigger_until = max(
                    self.guard_trigger_until,
                    time.monotonic() + window / 1_000_000,
                )
            except ValueError:
                pass
        now = time.time()
        monotonic_now = time.monotonic()
        if not self._guard_pressure_high():
            if self.guard_state.get("active"):
                return self._finish_guard()
            return None
        state = self.guard_state
        if not state.get("active"):
            state.update(
                active=True,
                trigger=trigger,
                triggers=[trigger],
                started_at=now,
                steps=[],
                bytes_freed=0,
                retry_at=0.0,
            )
            self.guard_started_monotonic = monotonic_now
            self.store.log(
                event="guard_started",
                trigger=trigger,
                available_bytes=self._guard_floor()[0],
            )
        elif trigger not in state.get("triggers", []):
            state.setdefault("triggers", []).append(trigger)

        try:
            cooldown = max(0.0, float(guard.get("cooldown", 10)))
        except (TypeError, ValueError):
            cooldown = 10.0
        stages = (
            ("page_cache", lambda: self._guard_reclaim_step("page_cache")),
            ("freeze", self._guard_freeze_step),
            ("anonymous", lambda: self._guard_reclaim_step("anonymous")),
            ("stop", self._guard_stop_step),
        )
        for name, action in stages:
            if not self._guard_pressure_high():
                break
            last = self.guard_last_steps.get(name)
            if isinstance(last, (int, float)) and monotonic_now - last < cooldown:
                continue
            self.guard_last_steps[name] = monotonic_now
            before_available, _floor = self._guard_floor()
            started = time.monotonic()
            result = action()
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            after_available, _floor = self._guard_floor()
            freed = result.get("bytes_freed", 0)
            if (
                isinstance(before_available, int)
                and isinstance(after_available, int)
                and after_available > before_available
            ):
                freed = max(
                    freed if isinstance(freed, int) else 0,
                    after_available - before_available,
                )
            freed = freed if isinstance(freed, int) and freed >= 0 else 0
            step = {
                "step": name,
                "status": "acted" if result.get("performed", 0) else "skipped",
                "scopes": result.get("scopes", []),
                "bytes_freed": freed,
                "duration_ms": elapsed_ms,
                "reason": result.get("reason"),
            }
            state.setdefault("steps", []).append(step)
            state["bytes_freed"] = int(state.get("bytes_freed", 0)) + freed
            self.store.log(
                event="guard_step",
                trigger=state.get("trigger"),
                step=name,
                status=step["status"],
                scopes=step["scopes"],
                bytes_freed=freed,
                duration_ms=elapsed_ms,
                reason=step["reason"],
            )
            if not self._guard_pressure_high():
                break

        if self._guard_pressure_high():
            due = [
                value + cooldown
                for value in self.guard_last_steps.values()
                if isinstance(value, (int, float)) and value + cooldown > monotonic_now
            ]
            state["retry_at"] = (
                now + max(1.0, min(due) - monotonic_now) if due else now + 1.0
            )
            return state
        return self._finish_guard()

    def next_timeout(self, now=None):
        """Seconds until the next scheduled lifecycle or resource pass is due."""
        if self.collector_events:
            return 0.0
        now = time.time() if now is None else now
        due_times = [
            self.last["adopt"] + self.iv_adopt,
            self.last["gc"] + self.iv_gc,
            now + MAX_SLEEP,
        ] + [d[0] for d in self.deadlines]
        if self.last.get("freeze", 0.0):
            due_times.append(self.last["freeze"] + 60.0)
        if self._frozen_listener_scopes():
            due_times.append(self.last_listener_check + 2.0)
        due_times.extend(
            since + qos.DEBOUNCE_SECONDS
            for _candidate, since in self.qos_pending.values()
        )
        if self.qos_next_background_sample:
            due_times.append(self.qos_next_background_sample)
        for scope, record in self.store.data.get("qos_scopes", {}).items():
            if (
                not isinstance(record, dict)
                or record.get("active") is not True
                or record.get("controllers_ready", False)
            ):
                continue
            retry_at = record.get("controller_retry_at")
            if not isinstance(retry_at, (int, float)):
                continue
            candidate = self.qos_pending.get(scope)
            if candidate is not None:
                retry_at = candidate[1] + qos.DEBOUNCE_SECONDS
            due_times.append(retry_at)
        if self.mem_enabled:
            due_times.append(self.last.get("memory", now) + self.iv_memory)
        if self.memory_reclaim_enabled():
            due_times.append(self.last.get("reclaim", now) + self.iv_reclaim)
        if self._guard_enabled():
            due_times.append(self.last_guard_check + 1.0)
            if self.guard_state.get("active"):
                retry_at = self.guard_state.get("retry_at")
                if isinstance(retry_at, (int, float)) and retry_at > 0:
                    due_times.append(retry_at)
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
                now = time.time()
                self._run_listener_wake_if_due(now)
                self.store.log(event="store_busy", where="tick", retry=True)
                return
            self.guarded(self._sync_pressure_monitor)
            self.guarded(self.check_socket)
            self.guarded(self.store.apply_feedback)
            self.guarded(self.toggle_hold)
            self.guarded(self.thaw_held_scopes)
            self.run_deadlines()
            now = time.time()
            self._collect_available_floor_event(now)
            if self.guard_state.get("active") and now >= self.guard_state.get(
                "retry_at", float("inf")
            ):
                self.queue_collector_event(PressureHigh("retry"))
            self._run_listener_wake_if_due(now)
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
            if (
                self.memory_reclaim_enabled()
                and now - self.last.get("reclaim", 0.0) >= self.iv_reclaim
            ):
                if self.queue_collector_event(ReclaimReconcile()):
                    self.last["reclaim"] = now
            if now - self.last.get("freeze", 0.0) >= 60.0:
                self.last["freeze"] = now
                self.guarded(self.freeze_pass)
            self._run_listener_wake_if_due(now)
            self.drain_collector_events()
            self.guarded(self.qos_pass)
        finally:
            self._in_tick = False
            self.store.defer_writes = False
            if not skip_pass:
                self.guarded(self.store.save_if_dirty)
                self.guarded(self.store.export_daily_if_due)
            self._write_summary_if_dirty()

    def _memory_paths(self):
        """Return every real directory below this user's delegated cgroup boundary."""
        base = cgroup.base()
        paths = {}
        pending = list(cgroup.subdirs(base))
        while pending:
            path = pending.pop()
            scope = cgroup.rel(path)
            if scope == path or not cgroup.valid_rel(scope):
                continue
            paths[scope] = path
            pending.extend(cgroup.subdirs(path))
        return paths

    def _memory_scope_owned(self, scope, path):
        """Constrain control writes to directories owned by this uid under cgroup.base()."""
        base = cgroup.base()
        try:
            if os.path.commonpath((base, path)) != base:
                return False
            if cgroup.rel(path) != scope or not cgroup.valid_rel(scope):
                return False
            return os.stat(path, follow_symlinks=False).st_uid == os.getuid()
        except (OSError, ValueError):
            return False

    def _memory_targets(self, snapshot, now):
        """Resolve aggregate user scopes and their conservative resource classes."""
        paths = self._memory_paths()
        parents = set()
        for name in paths:
            parts = name.split("/")
            parents.update("/".join(parts[:index]) for index in range(1, len(parts)))
        rows = []
        idle_times = {**self.idle_since, **self.qos_idle_since}
        for observed in snapshot.get("scopes", []):
            scope = observed.get("name")
            path = paths.get(scope)
            if not isinstance(scope, str) or path is None:
                continue
            first = scope.split("/", 1)[0]
            descendants = scope in parents
            unit = engine.unit_for_leaf(self.units, os.path.basename(path))
            known_unit = "/" not in scope and unit is not None
            if known_unit:
                pass  # Named unit scopes may use any valid cgroup leaf name.
            elif "/" not in scope and scope.startswith(("app-", "scope-")):
                pass  # Aggregate application scopes are the primary accounting boundary.
            elif first in ("leftover", "shared") and not descendants:
                pass  # Treat each contained leaf as one independent budget target.
            elif scope == "manager" and not descendants:
                pass  # Account for the daemon without applying workload limits to it.
            else:
                continue

            metadata = unit.get("unit", {}) if isinstance(unit, dict) else {}
            unit_mem = unit.get("mem", {}) if isinstance(unit, dict) else {}
            if not isinstance(metadata, dict):
                metadata = {}
            if not isinstance(unit_mem, dict):
                unit_mem = {}
            raw_class = unit_mem.get(
                "class",
                metadata.get(
                    "mem_class",
                    metadata.get(
                        "qos_class", metadata.get("class", metadata.get("kind"))
                    ),
                ),
            )
            if raw_class in ("vm", "container", "app"):
                class_name = raw_class
            elif raw_class in ("interactive", "foreground"):
                class_name = "app"
            elif scope.startswith("app-") or scope.startswith("scope-"):
                class_name = "app"
            else:
                class_name = None
            resource_class = qos.classify(scope, idle_times, now)
            background = (
                raw_class == "background"
                or unit_mem.get("background") is True
                or resource_class in ("background", "leftover")
            )
            infrastructure = first in ("shared", "manager") or raw_class in (
                "infrastructure",
                "protected",
            )
            try:
                pids = cgroup.tree_procs(path)
                safety = self._qos_hard_safety(path, pids) if pids else ""
            except OSError:
                pids, safety = None, "scope process facts are unavailable"
            if safety:
                infrastructure = True
                background = False
            current = observed.get("current_bytes")
            rows.append(
                {
                    "name": scope,
                    "path": path,
                    "unit": unit,
                    "unit_mem": unit_mem,
                    "class": "infrastructure" if infrastructure else class_name,
                    "background": bool(background and not infrastructure),
                    "infrastructure": infrastructure,
                    "current_bytes": current,
                    "pids": pids,
                    "safety": safety,
                    "owned": self._memory_scope_owned(scope, path),
                }
            )
        return paths, rows

    @staticmethod
    def _memory_control(path, name):
        value = memory._read(os.path.join(path, name))
        return value.strip() if value is not None else None

    @staticmethod
    def _memory_numeric_limit(value):
        if value is None or value == "max":
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number if number >= 0 else None

    def _memory_budget_report(self, snapshot=None, now=None, _details=False):
        """Build the same live plan the periodic governor applies, without writing controls."""
        now = time.time() if now is None else float(now)
        if snapshot is None:
            snapshot = memory.snapshot(
                cfg=self.cfg, peak_cache=self.memory_peaks, now=now
            )
        if not snapshot.get("enabled"):
            result = {
                "schema": "taema.memory-budget.v1",
                "enabled": False,
                "manage": self.cfg.get("mem", {}).get("manage", "soft"),
                "budget_bytes": None,
                "floor_bytes": None,
                "allocatable_bytes": None,
                "delegated_max_bytes": None,
                "scopes": [],
            }
            return (result, {}, []) if _details else result

        config = self.cfg.get("mem", {})
        if not isinstance(config, dict):
            config = {}
        paths, rows = self._memory_targets(snapshot, now)
        host = snapshot.get("host") or {}
        total = host.get("total_bytes")
        delegated_value = self._memory_control(cgroup.base(), "memory.max")
        delegated = self._memory_numeric_limit(delegated_value)
        budget_known = (
            isinstance(total, int)
            and not isinstance(total, bool)
            and total > 0
            and (delegated_value == "max" or delegated is not None)
        )
        explicit = config.get("budget", "auto")
        if explicit == "auto":
            explicit_bytes = None
        else:
            try:
                explicit_bytes = memory.size_bytes(explicit)
            except ValueError:
                explicit_bytes = None
        try:
            floor = memory.size_bytes(config.get("floor", "512M"))
            minimum_headroom = memory.size_bytes(config.get("min_headroom", "128M"))
        except ValueError:
            floor = memory_budget.DEFAULT_AVAILABILITY_FLOOR
            minimum_headroom = memory_budget.DEFAULT_MIN_HEADROOM
        fraction = config.get("fraction", 0.80)
        budget = (
            memory_budget.budget_bytes(total, delegated, fraction, explicit_bytes)
            if budget_known
            else None
        )
        infrastructure = sum(
            row["current_bytes"] or 0
            for row in rows
            if row["infrastructure"] and isinstance(row["current_bytes"], int)
        )
        plan_rows = [
            memory_budget.BudgetScope(
                name=row["name"],
                class_name=row["class"],
                background=row["background"],
            )
            for row in rows
            if row["pids"]
        ]
        allocation = memory_budget.plan(
            budget if budget is not None else 0, floor, infrastructure, plan_rows
        )
        rendered = []
        for row in rows:
            scope = row["name"]
            current = row["current_bytes"]
            headroom = (
                memory_budget.headroom_bytes(
                    current, minimum_headroom, config.get("headroom_percent", 10)
                )
                if isinstance(current, int) and not isinstance(current, bool)
                else None
            )
            share = allocation.shares.get(row["name"]) if budget_known else None
            reservation = (
                allocation.reservations.get(row["name"]) if budget_known else None
            )
            desired_high = (
                max(current + headroom, share)
                if row["background"]
                and isinstance(current, int)
                and headroom is not None
                and share is not None
                else None
            )
            hard_cap = None
            if config.get("manage", "soft") == "hard":
                raw_cap = row["unit_mem"].get("max")
                if raw_cap is not None:
                    try:
                        hard_cap = memory.size_bytes(raw_cap)
                    except ValueError:
                        hard_cap = None
            swap_cap = None
            raw_swap_cap = row["unit_mem"].get("swap_max")
            if raw_swap_cap is not None:
                try:
                    swap_cap = memory.size_bytes(raw_swap_cap)
                except ValueError:
                    if row["class"] == "vm" and scope not in self.saved_vm_scopes:
                        swap_cap = 0
            elif row["class"] == "vm" and scope not in self.saved_vm_scopes:
                swap_cap = 0
            managed_state = self.store.data.get("memory_scopes", {})
            managed_scope = (
                managed_state.get(row["name"], {})
                if isinstance(managed_state, dict)
                else {}
            )
            if not isinstance(managed_scope, dict):
                managed_scope = {}
            rendered.append(
                {
                    "name": row["name"],
                    "class": row["class"] or "unknown",
                    "background": row["background"],
                    "current_bytes": current,
                    "headroom_bytes": headroom,
                    "share_bytes": share,
                    "reservation_bytes": reservation,
                    "desired_high_bytes": desired_high,
                    "desired_low_bytes": reservation,
                    "desired_max_bytes": hard_cap,
                    "desired_swap_max_bytes": swap_cap,
                    "high": self._memory_control(row["path"], "memory.high"),
                    "low": self._memory_control(row["path"], "memory.low"),
                    "max": self._memory_control(row["path"], "memory.max"),
                    "swap_max": self._memory_control(row["path"], "memory.swap.max"),
                    "owned": row["owned"],
                    "managed": sorted(
                        key
                        for key in managed_scope
                        if key
                        in (
                            "memory.high",
                            "memory.low",
                            "memory.max",
                            "memory.swap.max",
                        )
                    ),
                }
            )
        result = {
            "schema": "taema.memory-budget.v1",
            "enabled": True,
            "manage": config.get("manage", "soft"),
            "budget_bytes": budget,
            "floor_bytes": floor,
            "allocatable_bytes": (
                allocation.allocatable_bytes if budget_known else None
            ),
            "delegated_max_bytes": delegated,
            "fraction": fraction,
            "infrastructure_bytes": allocation.infrastructure_bytes,
            "reserved_bytes": allocation.reserved_bytes,
            "background_bytes": allocation.background_bytes,
            "scopes": rendered,
        }
        return (result, paths, rows) if _details else result

    def _memory_control_state(self):
        state = self.store.data.get("memory_scopes")
        if not isinstance(state, dict):
            state = {}
            self.store.data["memory_scopes"] = state
            self.store.dirty = True
        return state

    def _memory_apply_control(
        self, scope, path, name, target, *, soft_threshold=False, minimum_target=None
    ):
        if not self._memory_scope_owned(scope, path):
            return False
        states = self._memory_control_state()
        scope_state = states.get(scope)
        if not isinstance(scope_state, dict):
            scope_state = {}
        record = scope_state.get(name)
        current = self._memory_control(path, name)
        if current is None:
            return False
        desired = str(target)
        current_limit = self._memory_numeric_limit(current)
        below_minimum = minimum_target is not None and (
            current_limit is None or current_limit < minimum_target
        )
        within_soft_threshold = (
            soft_threshold
            and not memory_budget.materially_changed(current, target)
            and not below_minimum
        )
        if isinstance(record, dict):
            if record.get("blocked") is True:
                return False
            if current != record.get("applied"):
                if record.get("blocked") is not True:
                    record["blocked"] = True
                    self.store.dirty = True
                    self.store.log(
                        event="memory_control_external_change",
                        scope=scope,
                        control=name,
                        current=current,
                    )
                return False
            if (
                current == desired
                or record.get("requested") == desired
                or within_soft_threshold
            ):
                return True
            original = record.get("original", current)
        else:
            if current == desired or within_soft_threshold:
                return True
            original = current
        try:
            memory._write_control(path, name, desired)
        except OSError as error:
            reason = str(error)
            if self.store.changed(f"memory_budget_failed:{scope}:{name}:apply", reason):
                self.store.log(
                    event="memory_budget_failed",
                    scope=scope,
                    control=name,
                    reason=reason,
                )
            return False
        applied = self._memory_control(path, name)
        if applied is None:
            applied = desired
        states[scope] = scope_state
        scope_state[name] = {
            "original": original,
            "requested": desired,
            "applied": applied,
        }
        self.store.dirty = True
        self.store.log(
            event="memory_budget_applied",
            scope=scope,
            control=name,
            old=current,
            new=applied,
        )
        return True

    def _memory_restore_control(self, scope, path, name):
        states = self._memory_control_state()
        scope_state = states.get(scope)
        record = scope_state.get(name) if isinstance(scope_state, dict) else None
        if not isinstance(record, dict):
            return True
        if not self._memory_scope_owned(scope, path):
            states.pop(scope, None)
            self.store.dirty = True
            return False
        if record.get("blocked") is True:
            return False
        current = self._memory_control(path, name)
        if current is None:
            return False
        if current != record.get("applied"):
            record["blocked"] = True
            self.store.dirty = True
            self.store.log(
                event="memory_control_external_change",
                scope=scope,
                control=name,
                current=current,
            )
            return False
        try:
            memory._write_control(path, name, record.get("original", "max"))
        except OSError as error:
            reason = str(error)
            if self.store.changed(
                f"memory_budget_failed:{scope}:{name}:restore", reason
            ):
                self.store.log(
                    event="memory_budget_failed",
                    scope=scope,
                    control=name,
                    reason=reason,
                )
            return False
        scope_state.pop(name, None)
        if not scope_state:
            states.pop(scope, None)
        self.store.dirty = True
        self.store.log(
            event="memory_control_restored",
            scope=scope,
            control=name,
            value=record.get("original", "max"),
        )
        return True

    def _memory_restore_scope(self, scope, path):
        for name in (
            "memory.high",
            "memory.low",
            "memory.max",
            "memory.swap.max",
        ):
            self._memory_restore_control(scope, path, name)

    def _enable_memory_controllers(self, scope, path):
        ready = True
        for parent in self._qos_controller_parents(path):
            reason = qos.enable_controllers(parent, required=("memory",))
            if reason:
                ready = False
                if self.store.changed("memory_controller:" + parent, reason):
                    self.store.log(
                        event="memory_controller_unavailable",
                        scope=scope,
                        parent=cgroup.rel(parent),
                        reason=reason,
                    )
        return ready

    def memory_governor_pass(self, now=None, snapshot=None, force_restore=False):
        """Reconcile reversible scope limits from one bounded accounting snapshot."""
        now = time.time() if now is None else float(now)
        states = self._memory_control_state()
        if force_restore or not memory.enabled(self.cfg):
            paths = self._memory_paths()
            for scope, state in list(states.items()):
                path = paths.get(scope)
                if path is not None and self._memory_scope_owned(scope, path):
                    self._memory_restore_scope(scope, path)
                else:
                    states.pop(scope, None)
                    self.store.dirty = True
            self.memory_scope_seen.clear()
            self.memory_scope_allocations.clear()
            return {"restored": True, "scopes": []}

        if not states and not any(
            os.path.isfile(os.path.join(cgroup.base(), name))
            for name in (
                "memory.high",
                "memory.low",
                "memory.max",
                "memory.swap.max",
            )
        ):
            self.memory_scope_seen.clear()
            self.memory_scope_allocations.clear()
            return {"enabled": True, "scopes": []}

        report, observed_paths, rows = self._memory_budget_report(
            snapshot=snapshot, now=now, _details=True
        )
        row_data = {row["name"]: row for row in report["scopes"]}
        resumed = self._reconcile_saved_vm_scopes(rows)
        for row in rows:
            scope = row["name"]
            if (
                scope in resumed
                and row["class"] == "vm"
                and row["unit_mem"].get("swap_max") is None
            ):
                row_data[scope]["desired_swap_max_bytes"] = 0
        active = {row["name"] for row in rows if row["pids"]}
        exited = self.memory_scope_seen - active
        stale = {scope for scope in states if scope not in observed_paths}
        released = exited | stale
        for scope in sorted(released):
            released_bytes = self.memory_scope_allocations.get(scope, 0)
            scope_state = states.get(scope, {})
            if not released_bytes and isinstance(scope_state, dict):
                released_bytes = max(
                    (
                        self._memory_numeric_limit(record.get("applied")) or 0
                        for record in scope_state.values()
                        if isinstance(record, dict)
                    ),
                    default=0,
                )
            self.store.log(
                event="rebalance",
                scope=scope,
                released_bytes=released_bytes,
                remaining_scopes=len(active),
            )
        # A restarted daemon has no in-memory active set. Persisted ownership records
        # still tell us that an empty scope needs its reservation released and logged.
        for row in rows:
            scope = row["name"]
            if (
                row["pids"] == []
                and scope in states
                and scope not in released
                and self.store.changed("memory_rebalance_empty:" + scope, True)
            ):
                scope_state = states.get(scope, {})
                released_bytes = (
                    max(
                        (
                            self._memory_numeric_limit(record.get("applied")) or 0
                            for record in scope_state.values()
                            if isinstance(record, dict)
                        ),
                        default=0,
                    )
                    if isinstance(scope_state, dict)
                    else 0
                )
                self.store.log(
                    event="rebalance",
                    scope=scope,
                    released_bytes=released_bytes,
                    remaining_scopes=len(active),
                )
        self.memory_scope_allocations = {
            row["name"]: row_data.get(row["name"], {}).get("reservation_bytes")
            or row_data.get(row["name"], {}).get("share_bytes")
            or 0
            for row in rows
            if row["pids"]
        }
        for scope in sorted(exited):
            path = observed_paths.get(scope)
            if path is not None and self._memory_scope_owned(scope, path):
                self._memory_restore_scope(scope, path)
        self.memory_scope_seen = active

        for scope in tuple(states):
            if scope not in observed_paths:
                states.pop(scope, None)
                self.store.dirty = True

        config = self.cfg.get("mem", {})
        if not isinstance(config, dict):
            config = {}
        manage = config.get("manage", "soft")
        for row in rows:
            scope, path = row["name"], row["path"]
            plan_row = row_data.get(scope, {})
            if not row["owned"]:
                if self.store.changed("memory_unowned:" + scope, True):
                    self.store.log(
                        event="memory_scope_refused",
                        scope=scope,
                        reason="scope is outside user-owned cgroup controls",
                    )
                if states.pop(scope, None) is not None:
                    self.store.dirty = True
                continue
            if not row["pids"]:
                self._memory_restore_scope(scope, path)
                continue
            if row["pids"] is None or row["safety"] or row["current_bytes"] is None:
                self._memory_restore_scope(scope, path)
                continue

            decision = self.authorize(
                authorization.RECLAIM,
                authorization.Facts(scope=scope, hard_safety=row["safety"]),
            )
            if decision.verdict != authorization.ACT:
                if decision.verdict == authorization.WOULD_ACT and self.store.changed(
                    "memory_budget_would:" + scope,
                    (
                        plan_row.get("desired_high_bytes"),
                        plan_row.get("desired_low_bytes"),
                        plan_row.get("desired_max_bytes"),
                        plan_row.get("desired_swap_max_bytes"),
                    ),
                ):
                    self.store.log(
                        event="memory_budget_would",
                        scope=scope,
                        high=plan_row.get("desired_high_bytes"),
                        low=plan_row.get("desired_low_bytes"),
                        max=plan_row.get("desired_max_bytes"),
                        swap_max=plan_row.get("desired_swap_max_bytes"),
                        reason=decision.reason,
                    )
                self._memory_restore_scope(scope, path)
                continue

            wants_controls = any(
                plan_row.get(key) is not None
                for key in (
                    "desired_high_bytes",
                    "desired_low_bytes",
                    "desired_max_bytes",
                    "desired_swap_max_bytes",
                )
            )
            if wants_controls and not any(
                os.path.isfile(os.path.join(path, name))
                for name in (
                    "memory.high",
                    "memory.low",
                    "memory.max",
                    "memory.swap.max",
                )
            ):
                self._enable_memory_controllers(scope, path)

            desired_max = None
            if manage == "hard" and row["unit_mem"].get("max") is not None:
                desired_max = plan_row.get("desired_max_bytes")
                headroom = plan_row.get("headroom_bytes")
                if desired_max is None:
                    if self.store.changed(
                        "memory_cap_invalid:" + scope, repr(row["unit_mem"].get("max"))
                    ):
                        self.store.log(
                            event="memory_cap_refused",
                            scope=scope,
                            reason="unit mem.max must be a valid binary size",
                        )
                elif headroom is None or desired_max < row["current_bytes"] + headroom:
                    if self.store.changed(
                        "memory_cap_refused:" + scope,
                        (desired_max, row["current_bytes"], headroom),
                    ):
                        self.store.log(
                            event="memory_cap_refused",
                            scope=scope,
                            cap=desired_max,
                            current=row["current_bytes"],
                            headroom=headroom,
                            reason="cap is below current usage plus required headroom",
                        )
                    desired_max = None
            if desired_max is not None:
                self._memory_apply_control(scope, path, "memory.max", desired_max)
            else:
                self._memory_restore_control(scope, path, "memory.max")

            raw_swap_max = row["unit_mem"].get("swap_max")
            if raw_swap_max is not None:
                try:
                    memory.size_bytes(raw_swap_max)
                except ValueError:
                    if self.store.changed(
                        "memory_swap_cap_invalid:" + scope, repr(raw_swap_max)
                    ):
                        self.store.log(
                            event="memory_swap_cap_refused",
                            scope=scope,
                            value=raw_swap_max,
                            reason="unit mem.swap_max must be a valid binary size",
                        )
            desired_swap_max = plan_row.get("desired_swap_max_bytes")
            if desired_swap_max is not None:
                self._memory_apply_control(
                    scope, path, "memory.swap.max", desired_swap_max
                )
            else:
                self._memory_restore_control(scope, path, "memory.swap.max")

            desired_low = plan_row.get("desired_low_bytes")
            if desired_low is not None and not row["background"]:
                try:
                    desired_low = memory_budget.align_up(
                        desired_low, int(os.sysconf("SC_PAGE_SIZE"))
                    )
                except (OSError, ValueError):
                    pass
                self._memory_apply_control(scope, path, "memory.low", desired_low)
            else:
                self._memory_restore_control(scope, path, "memory.low")

            desired_high = plan_row.get("desired_high_bytes")
            if desired_high is not None and row["background"]:
                try:
                    page_size = int(os.sysconf("SC_PAGE_SIZE"))
                    desired_high = memory_budget.align_up(desired_high, page_size)
                except (OSError, ValueError):
                    pass
                self._memory_apply_control(
                    scope,
                    path,
                    "memory.high",
                    desired_high,
                    soft_threshold=True,
                    minimum_target=row["current_bytes"] + plan_row["headroom_bytes"],
                )
            else:
                self._memory_restore_control(scope, path, "memory.high")

        return report

    def memory_pass(self, now=None):
        """Sample live cgroups and persist only material changes or the 10-minute heartbeat."""
        if not memory.enabled(self.cfg):
            self.memory_governor_pass(now=now, force_restore=True)
            return 0
        now = time.time() if now is None else float(now)
        snapshot = memory.snapshot(cfg=self.cfg, peak_cache=self.memory_peaks, now=now)
        self.memory_governor_pass(now=now, snapshot=snapshot)
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

    def mark_vm_saved(self, scope):
        """Allow anonymous reclaim for a VM after its configured save hook succeeds."""
        if isinstance(scope, str) and cgroup.valid_rel(scope):
            self.saved_vm_scopes.add(scope)
            path = os.path.join(cgroup.base(), scope)
            pids = cgroup.tree_procs(path) if os.path.isdir(path) else None
            self.saved_vm_members[scope] = (
                frozenset(pids) if isinstance(pids, list) else None
            )

    def mark_vm_resumed(self, scope):
        """Restore the VM swap guard after a saved guest resumes."""
        if isinstance(scope, str):
            self.saved_vm_scopes.discard(scope)
            self.saved_vm_members.pop(scope, None)

    def _reconcile_saved_vm_scopes(self, rows):
        """Forget save authorization when a VM scope is replaced by new members."""
        observed = {row["name"] for row in rows}
        resumed = set()
        for scope in tuple(self.saved_vm_scopes):
            if scope not in observed:
                self.mark_vm_resumed(scope)
        for row in rows:
            scope = row["name"]
            pids = row.get("pids")
            if (
                scope not in self.saved_vm_scopes
                or not isinstance(pids, list)
                or not pids
            ):
                continue
            expected = self.saved_vm_members.get(scope)
            current = frozenset(pids)
            if expected is None:
                self.saved_vm_members[scope] = current
            elif current != expected:
                self.mark_vm_resumed(scope)
                resumed.add(scope)
        return resumed

    def _vm_save_hook_authority(self, scope, path, unit):
        """Require the lifecycle stop policy before running a potentially destructive hook."""
        metadata = (unit or {}).get("unit", {})
        unit_stop_allowed = (
            isinstance(metadata, dict) and metadata.get("stop_when_unneeded") is True
        )
        leftover = scope.startswith(engine.LEFTOVER + "/")
        facts = (
            self._pair_scope_facts(path)
            if leftover and self.mode in ("adopt", "auto")
            else authorization.Facts(scope=scope, leftover=leftover)
        )
        decision = self.authorize(authorization.GC_STOP, facts)
        pair_stop_allowed = (
            leftover
            and self.mode in ("adopt", "auto")
            and facts.pair_action in ("stop", "expiry")
        )
        if decision.verdict != authorization.ACT:
            return False, decision.reason
        if not unit_stop_allowed and not pair_stop_allowed:
            return (
                False,
                "unit stop_when_unneeded or authorized leftover stop is required",
            )
        return True, decision.reason

    def _run_vm_save_hook(self, scope, unit, now):
        """Run an explicitly configured save command without invoking a shell."""
        unit_mem = (unit or {}).get("mem", {})
        metadata = (unit or {}).get("unit", {})
        if not isinstance(unit_mem, dict) or not isinstance(metadata, dict):
            return False, "VM save hook configuration is invalid"
        command = unit_mem.get("save_state")
        if not isinstance(command, str) or not command.strip():
            return False, "no VM save hook is configured"
        previous = self.memory_save_attempts.get(scope)
        cooldown = float(self.cfg.get("mem", {}).get("reclaim_cooldown", 300))
        if isinstance(previous, (int, float)) and now - previous < cooldown:
            return False, "VM save hook cooldown has %ds remaining" % int(
                cooldown - (now - previous)
            )
        try:
            argv = shlex.split(command)
        except ValueError as error:
            return False, "VM save hook command is invalid: %s" % error
        fields = {
            "name": metadata.get("name"),
            "domain": metadata.get("domain"),
            "container": metadata.get("container_id"),
        }
        for index, item in enumerate(argv):
            for key, value in fields.items():
                marker = "%%(%s)s" % key
                if marker in item:
                    if not isinstance(value, str) or not value:
                        return False, "VM save hook needs unit.%s" % key
                    item = item.replace(marker, value)
            if re.search(r"%\([^)]*\)[a-zA-Z]", item):
                return False, "VM save hook contains an unsupported template field"
            argv[index] = item
        if not argv:
            return False, "VM save hook command is empty"
        self.memory_save_attempts[scope] = now
        try:
            process = subprocess.Popen(
                argv,
                start_new_session=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                output, _ = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                output, _ = process.communicate()
                reason = "VM save hook timed out after 30 seconds"
                success = False
            else:
                reason = (
                    ""
                    if process.returncode == 0
                    else "VM save hook exited %d" % process.returncode
                )
                success = process.returncode == 0
        except OSError as error:
            output = ""
            reason = "VM save hook could not run: %s" % error
            success = False
        self.store.log(
            event="memory_save_state",
            scope=scope,
            hook=argv[0],
            success=success,
            reason=reason or None,
            output=(output or "")[:4096],
            output_truncated=len(output or "") > 4096,
        )
        if success:
            self.mark_vm_saved(scope)
            return True, "VM save hook succeeded"
        return False, reason

    def _reclaim_class(self, scope, path):
        """Resolve the deliberately small set of scope classes eligible for idle reclaim."""
        if scope == "manager" or scope.startswith("manager/"):
            return None
        if scope.startswith("leftover/"):
            return "leftover"
        unit = engine.unit_for_leaf(self.units, os.path.basename(path))
        metadata = (unit or {}).get("unit", {})
        unit_mem = (unit or {}).get("mem", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if not isinstance(unit_mem, dict):
            unit_mem = {}
        unit_gc = (unit or {}).get("gc", {})
        resource_class = unit_mem.get(
            "class",
            metadata.get("mem_class", metadata.get("qos_class", metadata.get("class"))),
        )
        bundled_podman = (
            metadata.get("name") == "app-podman"
            and metadata.get("kind") == "app"
            and metadata.get("group_by_env") == "XDG_RUNTIME_DIR"
            and unit_gc.get("keep_while_children") is True
            and scope.startswith("app-podman-")
        )
        if resource_class == "vm" or metadata.get("kind") == "vm":
            return "vm"
        if (
            resource_class == "container"
            or metadata.get("kind") == "container"
            or bundled_podman
            or scope == "container"
            or scope.startswith(("container/", "container-", "app-container-"))
        ):
            return "container"
        if resource_class == "background" or scope in self.qos_idle_since:
            return "background"
        return None

    def _reclaim_safety_reason(self, scope, path, pids):
        if scope == "manager" or scope.startswith("manager/"):
            return "manager scope is never reclaimed"
        if os.getpid() in pids or cgroup.is_prefix(path, cgroup.own_cgroup()):
            return "scope contains the daemon"
        if not pids:
            return "scope is empty"
        infos = self._infos(pids)
        if {info.get("pid") for info in infos} != set(pids):
            return "member safety facts are unavailable"
        for info in infos:
            pid = info["pid"]
            if info.get("protected"):
                return "protected member: %s" % info["protected"]
            if info.get("ptmx"):
                return "pty host"
            if info.get("edges") is None:
                return "dependency edges are unknown"
            if info["edges"]:
                return "scope has external dependency edges"
            if inspect.uid_of(pid) != os.getuid():
                return "scope contains a process owned by another uid"
        return ""

    def _reclaim_warm(self, scope, path, now, cooldown):
        state = self.reclaim_state.get(scope)
        if not isinstance(state, dict):
            return False
        warm_until = state.get("warm_until")
        if (
            state.get("warm") is True
            and isinstance(warm_until, (int, float))
            and now >= warm_until
        ):
            state["warm"] = False
            state["warm_until"] = None
        last = state.get("last_at")
        if not isinstance(last, (int, float)) or now - last > cooldown:
            return state.get("warm") is True
        counters = memory.scope_counters(path)
        if counters is None:
            return state.get("warm") is True
        refaulted = False
        for name, stored in (
            ("workingset_refault_file", "refault_file"),
            ("workingset_refault_anon", "refault_anon"),
            ("pgmajfault", "major_faults"),
            ("high_events", "high_events"),
        ):
            current = counters.get(name)
            previous = state.get(stored)
            if isinstance(current, int) and isinstance(previous, int):
                if current > previous:
                    refaulted = True
                if current != previous:
                    state[stored] = current
        if refaulted:
            was_warm = state.get("warm") is True
            state["warm"] = True
            warm_until = state.get("warm_until")
            state["warm_until"] = max(
                now + (2 * cooldown),
                warm_until if isinstance(warm_until, (int, float)) else 0,
            )
            if self.store.changed("reclaim_warm:" + scope, state["warm_until"]):
                self.store.log(
                    event="memory_scope_warm",
                    scope=scope,
                    reason="file refault or major fault followed reclaim",
                    warm_grace_multiplier=2,
                    suppress_until=state["warm_until"],
                    repeated=was_warm,
                )
        return state.get("warm") is True

    def _reclaim_idle(self, scope, path, now, warm, grace):
        usage = engine._cpu_usage(path)
        previous = self.reclaim_usage.get(scope)
        if usage is None:
            self.reclaim_usage.pop(scope, None)
            self.reclaim_idle_since.pop(scope, None)
            return False, "CPU usage is unavailable"
        self.reclaim_usage[scope] = (usage, now)
        if previous is None or now <= previous[1]:
            self.reclaim_idle_since[scope] = now
            return False, "waiting for a second idle sample"
        elapsed = now - previous[1]
        if usage < previous[0]:
            self.reclaim_idle_since[scope] = now
            return False, "CPU counter changed"
        if elapsed < qos.BACKGROUND_SAMPLE_SECONDS:
            return False, "waiting for a stable CPU sample"
        cpu_percent = 100.0 * (usage - previous[0]) / (elapsed * 1_000_000)
        if cpu_percent > RECLAIM_CPU_PERCENT:
            self.reclaim_idle_since[scope] = now
            return False, "scope is active (%.2f%% CPU)" % cpu_percent
        idle_since = self.reclaim_idle_since.setdefault(scope, previous[1])
        effective_grace = grace * (2 if warm else 1)
        if now - idle_since < effective_grace:
            return (
                False,
                "idle for %ds; needs %ds%s"
                % (
                    int(now - idle_since),
                    int(effective_grace),
                    " (warm scope)" if warm else "",
                ),
            )
        return True, "idle for %ds" % int(now - idle_since)

    def _reclaim_one(
        self,
        scope,
        path,
        now,
        host_pressure,
        *,
        manual=False,
        force_veto=False,
        dry_run=False,
        resource_class=None,
        guard=False,
        stage="all",
    ):
        if stage not in ("all", "page_cache", "anonymous"):
            return {
                "scope": scope,
                "status": "failed",
                "reason": "invalid reclaim stage",
            }
        config = self.cfg.get("mem", {})
        if (
            not memory.enabled(self.cfg)
            or not isinstance(config, dict)
            or config.get("reclaim", True) is not True
        ):
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "reclaim is disabled",
            }
        pids = cgroup.tree_procs(path)
        safety = self._reclaim_safety_reason(scope, path, pids)
        if safety:
            return {"scope": scope, "status": "skipped", "reason": safety}

        cooldown = float(config.get("reclaim_cooldown", 300))
        warm = self._reclaim_warm(scope, path, now, cooldown)
        state = self.reclaim_state.get(scope, {})
        warm_until = state.get("warm_until") if isinstance(state, dict) else None
        if isinstance(warm_until, (int, float)) and now < warm_until:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "scope is warm; reclaim suppressed for %ds"
                % int(warm_until - now),
            }
        managed_frozen = (
            isinstance(self.store.data.get("frozen_scopes"), dict)
            and scope in self.store.data["frozen_scopes"]
            and self._freeze_value(path) == "1"
        )
        if stage == "anonymous" and not managed_frozen:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "guard anonymous reclaim requires a taema-frozen scope",
            }
        idle_eligible = managed_frozen
        idle_reason = "scope is frozen by taema" if managed_frozen else ""
        idle_grace_met = False
        if not manual and not managed_frozen:
            idle, reason = self._reclaim_idle(
                scope,
                path,
                now,
                warm,
                float(config.get("idle_reclaim_grace", 300)),
            )
            if not idle:
                return {"scope": scope, "status": "skipped", "reason": reason}
            idle_eligible, idle_reason = True, reason
            idle_grace_met = True

        state = self.reclaim_state.get(scope, {})
        last = state.get("last_at") if isinstance(state, dict) else None
        if not guard and isinstance(last, (int, float)) and now - last < cooldown:
            remaining = int(cooldown - (now - last))
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "reclaim cooldown has %ds remaining" % remaining,
            }

        pressure = host_pressure or memory.pressure()
        if not guard:
            full = pressure.get("full_avg10")
            ceiling = config.get("pressure_ceiling", 60)
            if full is None:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "full memory pressure is unavailable",
                }
            if full > ceiling:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "full memory pressure %.2f%% exceeds %.2f%%"
                    % (full, ceiling),
                }
            local_full = memory.pressure(os.path.join(path, "memory.pressure"))[
                "full_avg10"
            ]
            if local_full is not None and local_full > ceiling:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "scope full memory pressure %.2f%% exceeds %.2f%%"
                    % (local_full, ceiling),
                }
        if not manual and not guard:
            some = pressure.get("some_avg10")
            gate = config.get("pressure_gate", 10)
            if some is None or some < gate:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "global some pressure is below the reclaim gate",
                }

        facts = authorization.Facts(
            scope=scope,
            hard_safety="",
            force_veto=bool(force_veto),
        )
        trigger = authorization.MANUAL_RECLAIM if manual else authorization.RECLAIM
        decision = self.authorize(trigger, facts)
        if decision.verdict == authorization.WOULD_ACT:
            result = {
                "scope": scope,
                "status": "would",
                "reason": decision.reason,
            }
            if not dry_run and self.store.changed(
                "reclaim_would:" + scope, decision.reason
            ):
                self.store.log(
                    event="memory_reclaim_would",
                    scope=scope,
                    reason=decision.reason,
                    resource_class=resource_class,
                )
            return result
        if decision.verdict != authorization.ACT:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": decision.reason,
            }

        counters = memory.scope_counters(path)
        if not isinstance(counters, dict):
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "memory usage statistics are unavailable",
            }
        if not manual and counters.get("workingset_refault_file") is None:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "file refault counters are unavailable",
            }
        if manual and not managed_frozen:
            idle_eligible, idle_reason = self._reclaim_idle(
                scope,
                path,
                now,
                warm,
                float(config.get("idle_reclaim_grace", 300)),
            )
            idle_grace_met = idle_eligible
        unit = engine.unit_for_leaf(self.units, os.path.basename(path))
        unit_mem = (unit or {}).get("mem", {})
        if not isinstance(unit_mem, dict):
            unit_mem = {}
        swap_enabled = config.get("swap_reclaim", True) is True
        if self.mode == "adopt" and config.get("swap_reclaim_adopt", False) is not True:
            swap_enabled = False
        eligible_class = resource_class in {
            "background",
            "leftover",
            "container",
            "vm",
        }
        save_required = (
            stage != "page_cache"
            and resource_class == "vm"
            and unit_mem.get("swap_max") is None
            and unit_mem.get("save_state")
            and scope not in self.saved_vm_scopes
        )
        if save_required and swap_enabled and eligible_class and not dry_run:
            save_allowed, save_authority_reason = self._vm_save_hook_authority(
                scope, path, unit
            )
            if not save_allowed:
                if self.store.changed(
                    "memory_save_state_refused:" + scope, save_authority_reason
                ):
                    self.store.log(
                        event="memory_save_state_refused",
                        scope=scope,
                        reason=save_authority_reason,
                    )
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "VM save hook lacks stop authority: "
                    + save_authority_reason,
                }
            if not idle_grace_met:
                idle_eligible, idle_reason = self._reclaim_idle(
                    scope,
                    path,
                    now,
                    warm,
                    float(config.get("idle_reclaim_grace", 300)),
                )
                idle_grace_met = idle_eligible
            if not idle_grace_met:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "VM save hook requires idle grace: " + idle_reason,
                }
            safety = self._reclaim_safety_reason(scope, path, cgroup.tree_procs(path))
            if safety:
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "VM save hook blocked by safety check: " + safety,
                }
            saved, save_reason = self._run_vm_save_hook(scope, unit, now)
            if saved:
                self._memory_restore_control(scope, path, "memory.swap.max")
                safety = self._reclaim_safety_reason(
                    scope, path, cgroup.tree_procs(path)
                )
                if safety:
                    return {
                        "scope": scope,
                        "status": "skipped",
                        "reason": "save hook changed scope safety: " + safety,
                    }
                counters = memory.scope_counters(path)
                if not isinstance(counters, dict):
                    return {
                        "scope": scope,
                        "status": "skipped",
                        "reason": "memory usage statistics are unavailable after VM save",
                    }
            else:
                if self.store.changed(
                    "memory_save_state_refused:" + scope, save_reason
                ):
                    self.store.log(
                        event="memory_save_state_refused",
                        scope=scope,
                        reason=save_reason,
                    )
                return {
                    "scope": scope,
                    "status": "skipped",
                    "reason": "VM save hook failed: " + save_reason,
                }
        try:
            maximum = memory.size_bytes(config.get("reclaim_max", "2G"))
            minimum = memory.size_bytes(config.get("reclaim_minimum", "16M"))
            headroom = memory.size_bytes(config.get("min_headroom", "128M"))
            percent = config.get("headroom_percent", 10)
        except ValueError as error:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": "invalid memory reclaim configuration: %s" % error,
            }
        bounds = memory.ReclaimBounds(maximum, headroom, percent, minimum)
        amount = (
            0
            if stage == "anonymous"
            else memory.page_cache_budget(
                counters.get("current_bytes"),
                counters.get("anon_bytes"),
                counters.get("reclaimable_bytes"),
                bounds,
            )
        )
        anon_amount = 0
        anon_block_reason = ""
        if stage == "page_cache":
            anon_block_reason = "anonymous reclaim is not part of the page-cache step"
        elif not swap_enabled:
            anon_block_reason = (
                "anonymous swap reclaim needs mem.swap_reclaim and, in adopt, "
                "mem.swap_reclaim_adopt"
            )
        elif not eligible_class:
            anon_block_reason = "scope class is not eligible for anonymous reclaim"
        elif not idle_eligible:
            anon_block_reason = (
                "anonymous reclaim requires an idle or taema-frozen scope"
            )
        elif counters.get("anon_bytes") is None or counters.get("swap_bytes") is None:
            anon_block_reason = "anonymous or swap usage is unavailable"
        else:
            raw_swap_limit = memory.swap_limit(path)
            if raw_swap_limit is None:
                anon_block_reason = "scope swap limit is unavailable"
            elif raw_swap_limit != "max" and not isinstance(raw_swap_limit, int):
                anon_block_reason = "scope swap limit is invalid"
            else:
                swap_cap = None if raw_swap_limit == "max" else raw_swap_limit
                if resource_class == "vm":
                    raw_vm_swap_cap = unit_mem.get("swap_max")
                    vm_saved = scope in self.saved_vm_scopes
                    if raw_vm_swap_cap is None and not vm_saved:
                        swap_cap = 0
                        anon_block_reason = (
                            "VM anonymous reclaim requires unit mem.swap_max or "
                            "a successful save hook"
                        )
                    elif raw_vm_swap_cap is not None:
                        try:
                            configured_cap = memory.size_bytes(raw_vm_swap_cap)
                            swap_cap = (
                                configured_cap
                                if swap_cap is None
                                else min(swap_cap, configured_cap)
                            )
                        except ValueError:
                            anon_block_reason = "VM mem.swap_max is invalid"
                available_swap = memory.swap_available_bytes()
                if not anon_block_reason and available_swap is None:
                    anon_block_reason = "host swap availability is unknown"
                if not anon_block_reason:
                    anon_amount = memory.anonymous_reclaim_budget(
                        max(0, counters["current_bytes"] - amount),
                        counters.get("anon_bytes"),
                        counters.get("swap_bytes"),
                        swap_cap,
                        available_swap,
                        replace(bounds, maximum_bytes=max(0, maximum - amount)),
                    )
                    if anon_amount <= 0:
                        anon_block_reason = (
                            "no useful anonymous memory fits swap and headroom limits"
                        )
        if amount <= 0 and anon_amount <= 0:
            return {
                "scope": scope,
                "status": "skipped",
                "reason": anon_block_reason
                or "no useful page cache remains above headroom",
            }

        requested = amount + anon_amount
        result = {
            "scope": scope,
            "status": "would" if dry_run else "reclaimed",
            "requested_bytes": requested,
            "page_cache_requested_bytes": amount,
            "anonymous_requested_bytes": anon_amount,
            "current_before": counters["current_bytes"],
            "reclaimable_before": counters["reclaimable_bytes"],
            "resource_class": resource_class,
            "anonymous_reclaim_reason": anon_block_reason or None,
        }
        if dry_run:
            return result

        matched_veto = (
            engine.veto_for_scope(self.store, path, unit=unit) if force_veto else None
        )
        started = time.monotonic()
        methods = []
        errors = []
        try:
            with self.store.decision_context(
                "reclaim",
                scope=scope,
                authority=decision.authority or ("manual" if manual else "mode"),
                mode=self.mode,
                why=decision.reason,
            ):
                if matched_veto:
                    self.store.log(
                        event="veto_override",
                        trigger=authorization.MANUAL_RECLAIM,
                        scope=scope,
                        target=self.store.describe_veto(matched_veto),
                        source=matched_veto.get("source", "user"),
                    )
                if amount:
                    try:
                        methods.append(
                            memory.reclaim_page_cache(
                                path,
                                amount,
                                counters["current_bytes"] - amount,
                            )
                        )
                    except (OSError, ValueError) as error:
                        errors.append("page cache: %s" % error)
                if anon_amount:
                    try:
                        methods.append(memory.reclaim_anonymous(path, anon_amount))
                    except (OSError, ValueError) as error:
                        errors.append("anonymous: %s" % error)
        except (OSError, ValueError) as error:
            errors.append(str(error))
        after = memory.scope_counters(path) or {}
        if not methods:
            result.update(
                status="failed",
                error="; ".join(errors) or "reclaim did not complete",
                current_after=after.get("current_bytes"),
                reclaimable_after=after.get("reclaimable_bytes"),
            )
            self.store.log(
                event="memory_reclaim_failed",
                scope=scope,
                resource_class=resource_class,
                method="memory.reclaim or memory.high",
                current_before=counters["current_bytes"],
                current_after=after.get("current_bytes"),
                reclaimable_before=counters["reclaimable_bytes"],
                reclaimable_after=after.get("reclaimable_bytes"),
                reason=result["error"],
            )
            return result

        current_after = after.get("current_bytes")
        anon_after = after.get("anon_bytes")
        file_after = after.get("file_bytes")
        swap_after = after.get("swap_bytes")
        zswap_after = after.get("zswap_bytes")
        measured = memory.counter_delta(
            counters["current_bytes"], current_after, direction="decrease"
        )
        anon_reclaimed = memory.counter_delta(
            counters.get("anon_bytes"), anon_after, direction="decrease"
        )
        file_reclaimed = memory.counter_delta(
            counters.get("file_bytes"), file_after, direction="decrease"
        )
        swap_delta = memory.counter_delta(
            counters.get("swap_bytes"), swap_after, direction="increase"
        )
        zswap_delta = memory.counter_delta(
            counters.get("zswap_bytes"), zswap_after, direction="increase"
        )
        unique_methods = list(dict.fromkeys(methods))
        method = (
            "memory.reclaim"
            if "memory.reclaim" in unique_methods
            else unique_methods[0]
        )
        result.update(
            method=method,
            methods=unique_methods,
            current_after=current_after,
            reclaimable_after=after.get("reclaimable_bytes"),
            reclaimed_bytes=measured,
            anonymous_reclaimed_bytes=anon_reclaimed,
            file_reclaimed_bytes=file_reclaimed,
            swap_delta_bytes=swap_delta,
            zswap_delta_bytes=zswap_delta,
            elapsed_ms=round((time.monotonic() - started) * 1000, 2),
        )
        if errors:
            result["error"] = "; ".join(errors)
        self.reclaim_state[scope] = {
            "last_at": now,
            "warm": warm,
            "warm_until": state.get("warm_until") if isinstance(state, dict) else None,
            "refault_file": after.get("workingset_refault_file"),
            "refault_anon": after.get("workingset_refault_anon"),
            "major_faults": after.get("pgmajfault"),
            "high_events": after.get("high_events"),
        }
        self.store.log(
            event="memory_reclaimed",
            scope=scope,
            resource_class=resource_class,
            method=method,
            requested_bytes=requested,
            page_cache_requested_bytes=amount,
            anonymous_requested_bytes=anon_amount,
            reclaimed_bytes=measured,
            anonymous_reclaimed_bytes=anon_reclaimed,
            file_reclaimed_bytes=file_reclaimed,
            swap_delta_bytes=swap_delta,
            zswap_delta_bytes=zswap_delta,
            current_before=counters["current_bytes"],
            current_after=current_after,
            reclaimable_before=counters["reclaimable_bytes"],
            reclaimable_after=after.get("reclaimable_bytes"),
            elapsed_ms=result["elapsed_ms"],
            reason=result.get("error"),
        )
        return result

    def reclaim_scope(self, scope, force_veto=False, dry_run=False, now=None):
        """Run one explicit, daemon-authorized page-cache reclaim request."""
        if not isinstance(scope, str) or not cgroup.valid_rel(scope):
            return {"scope": scope, "status": "failed", "reason": "scope is invalid"}
        path = os.path.join(cgroup.base(), scope)
        if not os.path.isdir(path):
            return {"scope": scope, "status": "failed", "reason": "scope not found"}
        return self._reclaim_one(
            scope,
            path,
            time.time() if now is None else float(now),
            memory.pressure(),
            manual=True,
            force_veto=force_veto,
            dry_run=dry_run,
            resource_class=self._reclaim_class(scope, path) or "manual",
        )

    def reclaim_pass(self, now=None, dry_run=False):
        """Reclaim bounded page cache from safe idle scopes when pressure warrants it."""
        config = self.cfg.get("mem", {})
        if not memory.enabled(self.cfg) or not isinstance(config, dict):
            return []
        if config.get("reclaim", True) is not True:
            return []
        now = time.time() if now is None else float(now)
        snapshot = memory.snapshot(cfg=self.cfg, peak_cache=self.memory_peaks, now=now)
        host_pressure = memory.pressure()
        scope_names = {item["name"] for item in snapshot.get("scopes", [])}
        tracked_scopes = (
            set(self.reclaim_state)
            | set(self.reclaim_usage)
            | set(self.reclaim_idle_since)
        )
        for scope in tracked_scopes - scope_names:
            self.reclaim_state.pop(scope, None)
            self.reclaim_usage.pop(scope, None)
            self.reclaim_idle_since.pop(scope, None)

        candidates = []
        for row in snapshot.get("scopes", []):
            scope = row.get("name")
            if not isinstance(scope, str) or not cgroup.valid_rel(scope):
                continue
            path = os.path.join(cgroup.base(), scope)
            resource_class = self._reclaim_class(scope, path)
            if resource_class is not None:
                candidates.append((scope, path, resource_class))
        results = []
        if candidates:
            start = self.reclaim_cursor % len(candidates)
            count = min(len(candidates), MAX_RECLAIM_SCOPES)
            selected = (candidates + candidates)[start : start + count]
            self.reclaim_cursor = (start + count) % len(candidates)
        else:
            selected = []
            self.reclaim_cursor = 0
        for scope, path, resource_class in selected:
            result = self._reclaim_one(
                scope,
                path,
                now,
                host_pressure,
                dry_run=dry_run,
                resource_class=resource_class,
            )
            results.append(result)
        return results

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
        self.guarded(self._sync_pressure_monitor)
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
                elif key.data == "pressure":
                    self.guarded(self._collect_pressure_events)
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
        self._close_pressure_monitor()
        self.guarded(lambda: self.thaw_all_managed_scopes("daemon shutdown"))
        self.guarded(lambda: self.memory_governor_pass(force_restore=True))
        self.store.log(event="daemon_stop")
        self.store.save()
        self._write_summary_if_dirty()
        return 0


def run(cfg=None):
    cfg = policy.load_config() if cfg is None else cfg
    return Daemon(cfg).run()
