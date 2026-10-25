"""Self-learning store: counters and timings per executable, with decay and an audit log.

Learned: whether an exe tends to be shared (default action), how long it takes to stop
gracefully, and how long an idle shared leaf should live. Not learned: protected list,
uid rules, configured cgroup and environment exclusions (see policy.py). No model, no network.
"""

from contextlib import contextmanager
import hashlib
import json
import math
import os
import re
import tempfile
import time

from ..config import policy
from .. import protocol
from ..core import process as _inspect
from ..core import signature as survivor_signature
from ..governor import engine as _engine
from ..model import learning as pair_learning
from . import db
from . import transfer

DECAY_DAYS = 7
DECAY_FACTOR = 0.9
COUNTERS = (
    "seen",
    "shared_hits",
    "killed",
    "sigkill_needed",
    "respawned",
    "user_keep",
    "user_kill",
)
SEED_SHARE_PRIOR = 3.0
LOG_MAX = 1 << 20  # active and two rotated decisions.log files, each at most 1 MiB
LOG_ROTATIONS = 2
MAX_LOG_LINE = 64 << 10
MAX_EXES = 512
STALE_DAYS = 90
SCHEMA = 2
MAX_VETOES = 512
VETO_PRECEDENCE = (
    "pid",
    "scope",
    "pair",
    "signature",
    "app",
    "owner",
    "unit",
    "cgroup",
    "path",
)
_VETO_RANK = {kind: rank for rank, kind in enumerate(VETO_PRECEDENCE)}
MAX_AUTO_ACTIONS = 10_000  # durable undo context; status exposes only a recent view
MAX_FEEDBACK_IDS = 50_000
DAILY_EXPORT_RE = re.compile(r"^state-export-(\d{8})\.json$")
DAILY_EXPORTS_KEPT = 3


def _new_id():
    import uuid

    return uuid.uuid4().hex


# ---- pair model (Phase 2/4 thresholds; pure, see decide()) ----
DAY = 86400.0
PAIR_RETENTION = 30 * DAY
MAX_OPEN_REVIEWS = 128
REVIEW_TTL = 14 * DAY
REVIEW_RETENTION = 30 * DAY
MAX_PAIRS = 1000
MAX_PER_OWNER = 32
W_ANSWER = 3.0  # explicit answer weight; never decayed
W_INFERRED = 0.25  # user kill inferred from a vanished pid
W_STOP_OK = 0.5  # own successful stop; confidence only unless opted in
W_RESPAWN = 1.0  # own stop that respawned; decays with inferred evidence
W_REGRET = 3.0  # keep evidence added when an auto-stopped app comes back
SILENT_KILLS = pair_learning.SILENT_KILLS
SILENT_DAYS = pair_learning.SILENT_DAYS
SILENT_RATIO = pair_learning.SILENT_RATIO
SILENT_KEEP_FREE_DAYS = pair_learning.SILENT_KEEP_FREE_DAYS
SILENT_MIN_AGE = pair_learning.SILENT_MIN_AGE
BURN_IN_DAYS = pair_learning.BURN_IN_DAYS
BURN_IN_CLOSES = pair_learning.BURN_IN_CLOSES
REGRET_WINDOW = 30 * 60.0
REGRET_SUSPEND = 7 * DAY
ASK_PER_DAY = 3
ASK_PAIR_GAP = 7 * DAY
CHOICES = ("stop", "keep", "standalone", "never")
SEP = "\0"


def decide(p, now, authority="learned", allow_self_authority=False, learn=None):
    """Pure compatibility entry point for the pair model."""
    learn = learn if isinstance(learn, dict) else {}
    return pair_learning.decide_pair(
        pair_learning.PairEvidence.from_record(p, now),
        now,
        authority=authority,
        allow_self_authority=allow_self_authority,
        silent_kills=learn.get("silent_kills", SILENT_KILLS),
        silent_days=learn.get("silent_days", SILENT_DAYS),
        silent_ratio=learn.get("silent_ratio", SILENT_RATIO),
        burn_in_days=learn.get("burn_in_days", BURN_IN_DAYS),
        burn_in_closes=learn.get("burn_in_closes", BURN_IN_CLOSES),
    )


class Store:
    def __init__(
        self,
        state_dir,
        seeds=None,
        now=time.time,
        read_only=False,
        deny=(),
        mode="observe",
        learn=None,
    ):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "state.db")
        self.legacy_path = os.path.join(state_dir, "knowledge.json")
        self.log_path = os.path.join(state_dir, "decisions.log")
        self.feedback_path = os.path.join(state_dir, "feedback.jsonl")
        self.now = now
        self.seeds = seeds or {}
        self.read_only = read_only  # CLI: the daemon is the single writer
        self.deny = tuple(deny)  # configured owner-deny entries (extend the defaults)
        self.configure_learning(learn, mode)
        self.dirty = False
        self.defer_writes = False
        self.last_save = 0.0
        self.sigs = {}  # change-detection signatures for log lines (see changed())
        self.db = db.StateDB(self.path, read_only=self.read_only, deny=self.deny)
        self.db.import_legacy(self.legacy_path, now=self.now(), deny=self.deny)
        self.recovery = self.db.load_recovery()
        self._decision_seq, self._event_seq = self.db.audit_sequences()
        self._pending_decisions = []
        self._pending_events = []
        self._event_listeners = []
        self._audit_context = None
        self._feedback_replay_pending = None
        self._feedback_replaying = False
        self.data = self._fresh()
        self._load()
        self._decay()
        if self.recovery:
            self.log(
                event="store_recovered",
                source=self.recovery.get("source"),
                quarantined=self.recovery.get("quarantined"),
            )

    def configure_learning(self, learn=None, mode=None):
        """Apply validated learner settings without coupling the model to config loading."""
        if mode is not None:
            self.mode = mode
        self.learn = dict(learn) if isinstance(learn, dict) else {}
        configured = self.learn.get("authority")
        if configured in policy.LEARN_AUTHORITIES:
            self.learn_authority = configured
        elif self.mode == "adopt":
            self.learn_authority = "answered"
        elif self.mode == "enforce":
            self.learn_authority = "unit"
        else:
            self.learn_authority = "learned"
        self.allow_self_authority = bool(self.learn.get("allow_self_authority", False))
        self.probation_stops = max(0, int(self.learn.get("probation_stops", 3)))
        self.respawn_window = max(0.0, float(self.learn.get("respawn_window", 60)))
        self.revive_window = max(0.0, float(self.learn.get("revive_window", 1800)))
        self.regret_window = max(0.0, float(self.learn.get("regret_window", 1800)))
        self.regret_suspend = max(
            0.0, float(self.learn.get("regret_suspend_days", 7)) * DAY
        )

    def _fresh(self):
        return {
            "version": SCHEMA,
            "last_decay": self.now(),
            "created": self.now(),
            "closes": 0,
            "exes": {},
            "pairs": {},
            "standalone": {},
            "noise": {},
            "asked": {"day": 0, "n": 0},
            "signature_asked": {},
            "reviews": [],
            "review_seq": 0,
            "vetoes": [],
            "auto_actions": [],
            "feedback_ids": [],
            "feedback_invalid": 0,
            "feedback_last_replay": "",
            "held": False,
            "held_scopes": [],
            "snooze_until": 0.0,
            "muted_apps": [],
            "qos_scopes": {},
            "qos_exempt": {},
            "memory_scopes": {},
            "leftover_expiries": {},
            "frozen_scopes": {},
        }

    def _load(self):
        self.data = self.db.load_state(self.data)
        for pair in self.data["pairs"].values():
            if not isinstance(pair, dict):
                continue
            if "inferred_kills" not in pair:
                pair["inferred_kills"] = pair.get("kills", 0)
                self.dirty = True
            if "self_stop" not in pair:
                pair["self_stop"] = pair.get("stop_ok", 0) * W_STOP_OK
                self.dirty = True
            pair.setdefault("regret_keep", 0.0)
            pair.setdefault("respawn_weight", 0.0)

    def record_identity(self, identity, instance):
        """Persist resolver evidence independently of learned pair authority."""
        if self.read_only:
            return False
        return self.db.record_app_identity(identity, instance, now=self.now())

    def record_identities(self, records):
        """Persist identity rows discovered or changed by one process observe pass."""
        if self.read_only:
            return 0
        return self.db.record_app_identities(records, now=self.now())

    def app_identity(self, key):
        return self.db.app_identity(key)

    def latest_memory_samples(self):
        return self.db.latest_memory_samples()

    def record_memory_samples(self, samples, now=None):
        if self.read_only:
            return 0
        return self.db.save_memory_samples(samples, now=now)

    def set_frozen_scope(
        self, scope, since, decision_id=None, listeners=(), source="auto"
    ):
        """Record a cgroup freeze owned by Taema for crash recovery and explicit thaw."""
        self.data.setdefault("frozen_scopes", {})[scope] = {
            "since": float(since),
            "decision_id": decision_id,
            "listeners": list(listeners),
            "source": source,
        }
        self.dirty = True

    def set_frozen_listeners(self, scope, listeners):
        """Update a managed freeze's listener identities after reconciliation."""
        record = self.data.setdefault("frozen_scopes", {}).get(scope)
        listeners = list(listeners)
        if not isinstance(record, dict) or record.get("listeners") == listeners:
            return False
        record["listeners"] = listeners
        self.dirty = True
        return True

    def clear_frozen_scope(self, scope):
        """Forget one managed freeze after a successful thaw or confirmed removal."""
        record = self.data.setdefault("frozen_scopes", {}).pop(scope, None)
        if record is not None:
            self.dirty = True
        return record is not None

    def latest_app_instance(self, key):
        return self.db.latest_app_instance(key)

    def provenance_chain(self, key):
        return self.db.provenance_chain(key)

    def export_legacy(self):
        """Return the state fields understood by the 0.2 JSON store."""
        fields = (
            "version",
            "last_decay",
            "created",
            "closes",
            "exes",
            "pairs",
            "standalone",
            "noise",
            "asked",
            "reviews",
            "review_seq",
            "vetoes",
            "auto_actions",
            "feedback_ids",
            "feedback_invalid",
            "feedback_last_replay",
            "held",
            "held_scopes",
            "snooze_until",
            "muted_apps",
            "qos_scopes",
            "qos_exempt",
            "memory_scopes",
            "leftover_expiries",
        )
        return json.loads(json.dumps({field: self.data.get(field) for field in fields}))

    def export_daily_if_due(self):
        """Atomically write today's recovery export and retain the newest three days."""
        if self.read_only or self.dirty:
            return False
        now = self.now()
        day = time.strftime("%Y%m%d", time.gmtime(now))
        destination = os.path.join(self.dir, "state-export-%s.json" % day)
        if os.path.exists(destination) and not self.recovery:
            return False

        self._mkdir()
        descriptor, temporary = tempfile.mkstemp(prefix=".state-export-", dir=self.dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump(
                    self.export_legacy(), output, sort_keys=True, separators=(",", ":")
                )
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

        self.db.clear_recovery()
        self.recovery = None
        exports = []
        for name in os.listdir(self.dir):
            match = DAILY_EXPORT_RE.fullmatch(name)
            if match:
                exports.append((match.group(1), os.path.join(self.dir, name)))
        for _date, path in sorted(exports, reverse=True)[DAILY_EXPORTS_KEPT:]:
            try:
                os.unlink(path)
            except OSError:
                pass
        return True

    # ---- persistence ----
    def _mkdir(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def save(self):
        if self.read_only:
            return
        self.enforce_caps()
        self._prune_vetoes()
        self.db.save_state(
            self.data,
            now=self.now(),
            decisions=self._pending_decisions,
            events=self._pending_events,
            decision_seq=self._decision_seq,
            event_seq=self._event_seq,
        )
        self._pending_decisions.clear()
        self._pending_events.clear()
        self.dirty = False
        self.last_save = self.now()
        replay_path = self._feedback_replay_pending
        if replay_path:
            try:
                os.unlink(replay_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            else:
                self._feedback_replay_pending = None
                ids = self.data.get("feedback_ids", [])
                if len(ids) > MAX_FEEDBACK_IDS:
                    self.data["feedback_ids"] = ids[-MAX_FEEDBACK_IDS:]
                    self.dirty = True

    def save_if_dirty(self, min_interval=0):
        """Save only when something changed and min_interval seconds passed. True when saved."""
        if (
            self.defer_writes
            or not self.dirty
            or self.now() - self.last_save < min_interval
        ):
            return False
        self.save()
        return True

    def add_event_listener(self, listener):
        """Register a non-blocking observer for newly written audit events."""
        self._event_listeners.append(listener)

    def events_since(self, since_seq=0, limit=1001):
        """Return retained and not-yet-saved events after a cursor."""
        result = self.db.events_since(since_seq, limit)
        pending = [event for event in self._pending_events if event["seq"] > since_seq]
        combined = {event["seq"]: event for event in result["events"]}
        combined.update({event["seq"]: event for event in pending})
        ordered = [combined[seq] for seq in sorted(combined)]
        oldest = result["oldest_seq"]
        if pending:
            oldest = min(pending[0]["seq"], oldest or pending[0]["seq"])
        combined_more = result["more"] or len(ordered) > max(1, limit)
        return {
            "events": ordered[: max(1, limit)],
            "oldest_seq": oldest,
            "latest_seq": max(result["latest_seq"], self._event_seq),
            "more": combined_more,
        }

    def log(self, **fields):
        timestamp = round(self.now(), 3)
        event = fields.pop("event", "unknown")
        context = self._audit_context or {}
        mode = fields.pop("mode", None) or self.mode
        decision_id = fields.pop("decision_id", context.get("id"))
        corr = fields.pop("corr", context.get("corr"))
        why = fields.pop("why", None)
        if why is None:
            why = (
                fields.get("reason")
                or fields.get("error")
                or fields.get("target")
                or ""
            )
        record = {
            "ts": timestamp,
            "event": event,
            "mode": mode,
            "decision_id": decision_id,
            "corr": corr,
            "why": str(why)[:1024],
            **fields,
        }
        encoded = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > MAX_LOG_LINE:
            record = {
                "ts": timestamp,
                "event": event,
                "mode": mode,
                "decision_id": decision_id,
                "corr": corr,
                "why": (str(why)[:512] + " [event truncated]")[:1024],
                "truncated": True,
            }
            encoded = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        tracked = None
        if not self.read_only:
            self._event_seq += 1
            tracked = {
                "seq": self._event_seq,
                "ts": timestamp,
                "event": event,
                "decision_id": decision_id,
                "data": record,
            }
            self._pending_events.append(tracked)
            self.dirty = True
        self._mkdir()
        try:
            current_size = os.stat(self.log_path).st_size
        except OSError:
            current_size = 0
        if current_size and current_size + len(encoded) > LOG_MAX:
            for index in range(LOG_ROTATIONS, 0, -1):
                source = (
                    self.log_path
                    if index == 1
                    else "%s.%d" % (self.log_path, index - 1)
                )
                destination = "%s.%d" % (self.log_path, index)
                if index == LOG_ROTATIONS:
                    try:
                        os.unlink(destination)
                    except FileNotFoundError:
                        pass
                try:
                    os.replace(source, destination)
                    os.chmod(destination, 0o600)
                except FileNotFoundError:
                    continue
                except OSError:
                    continue
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(encoded)
        if tracked is not None:
            for listener in tuple(self._event_listeners):
                try:
                    listener(tracked)
                except Exception:
                    continue

    def record_decision(
        self,
        kind,
        scope=None,
        owner=None,
        authority="none",
        mode=None,
        why="",
        undo=None,
        corr=None,
        argv=None,
        cwd=None,
    ):
        """Record one durable lifecycle decision and return its trace identifiers."""
        correlation = corr or _new_id()
        if self.read_only:
            identifier = _new_id()
        else:
            self._decision_seq += 1
            identifier = self._decision_seq
        decision = {
            "id": identifier,
            "ts": round(self.now(), 3),
            "kind": str(kind),
            "scope": str(scope)[:256] if scope is not None else None,
            "owner": str(owner)[:256] if owner is not None else None,
            "authority": str(authority or "none"),
            "mode": mode or self.mode,
            "why": str(why)[:1024],
            "corr": correlation,
            "undoable": undo is not None and kind != "undo",
            "undo": undo,
            "argv": argv,
            "cwd": cwd,
            "undone": None,
        }
        if not self.read_only:
            self._pending_decisions.append(decision)
            self.dirty = True
        return decision

    @contextmanager
    def decision_context(
        self,
        kind,
        scope=None,
        owner=None,
        authority="none",
        mode=None,
        why="",
        undo=None,
        corr=None,
        argv=None,
        cwd=None,
    ):
        """Attach related audit events to one decision for the duration of an action."""
        decision = self.record_decision(
            kind,
            scope=scope,
            owner=owner,
            authority=authority,
            mode=mode,
            why=why,
            undo=undo,
            corr=corr,
            argv=argv,
            cwd=cwd,
        )
        previous = self._audit_context
        self._audit_context = decision
        try:
            yield decision
        except Exception as error:
            decision["outcome"] = "refused"
            self.log(event="refusal", why=str(error), scope=decision["scope"])
            raise
        finally:
            self._audit_context = previous

    def decision(self, identifier):
        """Return a retained decision, including any uncommitted record in this writer."""
        if isinstance(identifier, int) and not isinstance(identifier, bool):
            pending = next(
                (item for item in self._pending_decisions if item["id"] == identifier),
                None,
            )
            return dict(pending) if pending else self.db.decision(identifier)
        return None

    def latest_decision(self):
        pending = self._pending_decisions[-1] if self._pending_decisions else None
        committed = self.db.decisions(limit=1)
        if pending and (not committed or pending["id"] > committed[0]["id"]):
            return dict(pending)
        return committed[0] if committed else None

    def latest_undoable_decision(self, kinds=None):
        allowed = set(kinds) if kinds is not None else None
        pending = next(
            (
                item
                for item in reversed(self._pending_decisions)
                if item["undoable"]
                and item.get("undone") is None
                and (allowed is None or item["kind"] in allowed)
            ),
            None,
        )
        committed = self.db.decisions(
            limit=1,
            undoable=True,
            kinds=tuple(allowed) if allowed is not None else None,
        )
        if pending and (not committed or pending["id"] > committed[0]["id"]):
            return dict(pending)
        return committed[0] if committed else None

    def changed(self, key, sig):
        """True when sig differs from the last one seen for key (and remembers it)."""
        if self.sigs.get(key) == sig:
            return False
        self.sigs[key] = sig
        return True

    def forget_sigs(self, prefix, keep):
        """Drop remembered signatures under prefix that are not in keep (bounds the table)."""
        for k in [k for k in self.sigs if k.startswith(prefix) and k not in keep]:
            del self.sigs[k]

    # ---- vetoes and automatic-stop correction -----------------------------------------------
    @staticmethod
    def _finite_number(value):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        try:
            return math.isfinite(value)
        except OverflowError:
            return False

    @staticmethod
    def _valid_veto_target(target, allow_pid_wildcard=False):
        if not isinstance(target, dict) or target.get("kind") not in _VETO_RANK:
            return False
        kind = target["kind"]
        value = target.get("value")
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return False
        value = str(value)
        if not value or len(value) > 256:
            return False
        if kind == "pid":
            try:
                pid = int(value)
            except ValueError:
                return False
            start = target.get("start")
            return pid > 1 and (
                (allow_pid_wildcard and start is None)
                or (
                    isinstance(start, int) and not isinstance(start, bool) and start > 0
                )
            )
        if target.get("start") is not None:
            return False
        if kind == "pair":
            owner, leftover = target.get("owner"), target.get("leftover")
            return (
                isinstance(owner, str)
                and bool(owner)
                and len(owner) <= 256
                and SEP not in owner
                and isinstance(leftover, str)
                and bool(leftover)
                and len(leftover) <= 256
                and SEP not in leftover
                and value == leftover
            )
        if kind == "path":
            return os.path.isabs(value)
        return SEP not in value

    @staticmethod
    def _target(veto):
        target = {
            "kind": veto["kind"],
            "value": veto["value"],
            "start": veto.get("start"),
        }
        if veto.get("kind") == "pair":
            target["owner"] = veto["owner"]
            target["leftover"] = veto["leftover"]
        return target

    @staticmethod
    def describe_veto(veto):
        if veto["kind"] == "pair":
            label = "pair %s>%s" % (veto["owner"], veto["leftover"])
        else:
            label = "%s %s" % (veto["kind"], veto["value"])
        if veto["kind"] == "pid" and veto.get("start") is not None:
            label += " (starttime %s)" % veto["start"]
        if veto.get("reason"):
            label += " (reason: %s)" % veto["reason"]
        return label

    def add_veto(
        self,
        kind,
        value,
        start=None,
        identifier=None,
        reason="",
        corr=None,
        expires=None,
        source="user",
        owner=None,
        leftover=None,
    ):
        """Create a durable veto for one explicitly named target."""
        target = {"kind": kind, "value": value, "start": start}
        if kind == "pair":
            target.update(owner=owner, leftover=leftover)
        if not self._valid_veto_target(target):
            return None
        target["value"] = str(target["value"])
        if identifier is not None and (
            not isinstance(identifier, str) or not identifier or len(identifier) > 128
        ):
            return None
        if expires is not None and (not self._finite_number(expires)):
            return None
        if not isinstance(reason, str) or len(reason) > 256:
            return None
        if not isinstance(source, str) or not source or len(source) > 64:
            return None
        identifier = identifier or _new_id()
        existing = next(
            (
                v
                for v in self.data["vetoes"]
                if isinstance(v, dict) and v.get("id") == identifier
            ),
            None,
        )
        if existing:
            return dict(existing)
        self._prune_vetoes(trigger="add")
        if len(self.data["vetoes"]) >= MAX_VETOES:
            with self.decision_context(
                "refusal",
                scope=target["value"] if kind == "scope" else None,
                authority="user",
                why="veto capacity prevents adding protection",
            ):
                self.log(event="veto_refused", target=self._target(target))
            return None

        def append_veto(decision):
            veto = {
                "id": identifier,
                **target,
                "created": self.now(),
                "decision_id": decision["id"],
                "expires": expires,
                "source": source,
            }
            if reason:
                veto["reason"] = reason
            self.data["vetoes"].append(veto)
            self.dirty = True
            self.log(
                event="veto",
                target=self._target(veto),
                expires=expires,
                reason=reason,
                source=source,
            )
            return dict(veto)

        active = self._audit_context
        if corr and active and active.get("corr") == corr:
            return append_veto(active)
        with self.decision_context(
            "veto",
            scope=target["value"] if kind == "scope" else None,
            authority="user",
            why=reason or "user added a veto",
            corr=corr,
        ) as decision:
            return append_veto(decision)

    @staticmethod
    def _same_veto_target(veto, target, pid_wildcard=False):
        if veto.get("kind") != target.get("kind"):
            return False
        if target["kind"] == "pair":
            return veto.get("owner") == target.get("owner") and veto.get(
                "leftover"
            ) == target.get("leftover")
        return veto.get("value") == str(target.get("value")) and (
            target.get("kind") != "pid"
            or (target.get("start") is None and pid_wildcard)
            or veto.get("start") == target.get("start")
        )

    def remove_veto(self, target):
        """Remove a named veto. PID removal may omit start to clear that pid's instances."""
        if not self._valid_veto_target(target, allow_pid_wildcard=True):
            return []
        value = str(target.get("value"))
        removed = []
        keep = []
        for veto in self.data["vetoes"]:
            same = isinstance(veto, dict) and self._same_veto_target(
                veto, target, pid_wildcard=True
            )
            (removed if same else keep).append(veto)
        if removed:
            self.data["vetoes"] = keep
            self.dirty = True
            with self.decision_context(
                "veto_removed",
                scope=value if target["kind"] == "scope" else None,
                owner=target.get("owner", value)
                if target["kind"] in ("app", "owner")
                else None,
                authority="user",
                why="user removed a veto",
            ):
                self.log(
                    event="veto_removed",
                    target=self._target(target),
                )
        return [dict(v) for v in removed]

    def _active_vetoes(self, include_pending=True):
        now = self.now()
        vetoes = [
            dict(v)
            for v in self.data["vetoes"]
            if isinstance(v, dict)
            and self._valid_veto_target(v)
            and not self._veto_expired(v, now)
        ]
        if not include_pending:
            return vetoes
        for op in self._pending_feedback_ops():
            op_id = op.get("id")
            if op.get("op") == "veto" and self._valid_veto_target(op.get("target")):
                target = dict(op["target"])
                pending = {
                    "id": op_id,
                    **target,
                    "created": self.now(),
                    "expires": op.get("expires"),
                    "reason": op.get("reason", ""),
                    "source": "offline",
                }
                if not self._veto_expired(pending, now):
                    vetoes.append(pending)
            elif op.get("op") == "unveto":
                target = op.get("target")
                vetoes = [
                    v
                    for v in vetoes
                    if not (
                        self._valid_veto_target(target, allow_pid_wildcard=True)
                        and self._same_veto_target(v, target, pid_wildcard=True)
                    )
                ]
            elif op.get("op") == "undo":
                action = self.auto_action(op.get("action_id"))
                if action:
                    apps = action.get("apps") or [
                        pair[1]
                        for pair in action.get("pairs", [])
                        if isinstance(pair, list) and len(pair) == 2
                    ]
                    targets = [("app", app) for app in dict.fromkeys(apps)]
                    if not targets and action.get("scope"):
                        targets = [("scope", action["scope"])]
                    for index, (kind, value) in enumerate(targets):
                        target = {"kind": kind, "value": value, "start": None}
                        if self._valid_veto_target(target):
                            pending = {
                                "id": "%s:%d" % (op_id, index),
                                **target,
                                "created": self.now(),
                                "expires": op.get("expires"),
                                "reason": op.get("reason", ""),
                                "source": "offline",
                            }
                            if not self._veto_expired(pending, now):
                                vetoes.append(pending)
        return vetoes

    def _feedback_batch_id(self, path):
        try:
            stat_result = os.stat(path)
            identity = "%d:%d:%d:%d:" % (
                stat_result.st_dev,
                stat_result.st_ino,
                stat_result.st_mtime_ns,
                stat_result.st_size,
            )
            digest = hashlib.sha256(identity.encode())
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return ""

    def _pending_feedback_ops(self):
        """Yield valid queued operations in replay order, excluding applied ids."""
        known_ids = set(self.data.get("feedback_ids", []))
        replay = self.feedback_path + ".replay"
        for path in (replay, self.feedback_path):
            if path == replay and self.data.get(
                "feedback_last_replay"
            ) == self._feedback_batch_id(path):
                continue
            try:
                source = open(path, encoding="utf-8", errors="replace")
            except OSError:
                continue
            with source:
                for line in source:
                    try:
                        op = json.loads(line)
                        protocol.validate_feedback(op)
                    except (ValueError, TypeError):
                        continue
                    op_id = op.get("id") if "v" in op else None
                    if op_id and op_id in known_ids:
                        continue
                    if op_id:
                        known_ids.add(op_id)
                    yield op

    def pending_feedback_invalid(self):
        """Count malformed or unsupported lines that have not been replayed yet."""
        known_ids = set(self.data.get("feedback_ids", []))
        invalid = 0
        replay = self.feedback_path + ".replay"
        for path in (replay, self.feedback_path):
            if path == replay and self.data.get(
                "feedback_last_replay"
            ) == self._feedback_batch_id(path):
                continue
            try:
                source = open(path, encoding="utf-8", errors="replace")
            except OSError:
                continue
            with source:
                for line in source:
                    try:
                        op = json.loads(line)
                        protocol.validate_feedback(op)
                    except (ValueError, TypeError):
                        invalid += 1
                        continue
                    op_id = op.get("id") if "v" in op else None
                    if op_id and op_id in known_ids:
                        continue
                    if op_id:
                        known_ids.add(op_id)
        return invalid

    def _runtime_hold_path(self):
        runtime = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
        return os.path.join(runtime, "taema", "HOLD")

    def _read_runtime_hold(self):
        try:
            with open(self._runtime_hold_path(), encoding="utf-8") as stream:
                value = json.load(stream)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            # An unreadable marker must fail safe while the daemon is unavailable.
            return {"held": True}
        return value if isinstance(value, dict) else {"held": True}

    def hold_status(self, include_pending=True, include_runtime=None):
        """Return the active global/scope holds and snooze deadline."""
        if include_runtime is None:
            include_runtime = self.read_only
        held = self.data.get("held") is True
        scopes = {
            scope
            for scope in self.data.get("held_scopes", [])
            if isinstance(scope, str) and scope
        }
        snooze_until = self.data.get("snooze_until", 0)
        if include_pending:
            for op in self._pending_feedback_ops():
                if op.get("op") == "hold":
                    target = op.get("scope")
                    if target is None:
                        held = op["held"]
                        if not op["held"]:
                            snooze_until = 0.0
                    elif op["held"]:
                        scopes.add(target)
                    else:
                        scopes.discard(target)
                elif op.get("op") == "snooze":
                    snooze_until = op["until"]
        reason = ""
        if include_runtime:
            runtime = self._read_runtime_hold()
            held = held or runtime.get("held") is True
            runtime_until = runtime.get("snooze_until")
            if (
                isinstance(runtime_until, (int, float))
                and not isinstance(runtime_until, bool)
                and math.isfinite(runtime_until)
                and runtime_until > snooze_until
            ):
                snooze_until = runtime_until
            reason = runtime.get("reason", "")
        now = self.now()
        active_until = (
            snooze_until
            if isinstance(snooze_until, (int, float))
            and not isinstance(snooze_until, bool)
            and math.isfinite(snooze_until)
            and snooze_until > now
            else None
        )
        return {
            "global": held,
            "scopes": sorted(scopes),
            "snooze_until": active_until,
            "snooze_remaining_s": max(0, int(math.ceil(active_until - now)))
            if active_until is not None
            else 0,
            "reason": reason if isinstance(reason, str) else "",
        }

    def sync_runtime_hold(self, reason=None):
        """Mirror a global hold or snooze to the private runtime marker."""
        path = self._runtime_hold_path()
        parent = os.path.dirname(path)
        state = self.hold_status(include_runtime=False)
        if not state["global"] and state["snooze_until"] is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                return False
            return True
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            info = os.stat(parent)
            if info.st_uid != os.getuid():
                return False
            os.chmod(parent, 0o700)
            descriptor, temporary = tempfile.mkstemp(prefix=".HOLD.", dir=parent)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    json.dump(
                        {
                            "held": state["global"],
                            "snooze_until": state["snooze_until"],
                            "reason": reason or state["reason"],
                        },
                        stream,
                        sort_keys=True,
                    )
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                os.chmod(path, 0o600)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
        except OSError:
            return False
        return True

    def hold_reason(self, scope=None, include_pending=True):
        """Explain a global hold, matching scope hold, or active global snooze."""
        state = self.hold_status(include_pending=include_pending)
        if state["global"]:
            return "global hold"
        if state["snooze_until"] is not None:
            return "snoozed"
        if scope is not None and any(
            scope == held_scope or scope.startswith(held_scope + "/")
            for held_scope in state["scopes"]
        ):
            return "scope hold"
        return ""

    @staticmethod
    def _veto_expired(veto, now):
        expires = veto.get("expires")
        return (
            isinstance(expires, (int, float))
            and not isinstance(expires, bool)
            and expires <= now
        )

    def _prune_vetoes(self, trigger="save"):
        now = self.now()
        vetoes = self.data.get("vetoes", [])
        expired = [
            veto
            for veto in vetoes
            if isinstance(veto, dict) and self._veto_expired(veto, now)
        ]
        kept = [
            veto
            for veto in vetoes
            if not isinstance(veto, dict) or not self._veto_expired(veto, now)
        ]
        if len(kept) != len(vetoes):
            self.data["vetoes"] = kept
            self.dirty = True
            if not self.read_only:
                for veto in expired:
                    self.log(
                        event="veto_expired",
                        trigger=trigger,
                        target=self._target(veto),
                        expires=veto.get("expires"),
                        reason=veto.get("reason", ""),
                    )
        return expired

    def prune_vetoes(self, trigger="gc"):
        """Prune expired vetoes and log each removal at the lifecycle boundary."""
        return self._prune_vetoes(trigger=trigger)

    def match_veto(
        self,
        scope=None,
        members=(),
        include_pending=True,
        owner=None,
        leftover=None,
        signature=None,
        unit=None,
        cgroup_path=None,
    ):
        """Return the first veto matching a scope or observed member identities."""
        matches = self.matching_vetoes(
            scope,
            members,
            include_pending,
            owner=owner,
            leftover=leftover,
            signature=signature,
            unit=unit,
            cgroup_path=cgroup_path,
        )
        return matches[0] if matches else None

    def matching_vetoes(
        self,
        scope=None,
        members=(),
        include_pending=True,
        owner=None,
        leftover=None,
        signature=None,
        unit=None,
        cgroup_path=None,
    ):
        """Return every active veto in the spec's target-precedence order."""
        matches = []
        members = tuple(member for member in members if isinstance(member, dict))

        def under(path, prefix):
            return (
                isinstance(path, str)
                and isinstance(prefix, str)
                and bool(path)
                and bool(prefix)
                and (path == prefix or path.startswith(prefix.rstrip("/") + "/"))
            )

        def add(veto):
            if veto not in matches:
                matches.append(dict(veto))

        for veto in self._active_vetoes(include_pending):
            kind, value = veto.get("kind"), veto.get("value")
            if kind == "scope" and under(scope, value):
                add(veto)
                continue
            if (
                kind == "pair"
                and owner == veto.get("owner")
                and leftover == veto.get("leftover")
            ):
                add(veto)
                continue
            if kind == "signature" and signature == value:
                add(veto)
                continue
            if kind == "unit" and unit == value:
                add(veto)
                continue
            if kind == "cgroup" and (
                under(cgroup_path, value)
                or under(scope, value)
                or any(under(member.get("cgroup"), value) for member in members)
            ):
                add(veto)
                continue
            for member in members:
                raw_apps = member.get("apps", ())
                raw_owners = member.get("owners", ())
                apps = (
                    tuple(raw_apps) if isinstance(raw_apps, (list, tuple, set)) else ()
                )
                owners = (
                    tuple(raw_owners)
                    if isinstance(raw_owners, (list, tuple, set))
                    else ()
                )
                if member.get("owner"):
                    owners += (member["owner"],)
                if owner and owner not in owners:
                    owners += (owner,)
                if leftover and leftover not in apps:
                    apps += (leftover,)
                if kind == "pid" and (
                    str(member.get("pid")) == value
                    and member.get("start") == veto.get("start")
                ):
                    add(veto)
                    break
                if kind == "app" and value in apps:
                    add(veto)
                    break
                if kind == "owner" and (value == owner or value in owners):
                    add(veto)
                    break
                if kind == "pair" and veto.get("leftover") in apps:
                    if (
                        veto.get("owner") == member.get("owner")
                        or veto.get("owner") in owners
                    ):
                        add(veto)
                        break
                if kind == "path" and value in (
                    member.get("path"),
                    member.get("exe"),
                ):
                    add(veto)
                    break
                if kind == "unit" and value == member.get("unit"):
                    add(veto)
                    break
                if kind == "cgroup" and under(member.get("cgroup"), value):
                    add(veto)
                    break
        return sorted(
            matches,
            key=lambda veto: (
                _VETO_RANK.get(veto.get("kind"), len(_VETO_RANK)),
                veto.get("created")
                if isinstance(veto.get("created"), (int, float))
                and not isinstance(veto.get("created"), bool)
                else 0,
                str(veto.get("id", "")),
            ),
        )

    def record_auto_action(
        self,
        scope,
        why,
        pairs=(),
        apps=(),
        decision=None,
        owner=None,
        authority="mode",
        signature_id=None,
        restore=None,
    ):
        """Keep enough durable context to target the latest automatic stop after restart."""
        normalized_pairs = []
        for pair in pairs:
            if (
                isinstance(pair, (tuple, list))
                and len(pair) == 2
                and all(isinstance(x, str) and x and len(x) <= 256 for x in pair)
            ):
                normalized_pairs.append([pair[0], pair[1]])
        normalized_apps = list(
            dict.fromkeys(x for x in apps if isinstance(x, str) and x and len(x) <= 256)
        )
        for _owner, app in normalized_pairs:
            if app not in normalized_apps:
                normalized_apps.append(app)
        action = {
            "id": _new_id(),
            "scope": str(scope)[:256],
            "why": str(why)[:512],
            "pairs": normalized_pairs[:32],
            "apps": normalized_apps[:64],
            "ts": self.now(),
        }
        undo = {
            "action_id": action["id"],
            "scope": action["scope"],
            "pairs": action["pairs"],
            "apps": action["apps"],
            "ts": action["ts"],
        }
        if isinstance(signature_id, str) and signature_id:
            undo["signature_id"] = signature_id
        if decision is None:
            decision = self.record_decision(
                "auto_stop",
                scope=action["scope"],
                owner=owner or (normalized_pairs[0][0] if normalized_pairs else None),
                authority=authority,
                why=action["why"],
                undo=undo,
            )
        else:
            decision["undo"] = undo
            decision["undoable"] = True
            if not self.read_only and not any(
                item["id"] == decision["id"] for item in self._pending_decisions
            ):
                self._pending_decisions.append(decision)
        if isinstance(restore, dict):
            argv, cwd = restore.get("argv"), restore.get("cwd")
            if (
                isinstance(argv, list)
                and 0 < len(argv) <= 256
                and all(
                    isinstance(arg, str) and "\0" not in arg and len(arg) <= 4096
                    for arg in argv
                )
                and isinstance(cwd, str)
                and cwd.startswith("/")
                and len(cwd) <= 4096
            ):
                decision["argv"] = argv
                decision["cwd"] = cwd
        action["decision_id"] = decision["id"]
        action["corr"] = decision["corr"]
        actions = self.data.setdefault("auto_actions", [])
        actions.append(action)
        del actions[:-MAX_AUTO_ACTIONS]
        self.dirty = True
        self.log(
            event="auto_stop",
            scope=action["scope"],
            why=action["why"],
            pairs=action["pairs"][:8],
            decision_id=action["decision_id"],
            corr=action["corr"],
        )
        return dict(action)

    def auto_action(self, identifier=None):
        actions = [a for a in self.data.get("auto_actions", []) if isinstance(a, dict)]
        if identifier is None:
            decision = self.latest_undoable_decision(kinds=("stop", "auto_stop"))
            if decision:
                return self._action_for_decision(decision, actions)
            action = actions[-1] if actions else None
            if action and not action.get("decision_id") and not self.read_only:
                return self._record_legacy_action(action)
            return dict(action) if action else None
        decision_id = identifier
        if isinstance(identifier, str) and identifier.isdecimal():
            decision_id = int(identifier)
        decision = self.decision(decision_id)
        if (
            decision
            and decision.get("undoable")
            and decision.get("kind") in ("stop", "auto_stop")
        ):
            return self._action_for_decision(decision, actions)
        action = next((a for a in actions if a.get("id") == identifier), None)
        return dict(action) if action else None

    @staticmethod
    def _action_for_decision(decision, actions):
        payload = decision.get("undo")
        if not isinstance(payload, dict):
            return None
        action_id = payload.get("action_id")
        action = next((a for a in actions if a.get("id") == action_id), None)
        if action:
            return {
                **action,
                "decision_id": decision["id"],
                "corr": decision.get("corr"),
            }
        return {
            "id": action_id,
            "decision_id": decision["id"],
            "corr": decision.get("corr"),
            "scope": payload.get("scope"),
            "pairs": payload.get("pairs", []),
            "apps": payload.get("apps", []),
            "ts": payload.get("ts"),
            "why": decision.get("why", ""),
        }

    def _record_legacy_action(self, action):
        pairs = action.get("pairs")
        owner = (
            pairs[0][0]
            if isinstance(pairs, list)
            and pairs
            and isinstance(pairs[0], (tuple, list))
            and len(pairs[0]) == 2
            else None
        )
        undo = {key: action.get(key) for key in ("id", "scope", "pairs", "apps", "ts")}
        decision = self.record_decision(
            "auto_stop",
            scope=action.get("scope"),
            owner=owner,
            authority="mode",
            mode="unknown",
            why=action.get("why", "legacy automatic stop"),
            undo={"action_id": action.get("id"), **undo},
        )
        action["decision_id"] = decision["id"]
        action["corr"] = decision["corr"]
        self.dirty = True
        self.log(
            event="auto_stop",
            scope=action.get("scope"),
            why=action.get("why", "legacy automatic stop"),
            decision_id=decision["id"],
            corr=decision["corr"],
        )
        return dict(action)

    def undo_candidate(self, identifier=None):
        """Resolve an undoable decision by retained decision id or legacy action id."""
        if identifier is None:
            return self.latest_undoable_decision()
        decision_id = identifier
        if isinstance(identifier, str) and identifier.isdecimal():
            decision_id = int(identifier)
        decision = self.decision(decision_id)
        if decision and decision.get("undoable"):
            return decision
        action = next(
            (
                item
                for item in self.data.get("auto_actions", [])
                if isinstance(item, dict) and item.get("id") == identifier
            ),
            None,
        )
        if action:
            if not action.get("decision_id") and not self.read_only:
                action = self._record_legacy_action(action)
            return self.decision(action.get("decision_id"))
        return None

    def _mark_decision_undone(self, decision):
        timestamp = self.now()
        pending = next(
            (item for item in self._pending_decisions if item["id"] == decision["id"]),
            None,
        )
        if pending is not None:
            pending["undone"] = timestamp
            pending["undoable"] = False
        elif not self.read_only:
            self.db.mark_decision_undone(decision["id"], timestamp)
        decision["undone"] = timestamp
        decision["undoable"] = False
        self.dirty = True

    def mark_decision_restored(self, identifier, at=None):
        """Record that an opted-in stopped command has been relaunched once."""
        decision = self.undo_candidate(identifier)
        if decision is None:
            decision_id = int(identifier) if str(identifier).isdecimal() else None
            decision = self.decision(decision_id) if decision_id else None
        if not decision or not isinstance(decision.get("undo"), dict):
            return False
        if decision["undo"].get("restored_at") is not None:
            return False
        timestamp = self.now() if at is None else at
        pending = next(
            (item for item in self._pending_decisions if item["id"] == decision["id"]),
            None,
        )
        if pending is not None:
            pending["undo"]["restored_at"] = timestamp
        elif not self.read_only:
            if not self.db.mark_decision_restored(decision["id"], timestamp):
                return False
        else:
            return False
        self.log(
            event="restore",
            decision_id=decision["id"],
            scope=decision.get("scope"),
        )
        self.dirty = True
        return True

    def clear_decision_restored(self, identifier, at):
        """Clear a restore reservation only when its launcher failed to start."""
        decision_id = int(identifier) if str(identifier).isdecimal() else None
        decision = self.decision(decision_id) if decision_id is not None else None
        if not decision or not isinstance(decision.get("undo"), dict):
            return False
        if decision["undo"].get("restored_at") != at:
            return False
        pending = next(
            (item for item in self._pending_decisions if item["id"] == decision_id),
            None,
        )
        if pending is not None:
            pending["undo"].pop("restored_at", None)
        elif not self.read_only:
            if not self.db.clear_decision_restored(decision_id, at):
                return False
        else:
            return False
        self.dirty = True
        return True

    def mark_standalone(self, key):
        """Remember that a contained app is independent after undoing its containment."""
        if not isinstance(key, str) or not key or len(key) > 256 or SEP in key:
            return False
        entry = self.data["standalone"].setdefault(key, {"n": 0})
        entry["n"] = int(entry.get("n", 0)) + 1
        entry["ts"] = self.now()
        self.dirty = True
        return True

    def undo_decision(
        self,
        identifier=None,
        feedback_id=None,
        external_apply=None,
        allow_already_undone=False,
    ):
        """Undo one retained action, applying stop learning or a caller-owned kernel reversal."""
        decision = self.undo_candidate(identifier)
        if decision is None and allow_already_undone and identifier is not None:
            decision_id = int(identifier) if str(identifier).isdecimal() else None
            candidate = self.decision(decision_id) if decision_id else None
            if candidate and candidate.get("undone") is not None:
                decision = candidate
        if not decision:
            with self.decision_context(
                "refusal",
                authority="user",
                why="no retained automatic action is available to undo",
            ):
                self.log(event="undo_refused", action_id=identifier)
            return None
        already_undone = decision.get("undone") is not None
        if already_undone and not allow_already_undone:
            return None
        kind = decision.get("kind")
        payload = decision.get("undo")
        if not isinstance(payload, dict):
            return None
        if kind in ("stop", "auto_stop"):
            action = self._action_for_decision(
                decision,
                [a for a in self.data.get("auto_actions", []) if isinstance(a, dict)],
            )
            if not action:
                return None
            if already_undone:
                return {
                    "action": action,
                    "decision": decision,
                    "already_undone": True,
                }
            apps = action.get("apps") or [
                pair[1]
                for pair in action.get("pairs", [])
                if isinstance(pair, list) and len(pair) == 2
            ]
            signature_id = payload.get("signature_id")
            targets = (
                [("signature", signature_id)]
                if isinstance(signature_id, str) and signature_id
                else [("app", app) for app in dict.fromkeys(apps)]
            )
            if not targets and action.get("scope"):
                targets = [("scope", action["scope"])]
            self._prune_vetoes()
            if len(self.data["vetoes"]) + len(targets) > MAX_VETOES:
                with self.decision_context(
                    "refusal",
                    scope=action.get("scope"),
                    authority="user",
                    why="veto capacity prevents undo",
                ):
                    self.log(event="undo_refused", action_id=action.get("id"))
                return None

            target_id = decision["id"]
            undo_corr = None
            with self.decision_context(
                "undo",
                scope=action.get("scope"),
                authority="user",
                why="undo automatic stop",
                corr=action.get("corr"),
                undo={"target_decision_id": target_id},
            ) as undo_record:
                undo_corr = undo_record["corr"]
                vetoes = []
                for index, (target_kind, value) in enumerate(targets):
                    veto = self.add_veto(
                        target_kind,
                        value,
                        identifier=("%s:%d" % (feedback_id, index))
                        if feedback_id
                        else None,
                        reason="undo automatic stop",
                        corr=undo_corr,
                    )
                    if veto:
                        vetoes.append(veto)
                signature_ids = set()
                for pair in action.get("pairs", []):
                    if not isinstance(pair, list) or len(pair) != 2:
                        continue
                    owner, leftover = pair
                    self.answer(owner, leftover, "keep", source="undo")
                    record = self.data.get("pairs", {}).get(self.pkey(owner, leftover))
                    if isinstance(record, dict):
                        record["last_auto_stop"] = 0.0
                        record.pop("pending_stop", None)
                        record["suspended_until"] = self.now() + self.regret_suspend
                        if isinstance(record.get("sig"), str) and record["sig"]:
                            signature_ids.add(record["sig"])
                        self.dirty = True
                if isinstance(signature_id, str) and signature_id:
                    signature_ids.add(signature_id)
                for current_signature in signature_ids:
                    self.db.suspend_signature(
                        current_signature,
                        self.now() + self.regret_suspend,
                        now=self.now(),
                    )
                self.log(
                    event="undo",
                    action_id=action.get("id"),
                    target_decision_id=target_id,
                    scope=action.get("scope"),
                    vetoes=[self._target(v) for v in vetoes],
                    pairs=action.get("pairs", [])[:8],
                )
                self._mark_decision_undone(decision)
            return {
                "action": action,
                "decision": decision,
                "vetoes": vetoes,
                "already_undone": False,
                "restore_available": bool(decision.get("argv") and decision.get("cwd")),
            }

        if already_undone:
            return {
                "action": decision,
                "decision": decision,
                "already_undone": True,
            }
        if not callable(external_apply):
            return None
        effect = external_apply(decision)
        if not isinstance(effect, dict) or effect.get("ok") is not True:
            with self.decision_context(
                "refusal",
                scope=decision.get("scope"),
                authority="user",
                why=(effect or {}).get("error", "undo action is unavailable"),
            ):
                self.log(
                    event="undo_refused",
                    target_decision_id=decision["id"],
                )
            return None
        if payload.get("operation") == "adopt_standalone":
            for member in payload.get("members", []):
                if isinstance(member, dict):
                    self.mark_standalone(member.get("key"))
        with self.decision_context(
            "undo",
            scope=decision.get("scope"),
            authority="user",
            why="undo automatic %s action" % kind,
            corr=decision.get("corr"),
            undo={"target_decision_id": decision["id"]},
        ):
            self.log(
                event="undo",
                target_decision_id=decision["id"],
                scope=decision.get("scope"),
                operation=payload.get("operation"),
                effect={key: value for key, value in effect.items() if key != "ok"},
            )
            self._mark_decision_undone(decision)
        return {
            "action": decision,
            "decision": decision,
            "effect": effect,
            "already_undone": False,
        }

    def undo_auto_action(self, identifier=None, feedback_id=None):
        """Compatibility wrapper for the original automatic-stop-only undo API."""
        result = self.undo_decision(identifier, feedback_id=feedback_id)
        if result and result.get("vetoes") is not None:
            return result
        return None

    # ---- feedback ----
    def apply_op(self, op, key, all_records=False):
        """One explicit user answer: keep | forget | kill. Returns False for a bad op or key."""
        if (
            op not in ("keep", "forget", "kill")
            or not isinstance(key, str)
            or not key
            or len(key) > 256
            or not isinstance(all_records, bool)
            or (all_records and op != "forget")
        ):
            return False
        with self.decision_context(
            "answer", owner=key, authority="user", why="user answered %s" % op
        ):
            if op == "keep":
                self.bump(key, "user_keep", 3.0)
            elif op == "kill":
                self.bump(key, "user_kill", 1.0)
            else:
                self.forget(key, all_records=all_records)
            self.log(event=op, exe=key)
        return True

    def apply_feedback_command(self, msg, undo_handler=None):
        """Apply one supported feedback operation once, keyed by its versioned id."""
        try:
            protocol.validate_feedback(msg)
        except (ValueError, TypeError):
            return None
        if "v" not in msg:
            if not self.apply_op(msg["op"], msg["key"]):
                return None
            return {"ok": True}
        op_id, op = msg.get("id"), msg.get("op")
        ids = self.data.setdefault("feedback_ids", [])
        if op_id in ids:
            return {"ok": True, "duplicate": True}
        if msg["v"] in (1, 2) and op == "veto":
            target = msg.get("target")
            veto = self.add_veto(
                target["kind"],
                target["value"],
                target.get("start"),
                identifier=op_id,
                reason=msg.get("reason", ""),
                expires=msg.get("expires"),
                source="offline" if self._feedback_replaying else "user",
                owner=target.get("owner"),
                leftover=target.get("leftover"),
            )
            if veto is None:
                return None
            result = {"target": self._target(veto)}
        elif msg["v"] in (1, 2) and op == "unveto":
            target = msg.get("target")
            removed = self.remove_veto(target)
            result = {"removed": [self._target(v) for v in removed]}
        elif msg["v"] in (1, 2) and op == "undo":
            action_id = msg.get("action_id")
            restore = msg.get("restore") is True
            if restore:
                candidate = self.undo_candidate(action_id)
                if (
                    candidate is None
                    and isinstance(action_id, str)
                    and action_id.isdecimal()
                ):
                    candidate = self.decision(int(action_id))
                if not candidate or candidate.get("kind") not in ("stop", "auto_stop"):
                    return None
            undone = self.undo_decision(
                action_id,
                feedback_id=op_id,
                external_apply=undo_handler,
                allow_already_undone=restore,
            )
            if not undone:
                return None
            decision = undone["decision"]
            result = {
                "action_id": action_id,
                "target_decision_id": decision["id"],
                "kind": decision.get("kind"),
                "targets": [self._target(v) for v in undone.get("vetoes", [])],
                "pairs": undone.get("action", {}).get("pairs", []),
                "already_undone": undone.get("already_undone", False),
                "restore_available": bool(
                    decision.get("argv")
                    and decision.get("cwd")
                    and isinstance(decision.get("undo"), dict)
                    and decision["undo"].get("restored_at") is None
                ),
            }
        elif msg["v"] == 1 and op == "vetoed":
            target, trigger = msg.get("target"), msg.get("trigger")
            with self.decision_context(
                "refusal",
                scope=target.get("value") if target.get("kind") == "scope" else None,
                authority="veto",
                why="veto blocked %s" % trigger,
            ):
                self.log(event="vetoed", target=target, trigger=trigger)
            result = {"target": target}
        elif msg["v"] == 2 and op in ("keep", "forget", "kill"):
            if not self.apply_op(op, msg["key"], all_records=msg.get("all", False)):
                return None
            result = {}
        elif msg["v"] == 2 and op in ("answer", "teach"):
            owner, leftovers, choice = (
                msg["owner"],
                msg["leftovers"],
                msg["choice"],
            )
            if any(
                not self._ok(owner, key)
                or (
                    choice != "standalone"
                    and (
                        policy.bad_owner(owner, self.deny)
                        or (
                            isinstance(
                                self.data.get("pairs", {}).get(self.pkey(owner, key)),
                                dict,
                            )
                            and self.data["pairs"][self.pkey(owner, key)].get("source")
                            == "legacy-invalid"
                        )
                    )
                )
                for key in leftovers
            ):
                return None
            if not self.apply_answer(
                owner,
                leftovers,
                choice,
                source="explicit" if op == "answer" else "teach",
                audit_kind=op,
            ):
                return None
            result = {"owner": owner, "choice": choice, "leftovers": leftovers}
        elif msg["v"] == 2 and op == "review_answer":
            result = self.answer_review(
                msg["review_id"],
                msg["choice"],
                owner=msg.get("owner"),
                source="review",
            )
            if result is None:
                return None
        elif msg["v"] == 2 and op == "review_shown":
            result = self.mark_review_shown(msg["review_id"], owner=msg.get("owner"))
            if not result:
                return None
            result = {"review_id": msg["review_id"]}
        elif msg["v"] == 2 and op == "mute":
            apps = set(self.data.get("muted_apps", []))
            if msg["muted"]:
                apps.add(msg["app"])
            else:
                apps.discard(msg["app"])
            self.data["muted_apps"] = sorted(apps)
            self.dirty = True
            with self.decision_context(
                "mute" if msg["muted"] else "unmute",
                owner=msg["app"],
                authority="user",
                why="user %s notifications for %s"
                % ("muted" if msg["muted"] else "unmuted", msg["app"]),
            ):
                self.log(event="mute", app=msg["app"], muted=msg["muted"])
            result = {"app": msg["app"], "muted": msg["muted"]}
        elif msg["v"] == 2 and op == "hold":
            scope, held = msg.get("scope"), msg["held"]
            reason = msg.get("reason") or "user %s %s" % (
                "held" if held else "released",
                scope or "all actions",
            )
            if scope is None:
                self.data["held"] = held
                if not held:
                    self.data["snooze_until"] = 0.0
            else:
                scopes = set(self.data.get("held_scopes", []))
                if held:
                    scopes.add(scope)
                else:
                    scopes.discard(scope)
                self.data["held_scopes"] = sorted(scopes)
            self.dirty = True
            with self.decision_context(
                "hold" if held else "resume",
                scope=scope,
                authority="user",
                why=reason,
            ):
                self.log(event="hold", scope=scope, held=held, reason=reason)
            result = {"scope": scope, "held": held}
        elif msg["v"] == 2 and op == "snooze":
            until = msg["until"]
            self.data["snooze_until"] = until if until > self.now() else 0.0
            self.dirty = True
            reason = msg.get("reason") or "user snoozed actions until %.3f" % until
            with self.decision_context(
                "snooze",
                authority="user",
                why=reason,
            ):
                self.log(
                    event="snooze",
                    until=self.data["snooze_until"],
                    reason=reason,
                )
            result = {"until": self.data["snooze_until"]}
        elif msg["v"] == 2 and op == "import_learning":
            with self.decision_context(
                "import",
                authority="user",
                why="user imported learning (%s)" % msg["mode"],
            ):
                summary = self.import_learning_document(
                    msg["document"], mode=msg["mode"]
                )
                self.log(
                    event="import",
                    mode=msg["mode"],
                    added=bool(summary),
                )
            if summary is None:
                return None
            result = {"mode": msg["mode"], **summary}
        elif msg["v"] == 2 and op == "reset_scope":
            with self.decision_context(
                "reset",
                authority="user",
                why="user reset %s" % msg["scope"],
            ):
                summary = self.reset_scope(msg["scope"])
                self.log(event="reset", scope=msg["scope"])
            if summary is None:
                return None
            result = {"scope": msg["scope"], **summary}
        elif msg["v"] == 2 and op == "restore_backup":
            staging = msg["staging"]
            with self.decision_context(
                "restore",
                authority="user",
                why="user restored a backup",
            ):
                summary, error = transfer.apply_staged_backup(staging, self.dir)
                if error is None:
                    self.refresh_persisted()
                self.log(event="restore", staging=staging, error=error)
            if error is not None:
                return {"ok": False, "error": error}
            result = dict(summary)
        elif msg["v"] == 2 and op == "unit_test":
            problems = policy.validate_unit(msg["unit"])
            matched = []
            if not problems:
                match = msg["unit"].get("match", {})
                for pid in msg["pids"]:
                    if _engine.unit_matches(match, pid):
                        matched.append({"pid": pid, "comm": _inspect.comm(pid)})
            result = {"matched": matched, "lint": problems}
        else:
            return None
        ids.append(op_id)
        if not self._feedback_replaying:
            del ids[:-MAX_FEEDBACK_IDS]
        self.dirty = True
        if op in ("hold", "snooze"):
            self.sync_runtime_hold(reason=reason)
        return {"ok": True, **result}

    def apply_feedback(self, path=None):
        """Replay one queue batch and remove it only after its state is committed."""
        path = path or self.feedback_path
        work = path + ".replay"
        if self._feedback_replay_pending:
            return 0
        if os.path.exists(path):
            if not os.path.exists(work):
                try:
                    os.replace(path, work)
                except OSError:
                    return 0
        batch_id = self._feedback_batch_id(work)
        if not batch_id:
            return 0
        if batch_id == self.data.get("feedback_last_replay"):
            try:
                os.unlink(work)
            except OSError:
                pass
            return 0
        n = 0
        invalid = 0
        self._feedback_replaying = True
        try:
            with open(work, encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        m = json.loads(line)
                        protocol.validate_feedback(m)
                        if "v" in m:
                            result = self.apply_feedback_command(m)
                            if result is None:
                                invalid += 1
                            elif not result.get("duplicate"):
                                n += 1
                        elif self.apply_op(m.get("op"), m.get("key")):
                            n += 1
                        else:
                            invalid += 1
                    except (ValueError, TypeError):
                        invalid += 1
        except OSError:
            return 0
        finally:
            self._feedback_replaying = False
        self.data["feedback_invalid"] = (
            int(self.data.get("feedback_invalid", 0)) + invalid
        )
        self.data["feedback_last_replay"] = batch_id
        self.dirty = True
        self._feedback_replay_pending = work
        if not self.defer_writes:
            self.save()
        return n

    # ---- records ----
    def _fill(self, r):
        for c in COUNTERS:
            r.setdefault(c, 0.0)
        r.setdefault("term_exit_ms", [])
        r.setdefault("idle_grace_scale", 1.0)
        r.setdefault("stops", 0)
        return r

    def rec(self, key):
        """The stored record for key (created on first write). Reads use peek()."""
        r = self._fill(self.data["exes"].setdefault(key, {}))
        r["last_seen"] = self.now()
        self.dirty = True
        return r

    def peek(self, key):
        """Read-only view: never creates a record."""
        return self._fill(dict(self.data["exes"].get(key, {})))

    def bump(self, key, field, n=1.0):
        self.rec(key)[field] += n

    def add_term_ms(self, key, ms):
        r = self.rec(key)
        r["term_exit_ms"] = (r["term_exit_ms"] + [int(ms)])[-20:]

    def forget(self, key, all_records=False):
        """Forget one app counter, or all of its learned records while retaining vetoes."""
        self.dirty = True
        known = self.data["exes"].pop(key, None) is not None
        if not all_records:
            return known

        pairs = self.data.setdefault("pairs", {})
        related_pair_keys = []
        related_signature_ids = set()
        for pair_key, pair in pairs.items():
            owner, separator, leftover = pair_key.partition(SEP)
            if separator and key in (owner, leftover):
                related_pair_keys.append(pair_key)
                if isinstance(pair, dict) and isinstance(pair.get("sig"), str):
                    related_signature_ids.add(pair["sig"])
        for pair_key in related_pair_keys:
            del pairs[pair_key]
        known = known or bool(related_pair_keys)

        for collection in ("standalone", "noise"):
            values = self.data.setdefault(collection, {})
            known = values.pop(key, None) is not None or known

        signature_vetoes = {
            veto.get("value")
            for veto in self.data.get("vetoes", [])
            if veto.get("kind") == "signature" and isinstance(veto.get("value"), str)
        }
        signature_ids = set(
            self.db.forget_signatures_for_key(
                key,
                preserve=signature_vetoes,
                include=related_signature_ids,
            )
        )
        known = bool(signature_ids) or known
        asked = self.data.get("signature_asked", {})
        if isinstance(asked, dict):
            for identifier in signature_ids:
                asked.pop(identifier, None)

        reviews = self.data.setdefault("reviews", [])
        kept_reviews = []
        for review in reviews:
            survivors = review.get("survivors", [])
            related = review.get("state", "open") == "open" and (
                review.get("owner") == key
                or (isinstance(survivors, (list, tuple, set)) and key in survivors)
                or review.get("sig") in signature_ids
            )
            if related:
                known = True
            else:
                kept_reviews.append(review)
        self.data["reviews"] = kept_reviews
        return known

    def is_persistent(self, key):
        """True for [seeds] persist keys (tmux, gpg-agent ...): never a GC candidate."""
        return key in self.seeds.get("persist", [])

    def decay(self):
        days = (self.now() - self.data.get("last_decay", self.now())) / 86400.0
        steps = int(days // DECAY_DAYS)
        if steps <= 0:
            return
        self.dirty = True
        f = DECAY_FACTOR**steps
        for r in self.data["exes"].values():
            for c in COUNTERS:
                v = r.get(c, 0.0) * f
                r[c] = 0.0 if v < 0.01 else v
        for p in self.data["pairs"].values():
            for c in (
                "stop",
                "keep",
                "inferred_kills",
                "self_stop",
                "respawn_weight",
            ):  # inferred evidence only; ex_* counters never decay
                v = p.get(c, 0.0) * f
                p[c] = 0.0 if v < 0.01 else v
        self.data["last_decay"] += steps * DECAY_DAYS * 86400

    _decay = decay

    @staticmethod
    def _empty(r):
        return (
            all(r.get(c, 0.0) == 0 for c in COUNTERS)
            and not r.get("term_exit_ms")
            and not r.get("stops")
            and r.get("idle_grace_scale", 1.0) == 1.0
        )

    def enforce_caps(self):
        """Drop all-zero records; above MAX_EXES evict stale (last_seen > 90 days) records first,
        then the lowest decayed weight."""
        exes = self.data["exes"]
        for k in [k for k, r in exes.items() if self._empty(r)]:
            del exes[k]
            self.dirty = True
        pairs = self.data["pairs"]
        now = self.now()
        for k in [
            k
            for k, p in pairs.items()
            if self._pweight(p) == 0
            and not p.get("closes")
            and not p.get("launches")
            and not p.get("kills")
            and now - p.get("first_seen", p.get("last_seen", now)) >= PAIR_RETENTION
        ]:
            del pairs[k]
            self.dirty = True
        if len(pairs) > MAX_PAIRS:
            self._cap_pairs("\0none")
        over = len(exes) - MAX_EXES
        if over > 0:
            cutoff = self.now() - STALE_DAYS * 86400
            order = sorted(
                exes,
                key=lambda k: (
                    exes[k].get("last_seen", 0) >= cutoff,
                    sum(exes[k].get(c, 0.0) for c in COUNTERS),
                    exes[k].get("last_seen", 0),
                ),
            )
            for k in order[:over]:
                del exes[k]
            self.dirty = True

    # ---- pairs ----
    @staticmethod
    def pkey(owner, leftover):
        return owner + SEP + leftover

    @staticmethod
    def _ok(*keys):
        return all(
            isinstance(k, str) and 0 < len(k) <= 256 and SEP not in k for k in keys
        )

    def _pair(self, owner, leftover, create=True):
        k = self.pkey(owner, leftover)
        p = self.data["pairs"].get(k)
        if p is None:
            if not create:
                return None
            p = self.data["pairs"][k] = {"first_seen": self.now()}
            self._cap_pairs(owner, keep=k)
        for f in (
            "stop",
            "keep",
            "self_stop",
            "respawn_weight",
            "regret_keep",
            "ex_stop",
            "ex_keep",
            "closes",
            "kills",
            "launches",
            "stop_ok",
            "respawn",
            "probation",
            "last_asked",
            "last_auto_stop",
            "last_keep",
            "suspended_until",
        ):
            p.setdefault(f, 0 if f in ("closes", "kills", "launches") else 0.0)
        p.setdefault("inferred_kills", p.get("kills", 0))
        p.setdefault("days", [])
        p["last_seen"] = self.now()
        self.dirty = True
        return p

    @staticmethod
    def _pweight(p):
        return (
            p.get("stop", 0)
            + p.get("keep", 0)
            + p.get("self_stop", 0)
            + p.get("regret_keep", 0)
            + p.get("ex_stop", 0)
            + p.get("ex_keep", 0)
        )

    def _cap_pairs(self, owner, keep=None):
        pairs = self.data["pairs"]

        def drop(cands, over):
            order = sorted(
                (
                    k
                    for k in cands
                    if k != keep
                    and pairs[k].get("source") != "legacy-invalid"
                    and not (
                        pairs[k].get("ex_last") == "keep"
                        and pairs[k].get("ex_keep", 0) > pairs[k].get("stop", 0)
                    )
                ),
                key=lambda k: (self._pweight(pairs[k]), pairs[k].get("last_seen", 0)),
            )
            for k in order[:over]:
                del pairs[k]
            if order:
                self.dirty = True

        mine = [k for k in pairs if k.startswith(owner + SEP)]
        if len(mine) > MAX_PER_OWNER:
            drop(mine, len(mine) - MAX_PER_OWNER)
        if len(pairs) > MAX_PAIRS:
            drop(list(pairs), len(pairs) - MAX_PAIRS)

    # ---- close reviews ----------------------------------------------------------------------
    def open_reviews(self):
        """Pending reviews, in creation order, excluding reviews past their expiry."""
        now = self.now()
        return [
            dict(r)
            for r in self.data.get("reviews", [])
            if isinstance(r, dict)
            and r.get("state") == "open"
            and r.get("expires", now) > now
        ]

    @property
    def review_count(self):
        return len(self.open_reviews())

    def review_details(self, reviews=None):
        """Return review rows with stable signature, provenance, memory, and age fields."""
        now = self.now()
        result = []
        for review in self.open_reviews() if reviews is None else reviews:
            item = dict(review)
            item["age"] = max(0, int(now - item.get("created", now)))
            signature_id = item.get("sig")
            signature = self.db.signature(signature_id) if signature_id else None
            item["signature"] = signature
            item["closes"] = int(
                (signature or {}).get("closes", item.get("closes", 0)) or 0
            )
            provenance = item.get("provenance")
            if not provenance and item.get("owner"):
                instance = self.latest_app_instance(item["owner"])
                if instance:
                    provenance = instance.get("scope") or instance.get("parent_app")
                if not provenance:
                    chain = self.provenance_chain(item["owner"])
                    provenance = chain.get("chain_text") if chain else None
            item["provenance"] = provenance or "owner identity"
            result.append(item)
        return result

    def mark_review_shown(self, identifier, owner=None):
        """Count an interactive review once, when it is actually presented for a choice."""
        review = next(
            (
                item
                for item in self.data.get("reviews", [])
                if isinstance(item, dict)
                and item.get("id") == identifier
                and item.get("state") == "open"
                and item.get("expires", 0) > self.now()
            ),
            None,
        )
        if review is None:
            return False
        if review.get("shown"):
            return True
        review_owner = review.get("owner")
        if owner is None:
            owner = review_owner
        elif review_owner and owner != review_owner:
            return False
        if not owner:
            candidates = [
                candidate.get("key")
                for candidate in review.get("candidates", [])
                if isinstance(candidate, dict)
                and isinstance(candidate.get("key"), str)
                and not policy.bad_owner(candidate["key"], self.deny)
            ]
            owner = candidates[0] if len(candidates) == 1 else None
        if review.get("kind") == "provenance-candidate":
            candidate_keys = {
                candidate.get("key")
                for candidate in review.get("candidates", [])
                if isinstance(candidate, dict)
            }
            if owner not in candidate_keys:
                return False
        survivors = review.get("survivors", [])
        pairs = [(owner, key) for key in survivors if isinstance(owner, str)]
        signature = review.get("sig")
        eligible = [pair for pair in pairs if self.can_ask(pair, signature=signature)]
        if not eligible or len(eligible) != len(pairs):
            return False
        self.mark_asked(eligible, signature=signature)
        review["shown"] = self.now()
        self.dirty = True
        with self.decision_context(
            "question",
            scope=review.get("scope"),
            owner=owner,
            authority="user",
            why="user was shown review #%s" % identifier,
        ):
            self.log(
                event="review_shown",
                id=identifier,
                owner=owner,
                signature=signature,
                leftovers=review.get("survivors", [])[:8],
            )
        return True

    def review_holds_scope(self, scope):
        """Pair and leftover scope reviews hold; adopt reviews for shared/unit scopes are informational."""
        return bool(self.hold_reason(scope)) or any(
            isinstance(r, dict)
            and r.get("scope") == scope
            and r.get("state") in ("open", "expired")
            and (r.get("kind") != "scope" or scope.startswith("leftover/"))
            for r in self.data.get("reviews", [])
        )

    def _resolve_review(self, review, now, reason):
        review["state"] = "expired"
        review["closed"] = now
        review["reason"] = reason
        if review.get("kind") == "provenance-candidate" or not review.get("owner"):
            self.dirty = True
            return
        if review.get("sig"):
            self.db.answer_signature(review["sig"], "keep", W_ANSWER, now=now)
        for key in review.get("survivors", []):
            owner = review.get("owner")
            pair = (
                self.data.get("pairs", {}).get(self.pkey(owner, key)) if owner else None
            )
            # A user's explicit keep stays authoritative; a fresh unanswered review can replace
            # an older stop answer with the safe default keep.
            if (
                pair
                and pair.get("ex_keep", 0)
                and pair.get("ex_last") == "keep"
                and pair.get("ex_source") != "review_expiry"
            ):
                continue
            if self.answer(owner, key, "keep", source="review_expiry"):
                pair = self._pair(owner, key)
                if review.get("scope"):
                    pair.setdefault("review_expiries", {})[review["scope"]] = (
                        review.get("created", now)
                    )
        self.dirty = True

    def expire_reviews(self):
        """Resolve expired reviews, then prune closed pair and non-leftover scope records."""
        now = self.now()
        reviews = self.data.setdefault("reviews", [])
        expired = 0
        for review in reviews:
            if (
                isinstance(review, dict)
                and review.get("state") == "open"
                and review.get("expires", now + 1) <= now
            ):
                self._resolve_review(review, now, "expired")
                expired += 1
                self.log(
                    event="review_expired",
                    id=review.get("id"),
                    owner=review.get("owner"),
                )
        closed = [
            r
            for r in reviews
            if isinstance(r, dict)
            and r.get("state") != "open"
            and r.get("closed", now) <= now - REVIEW_RETENTION
        ]
        if closed:
            self.data["reviews"] = [r for r in reviews if r not in closed]
            self.dirty = True
        return expired

    def add_review(
        self,
        owner,
        members,
        scope,
        signature=None,
        memory=None,
        provenance=None,
    ):
        """Record one durable review for members moved to a leftover scope."""
        members = list(members or ())
        if (
            not isinstance(owner, str)
            or not owner
            or len(owner) > 256
            or not isinstance(scope, str)
            or not scope
        ):
            return None
        by_key = {}
        for member in members:
            if (
                not isinstance(member, dict)
                or not isinstance(member.get("key"), str)
                or not isinstance(member.get("pid"), int)
                or isinstance(member.get("pid"), bool)
            ):
                continue
            by_key.setdefault(member["key"], set()).add(member["pid"])
        if not by_key:
            return None
        self.expire_reviews()
        reviews = self.data.setdefault("reviews", [])
        opens = [r for r in reviews if isinstance(r, dict) and r.get("state") == "open"]
        while len(opens) >= MAX_OPEN_REVIEWS:
            oldest = min(opens, key=lambda r: (r.get("created", 0), r.get("id", 0)))
            now = self.now()
            self._resolve_review(oldest, now, "queue cap")
            self.log(
                event="review_expired",
                id=oldest.get("id"),
                owner=oldest.get("owner"),
                reason="queue cap",
            )
            opens.remove(oldest)
        now = self.now()
        review_id = self.data.get("review_seq", 0) + 1
        review = {
            "id": review_id,
            "kind": "close",
            "owner": owner,
            "survivors": sorted(by_key),
            "pids": sorted({p for pids in by_key.values() for p in pids}),
            "scope": scope,
            "created": now,
            "expires": now + REVIEW_TTL,
            "state": "open",
            "members": [
                {
                    "key": member["key"],
                    "pid": member["pid"],
                    "start": member.get("start"),
                }
                for member in members
                if isinstance(member, dict)
                and isinstance(member.get("key"), str)
                and isinstance(member.get("pid"), int)
                and not isinstance(member.get("pid"), bool)
            ],
        }
        if isinstance(signature, dict) and isinstance(signature.get("id"), str):
            review["sig"] = signature["id"]
        if isinstance(memory, int) and not isinstance(memory, bool) and memory >= 0:
            review["mem"] = memory
        if isinstance(provenance, str) and provenance:
            review["provenance"] = provenance[:512]
        reviews.append(review)
        self.data["review_seq"] = review_id
        self.dirty = True
        return dict(review)

    def add_provenance_review(
        self, members, scope, candidates=(), reason="owner is ambiguous"
    ):
        """Queue an unanswered ownership review without granting authority to a candidate."""
        members = list(members or ())
        if not isinstance(scope, str) or not scope or len(scope) > 512:
            return None
        by_key = {}
        for member in members:
            if (
                not isinstance(member, dict)
                or not isinstance(member.get("key"), str)
                or not isinstance(member.get("pid"), int)
                or isinstance(member.get("pid"), bool)
            ):
                continue
            by_key.setdefault(member["key"], set()).add(member["pid"])
        if not by_key:
            return None
        normalized = []
        seen = set()
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            key = candidate.get("key")
            if (
                not isinstance(key, str)
                or not key
                or policy.bad_owner(key, self.deny)
                or key in seen
            ):
                continue
            seen.add(key)
            normalized.append(
                {
                    "id": len(normalized) + 1,
                    "kind": candidate.get("kind", "ancestor"),
                    "key": key,
                    "label": str(candidate.get("label") or key)[:128],
                }
            )
            if len(normalized) >= 16:
                break
        self.expire_reviews()
        reviews = self.data.setdefault("reviews", [])
        existing = next(
            (
                review
                for review in reviews
                if isinstance(review, dict)
                and review.get("kind") == "provenance-candidate"
                and review.get("scope") == scope
                and review.get("state") == "open"
            ),
            None,
        )
        if existing:
            existing["candidates"] = normalized
            existing["survivors"] = sorted(by_key)
            existing["pids"] = sorted({pid for pids in by_key.values() for pid in pids})
            existing["members"] = [
                {
                    "key": member["key"],
                    "pid": member["pid"],
                    "start": member.get("start"),
                }
                for member in members
                if isinstance(member, dict)
                and isinstance(member.get("key"), str)
                and isinstance(member.get("pid"), int)
                and not isinstance(member.get("pid"), bool)
            ]
            existing["reason"] = str(reason)[:256]
            existing["provenance"] = str(reason)[:512]
            self.dirty = True
            return dict(existing)
        opens = [
            review
            for review in reviews
            if isinstance(review, dict) and review.get("state") == "open"
        ]
        while len(opens) >= MAX_OPEN_REVIEWS:
            oldest = min(
                opens,
                key=lambda review: (review.get("created", 0), review.get("id", 0)),
            )
            now = self.now()
            self._resolve_review(oldest, now, "queue cap")
            self.log(
                event="review_expired",
                id=oldest.get("id"),
                owner=oldest.get("owner"),
                reason="queue cap",
            )
            opens.remove(oldest)
        now = self.now()
        review_id = self.data.get("review_seq", 0) + 1
        review = {
            "id": review_id,
            "kind": "provenance-candidate",
            "survivors": sorted(by_key),
            "pids": sorted({pid for pids in by_key.values() for pid in pids}),
            "scope": scope,
            "candidates": normalized,
            "reason": str(reason)[:256],
            "provenance": str(reason)[:512],
            "created": now,
            "expires": now + REVIEW_TTL,
            "state": "open",
            "members": [
                {
                    "key": member["key"],
                    "pid": member["pid"],
                    "start": member.get("start"),
                }
                for member in members
                if isinstance(member, dict)
                and isinstance(member.get("key"), str)
                and isinstance(member.get("pid"), int)
                and not isinstance(member.get("pid"), bool)
            ],
        }
        reviews.append(review)
        self.data["review_seq"] = review_id
        self.dirty = True
        return dict(review)

    def add_scope_review(self, scope, reason, memory=None):
        """Queue a durable GC review without inventing an owner/member pair."""
        if (
            not isinstance(scope, str)
            or not scope
            or len(scope) > 512
            or not isinstance(reason, str)
            or not reason
        ):
            return None
        self.expire_reviews()
        existing = next(
            (
                r
                for r in self.data.get("reviews", [])
                if isinstance(r, dict)
                and r.get("kind") == "scope"
                and r.get("scope") == scope
                and r.get("state") == "open"
            ),
            None,
        )
        if existing:
            return dict(existing)
        reviews = self.data.setdefault("reviews", [])
        opens = [r for r in reviews if isinstance(r, dict) and r.get("state") == "open"]
        while len(opens) >= MAX_OPEN_REVIEWS:
            oldest = min(opens, key=lambda r: (r.get("created", 0), r.get("id", 0)))
            now = self.now()
            self._resolve_review(oldest, now, "queue cap")
            self.log(
                event="review_expired",
                id=oldest.get("id"),
                owner=oldest.get("owner"),
                reason="queue cap",
            )
            opens.remove(oldest)
        now = self.now()
        review_id = self.data.get("review_seq", 0) + 1
        review = {
            "id": review_id,
            "kind": "scope",
            "scope": scope,
            "reason": reason[:256],
            "created": now,
            "expires": now + REVIEW_TTL,
            "state": "open",
        }
        if isinstance(memory, int) and not isinstance(memory, bool) and memory >= 0:
            review["mem"] = memory
        reviews.append(review)
        self.data["review_seq"] = review_id
        self.dirty = True
        return dict(review)

    def leftover_expiry_due(self, scope, days, now=None):
        """Whether explicit leftover expiry has reached the age of its first review."""
        try:
            days = float(days)
        except (TypeError, ValueError):
            return False
        if not scope or days <= 0:
            return False
        now = self.now() if now is None else now
        expiries = self.data.setdefault("leftover_expiries", {})
        created = expiries.get(scope)
        if not isinstance(created, (int, float)) or isinstance(created, bool):
            reviews = [
                r
                for r in self.data.get("reviews", [])
                if isinstance(r, dict)
                and r.get("scope") == scope
                and isinstance(r.get("created"), (int, float))
            ]
            starts = [r["created"] for r in reviews]
            starts.extend(
                p.get("review_expiries", {}).get(scope)
                for p in self.data.get("pairs", {}).values()
                if isinstance(p, dict)
                and isinstance(p.get("review_expiries"), dict)
                and isinstance(p["review_expiries"].get(scope), (int, float))
            )
            if not starts:
                return False
            created = min(starts)
        if now - created < days * DAY:
            return False
        if expiries.get(scope) != created:
            expiries[scope] = created
            self.dirty = True
            self.log(event="leftover_expiry_authorized", scope=scope, days=days)
        for review in self.data.get("reviews", []):
            if (
                isinstance(review, dict)
                and review.get("scope") == scope
                and review.get("state") == "open"
            ):
                review.update(
                    state="leftover_expired", closed=now, reason="leftover_expire_days"
                )
                self.dirty = True
        return True

    def leftover_expiry_overrides_keep(self, owner, leftover, scope, days, now=None):
        """Configured expiry can override only a keep created by unanswered-review expiry."""
        if not self.leftover_expiry_due(scope, days, now=now):
            return False
        pair = self.data.get("pairs", {}).get(self.pkey(owner, leftover))
        if not pair or pair.get("ex_source") != "review_expiry":
            return False
        return pair.get("review_expiries", {}).get(scope) == self.data[
            "leftover_expiries"
        ].get(scope)

    def prune_leftover_expiries(self, live_scopes):
        """Bound persisted expiry markers once their leftover scope has disappeared."""
        expiries = self.data.get("leftover_expiries", {})
        stale = set(expiries) - set(live_scopes)
        if stale:
            for scope in stale:
                del expiries[scope]
            self.dirty = True

    def prune_scope_reviews(self, live_scopes):
        """Drop GC scope reviews after their scopes no longer exist."""
        reviews = self.data.get("reviews", [])
        kept = [
            r
            for r in reviews
            if not (
                isinstance(r, dict)
                and r.get("kind") == "scope"
                and r.get("scope") not in live_scopes
            )
        ]
        if len(kept) != len(reviews):
            self.data["reviews"] = kept
            self.dirty = True

    def answer(self, owner, leftover, choice, source="explicit"):
        """Record an answer at weight 3, kept in ex_* counters that decay never touches.

        Explicit answers clear contrary inferred evidence and regret suspension; review-expiry
        keeps use the same safe default while retaining their source for configured expiry policy.
        """
        if choice not in CHOICES or not self._ok(owner, leftover):
            return False
        if choice == "never":
            if not self.answer(owner, leftover, "keep", source=source):
                return False
            return (
                self.add_veto(
                    "app", leftover, reason="never stop survivor from %s" % owner
                )
                is not None
            )
        if choice == "standalone":
            e = self.data["standalone"].setdefault(leftover, {"n": 0})
            e["n"] += 1
            e["ts"] = self.now()
            self.dirty = True
            return True
        if policy.bad_owner(owner, self.deny):
            return False  # an explicit answer never lands on a bad key
        existing = self.data.get("pairs", {}).get(self.pkey(owner, leftover))
        if isinstance(existing, dict) and existing.get("source") == "legacy-invalid":
            return False
        p = self._pair(owner, leftover)
        p["ex_" + choice] += W_ANSWER
        p["ex_last"] = choice
        p["ex_ts"] = self.now()
        p["ex_source"] = source
        if source != "review_expiry":
            p["review_expiries"] = {}
        if choice == "stop":
            p["keep"] = 0.0
            p["regret_keep"] = 0.0
        else:
            p["stop"] = 0.0
            p["self_stop"] = 0.0
        p["suspended_until"] = 0.0
        if choice == "keep":
            p["last_keep"] = self.now()
        return True

    def apply_answer(
        self,
        owner,
        leftovers,
        choice,
        signature=None,
        signature_id=None,
        source="explicit",
        audit_kind="answer",
        review=None,
        apply_pairs=True,
    ):
        """Apply one explicit answer to its signature and pairs under a single audit decision."""
        if (
            not isinstance(owner, str)
            or not owner
            or not isinstance(leftovers, (list, tuple))
            or not leftovers
            or choice not in CHOICES
        ):
            return False
        keys = list(dict.fromkeys(leftovers))
        if any(not self._ok(owner, key) for key in keys):
            return False
        if choice != "standalone" and policy.bad_owner(owner, self.deny):
            return False
        for key in keys:
            pair = self.data.get("pairs", {}).get(self.pkey(owner, key))
            if (
                choice not in ("standalone",)
                and isinstance(pair, dict)
                and pair.get("source") == "legacy-invalid"
            ):
                return False

        active_app_vetoes = set()
        if choice == "never":
            self._prune_vetoes()
            active = self._active_vetoes(include_pending=False)
            active_app_vetoes = {
                veto.get("value") for veto in active if veto.get("kind") == "app"
            }
            if len(active) + len(set(keys) - active_app_vetoes) > db.MAX_VETOES:
                return False

        target_signature = None
        if signature is not None:
            target_signature = self.ensure_signature(owner, signature)
        elif signature_id:
            target_signature = self.db.signature(signature_id)
            if target_signature and target_signature.get("owner") != owner:
                return False
        signature_id = target_signature.get("id") if target_signature else signature_id
        scope = review.get("scope") if isinstance(review, dict) else None
        with self.decision_context(
            audit_kind,
            scope=scope,
            owner=owner,
            authority="user",
            why="user %s %s for %d relationship(s)" % (source, choice, len(keys)),
        ):
            if signature_id:
                signature_choice = "stop" if choice == "stop" else "keep"
                self.db.answer_signature(
                    signature_id, signature_choice, W_ANSWER, now=self.now()
                )
            if apply_pairs:
                for key in keys:
                    if choice == "standalone":
                        self.answer(owner, key, "standalone", source=source)
                        self.answer(owner, key, "keep", source=source)
                    elif choice == "never":
                        self.answer(owner, key, "keep", source=source)
                        active = self._audit_context or {}
                        if key not in active_app_vetoes and not self.add_veto(
                            "app",
                            key,
                            reason="never stop survivor from %s" % owner,
                            corr=active.get("corr"),
                        ):
                            return False
                    else:
                        self.answer(owner, key, choice, source=source)
            if choice == "never" and signature_id:
                self.signature_outcome(signature_id, "veto")
            if isinstance(review, dict):
                review.update(
                    state="answered",
                    owner=owner,
                    answer=choice,
                    closed=self.now(),
                    shown=review.get("shown") or self.now(),
                )
                self.dirty = True
            self.log(
                event=audit_kind,
                review=(review or {}).get("id") if isinstance(review, dict) else None,
                owner=owner,
                choice=choice,
                leftovers=keys[:8],
                signature=signature_id,
            )
        return True

    def answer_review(self, identifier, choice, owner=None, source="review"):
        """Resolve one live close/provenance review through the shared answer path."""
        if not isinstance(identifier, int) or isinstance(identifier, bool):
            return None
        self.expire_reviews()
        review = next(
            (
                item
                for item in self.data.get("reviews", [])
                if isinstance(item, dict)
                and item.get("id") == identifier
                and item.get("state") == "open"
                and item.get("expires", 0) > self.now()
            ),
            None,
        )
        if review is None or review.get("kind") == "scope":
            return None
        if owner is None:
            owner = review.get("owner")
            if not owner:
                candidates = [
                    candidate.get("key")
                    for candidate in review.get("candidates", [])
                    if isinstance(candidate, dict)
                    and isinstance(candidate.get("key"), str)
                    and not policy.bad_owner(candidate["key"], self.deny)
                ]
                if len(candidates) == 1:
                    owner = candidates[0]
        if not isinstance(owner, str) or policy.bad_owner(owner, self.deny):
            return None
        if review.get("owner") and owner != review["owner"]:
            return None
        if review.get("kind") == "provenance-candidate":
            candidates = {
                candidate.get("key")
                for candidate in review.get("candidates", [])
                if isinstance(candidate, dict)
            }
            if owner not in candidates:
                return None
        survivors = review.get("survivors", [])
        if not self.apply_answer(
            owner,
            survivors,
            choice,
            signature_id=review.get("sig"),
            source=source,
            review=review,
        ):
            return None
        self.dirty = True
        return {
            "review": dict(review),
            "owner": owner,
            "choice": choice,
            "leftovers": list(survivors),
            "members": list(review.get("members", [])),
            "scope": review.get("scope"),
        }

    def observe_signature_close(self, signature):
        """Persist one close for a survivor signature and link its pairs for display."""
        if (
            not isinstance(signature, dict)
            or not self._ok(signature.get("owner"))
            or policy.bad_owner(signature["owner"], self.deny)
        ):
            return None
        normalized = survivor_signature.signature(
            signature["owner"],
            signature.get("members", []),
            signature.get("runtime_hash", ""),
            signature.get("runtime_class", ""),
            signature.get("tty", False),
        )
        self.db.record_signature(normalized, now=self.now(), close=True)
        for member in normalized["members"]:
            pair = self.data.get("pairs", {}).get(
                self.pkey(normalized["owner"], member["key"])
            )
            if isinstance(pair, dict):
                pair["sig"] = normalized["id"]
                pair["last_seen"] = self.now()
                self.dirty = True
        return self.db.signature(normalized["id"])

    def ensure_signature(self, owner, signature):
        """Ensure an answered owner/signature exists, without inventing a close."""
        if (
            not self._ok(owner)
            or policy.bad_owner(owner, self.deny)
            or not isinstance(signature, dict)
        ):
            return None
        normalized = survivor_signature.signature(
            owner,
            signature.get("members", []),
            signature.get("runtime_hash", ""),
            signature.get("runtime_class", ""),
            signature.get("tty", False),
        )
        self.db.record_signature(normalized, now=self.now(), close=False)
        return normalized

    def answer_signature(self, owner, signature, choice):
        """Apply an explicit no-decay answer to the whole signature, never its pairs."""
        if choice not in ("stop", "keep"):
            return False
        normalized = self.ensure_signature(owner, signature)
        if not normalized:
            return False
        return self.db.answer_signature(
            normalized["id"], choice, W_ANSWER, now=self.now()
        )

    def import_learning_document(self, document, mode="merge"):
        """Import a validated learn document. Merge adds missing answers only;
        replace swaps all learning. Imported answers start probationary."""
        if mode not in ("merge", "replace"):
            return None
        if transfer.validate_learn_document(document) is not None:
            return None
        summary = {
            "pairs_added": 0,
            "pairs_updated": 0,
            "pairs_skipped": 0,
            "pairs_removed": 0,
            "standalone_added": 0,
            "standalone_removed": 0,
            "signatures_added": 0,
            "signatures_skipped": 0,
            "signatures_removed": 0,
        }
        pairs = self.data.setdefault("pairs", {})
        if mode == "replace":
            summary["pairs_removed"] = sum(
                1
                for record in pairs.values()
                if isinstance(record, dict)
                and record.get("ex_last") in transfer.LEARN_CHOICES
            )
            pairs.clear()
            summary["standalone_removed"] = len(self.data.get("standalone", {}))
            self.data["standalone"] = {}
            summary["signatures_removed"] = self.db.clear_signatures()
        for entry in document.get("pairs", []):
            owner, leftover = entry["owner"], entry["leftover"]
            if not self._ok(owner, leftover) or policy.bad_owner(owner, self.deny):
                summary["pairs_skipped"] += 1
                continue
            key = self.pkey(owner, leftover)
            existing = pairs.get(key)
            if (
                mode == "merge"
                and isinstance(existing, dict)
                and existing.get("ex_last") in transfer.LEARN_CHOICES
            ):
                summary["pairs_skipped"] += 1
                continue
            had_answer = isinstance(existing, dict) and (
                existing.get("ex_last") in transfer.LEARN_CHOICES
            )
            record = self._pair(owner, leftover)
            record["ex_stop"] = float(entry.get("ex_stop", 0.0))
            record["ex_keep"] = float(entry.get("ex_keep", 0.0))
            record["ex_last"] = entry["ex_last"]
            record["ex_ts"] = self.now()
            record["ex_source"] = "import"
            record["source"] = "import"
            record["probation"] = 0
            if entry.get("sig") is not None:
                record["sig"] = entry["sig"]
            summary["pairs_updated" if had_answer else "pairs_added"] += 1
            self.dirty = True
        standalone = self.data.setdefault("standalone", {})
        for entry in document.get("standalone", []):
            if entry["key"] in standalone:
                continue
            standalone[entry["key"]] = {"n": int(entry.get("n", 0)), "ts": self.now()}
            summary["standalone_added"] += 1
            self.dirty = True
        for entry in document.get("signatures", []):
            current = self.db.signature(entry["id"])
            if (
                isinstance(current, dict)
                and current.get("ex_last") in ("stop", "keep")
                and mode == "merge"
            ):
                summary["signatures_skipped"] += 1
                continue
            if not self.db.record_signature(
                {
                    "id": entry["id"],
                    "owner": entry["owner"],
                    "members": entry["members"],
                    "runtime_class": entry.get("runtime") or "",
                },
                now=self.now(),
            ):
                summary["signatures_skipped"] += 1
                continue
            weight = float(
                entry.get("ex_stop" if entry["ex_last"] == "stop" else "ex_keep", 0.0)
            )
            if not self.db.answer_signature(
                entry["id"], entry["ex_last"], weight, now=self.now()
            ):
                summary["signatures_skipped"] += 1
                continue
            summary["signatures_added"] += 1
            self.dirty = True
        return summary

    def report_window(self, start, end):
        """Aggregate one report window. Guard vocabulary comes from events.py."""
        from .. import events as event_views

        return self.db.report_window(start, end, event_views.guard_event_names())

    def refresh_persisted(self):
        """Reload persisted collections from the database, dropping memory drift.

        Used after a restore replaces the database file. In-flight pending
        decisions belong to the pre-restore state and are dropped; feedback
        ids are unioned so applied operations stay deduplicated.
        """
        self._pending_decisions.clear()
        self._pending_events.clear()
        keep_ids = list(self.data.get("feedback_ids", []))
        self.data = self._fresh()
        self.db.load_state(self.data)
        merged = self.data.get("feedback_ids", [])
        self.data["feedback_ids"] = merged + [
            identifier for identifier in keep_ids if identifier not in merged
        ]
        self._decision_seq, self._event_seq = self.db.audit_sequences()
        self.dirty = False

    def reset_scope(self, scope):
        """Clear learning, vetoes, history, or all. Returns a summary, None for bad scope."""
        if scope not in ("learning", "vetoes", "history", "all"):
            return None
        summary = {}
        if scope in ("learning", "all"):
            pairs = self.data.setdefault("pairs", {})
            summary["pairs_removed"] = sum(
                1
                for record in pairs.values()
                if isinstance(record, dict)
                and record.get("ex_last") in transfer.LEARN_CHOICES
            )
            pairs.clear()
            summary["standalone_removed"] = len(self.data.get("standalone", {}))
            self.data["standalone"] = {}
            summary["signatures_removed"] = self.db.clear_signatures()
        if scope in ("vetoes", "all"):
            summary["vetoes_removed"] = len(self.data.get("vetoes", []))
            self.data["vetoes"] = []
        if scope in ("history", "all"):
            decisions, events = self.db.clear_decisions_events()
            summary["decisions_removed"] = decisions
            summary["events_removed"] = events
            summary["auto_actions_removed"] = len(self.data.get("auto_actions", []))
            self.data["auto_actions"] = []
            self._pending_decisions.clear()
            self._pending_events.clear()
        self.dirty = True
        return summary

    def match_signature(self, signature):
        """Match exact id, then same-key ±1 counts in the same runtime class."""
        if not isinstance(signature, dict):
            return None
        exact = self.db.signature(signature.get("id"))
        if exact and exact.get("owner") == signature.get("owner"):
            return exact
        current = survivor_signature.member_counts(signature.get("members", []))
        if not current:
            return None
        matches = []
        for candidate in self.db.signatures_for_owner(signature.get("owner")):
            previous = survivor_signature.member_counts(candidate.get("members"))
            if (
                previous
                and previous.keys() == current.keys()
                and candidate.get("runtime") == signature.get("runtime_class", "")
                and all(abs(previous[key] - current[key]) <= 1 for key in current)
            ):
                distance = sum(abs(previous[key] - current[key]) for key in current)
                matches.append(
                    (
                        distance,
                        -(candidate.get("last_seen") or 0),
                        candidate["id"],
                        candidate,
                    )
                )
        return min(matches)[-1] if matches else None

    def signature_decision(self, signature):
        """Return a matched signature decision, or ``None`` for pair fallback."""
        matched = self.match_signature(signature)
        if self._signature_suspended(matched):
            return self._suspended_signature_decision(matched)
        return self._signature_answer(matched) or self._signature_outcome_answer(
            matched
        )

    def _signature_suspended(self, matched, now=None):
        if not matched:
            return False
        now = self.now() if now is None else now
        until = matched.get("suspended_until", 0)
        return (
            isinstance(until, (int, float))
            and not isinstance(until, bool)
            and until > now
        )

    def _suspended_signature_decision(self, matched):
        until = float(matched.get("suspended_until", 0))
        days = max(1, int((until - self.now()) // DAY + 1))
        return "ask", 0.0, "signature suspended after regret for %d more day(s)" % days

    @staticmethod
    def _signature_answer(matched):
        if not matched:
            return None
        choice = matched.get("ex_last")
        weight = (
            matched.get("ex_" + str(choice), 0) if choice in ("stop", "keep") else 0
        )
        if not weight:
            return None
        return (
            choice,
            1.0,
            "signature answered %s (id %s, weight %.0f)"
            % (choice, matched["id"], weight),
        )

    def _signature_outcome_answer(self, matched):
        if (
            not matched
            or self.learn_authority != "aggressive"
            or not self.allow_self_authority
        ):
            return None
        successful = matched.get("stop_ok", 0)
        respawned = matched.get("respawn", 0)
        if (
            successful < pair_learning.SELF_AUTHORITY_SUCCESSES
            or successful <= respawned
        ):
            return None
        total = successful + respawned
        confidence = successful / total if total else 0.0
        return (
            "stop",
            confidence,
            "self-authority: signature %s has %d successful stops"
            % (matched["id"], successful),
        )

    def signature_decisions(self, signature):
        """Return inherited decisions for covered members; unmatched members use pair fallback."""
        if not isinstance(signature, dict):
            return {}
        matched = self.match_signature(signature)
        if self._signature_suspended(matched):
            _action, _confidence, reason = self._suspended_signature_decision(matched)
            suspended_at = float(matched.get("suspended_at", 0))
            result = {}
            for member in signature.get("members", []):
                if not isinstance(member, dict) or not isinstance(
                    member.get("key"), str
                ):
                    continue
                key = member["key"]
                pair = self.data.get("pairs", {}).get(
                    self.pkey(signature.get("owner"), key)
                )
                if (
                    isinstance(pair, dict)
                    and isinstance(pair.get("ex_ts"), (int, float))
                    and not isinstance(pair.get("ex_ts"), bool)
                    and pair["ex_ts"] > suspended_at
                ):
                    result[key] = self._decide(signature.get("owner"), pair)
                else:
                    result[key] = "ask", 0.0, reason
            return result
        if matched:
            answer = self._signature_answer(matched) or self._signature_outcome_answer(
                matched
            )
            if answer:
                return {
                    item["key"]: answer
                    for item in signature.get("members", [])
                    if isinstance(item, dict) and isinstance(item.get("key"), str)
                }

        current = survivor_signature.member_counts(signature.get("members", []))
        if not current:
            return {}
        candidates = []
        for candidate in self.db.signatures_for_owner(signature.get("owner")):
            previous = survivor_signature.member_counts(candidate.get("members"))
            answer = self._signature_answer(
                candidate
            ) or self._signature_outcome_answer(candidate)
            if (
                not previous
                or not answer
                or self._signature_suspended(candidate)
                or not previous.keys() < current.keys()
                or candidate.get("runtime") != signature.get("runtime_class", "")
                or not all(abs(previous[key] - current[key]) <= 1 for key in previous)
            ):
                continue
            distance = sum(abs(previous[key] - current[key]) for key in previous)
            candidates.append(
                (
                    -len(previous),
                    distance,
                    -(candidate.get("last_seen") or 0),
                    candidate["id"],
                    answer,
                    previous,
                )
            )
        if not candidates:
            return {}
        _coverage, _distance, _seen, _identifier, answer, previous = min(candidates)
        return {key: answer for key in previous}

    def signature_outcome(self, identifier, counter):
        """Increment stop, respawn, or veto evidence for one signature."""
        return self.db.increment_signature(identifier, counter, now=self.now())

    def signature_summaries(self, key, limit=20):
        """Recent signature counters for an owner or member key, suitable for `why`."""
        result = []
        for item in self.db.signatures_for_key(key, limit=limit):
            answer = (
                item.get("ex_last")
                if item.get("ex_last") in ("stop", "keep")
                else "none"
            )
            result.append(
                {
                    "id": item["id"],
                    "owner": item["owner"],
                    "members": item["members"],
                    "answer": answer,
                    "closes": item.get("closes", 0),
                    "stop_ok": item.get("stop_ok", 0),
                    "respawn": item.get("respawn", 0),
                    "probation": item.get("probation", 0),
                    "veto": item.get("veto", 0),
                }
            )
        return result

    @staticmethod
    def _signature_last_outcome(item):
        """Return the latest durable explicit answer or automatic signature outcome."""
        outcome = item.get("last_outcome")
        at = item.get("last_outcome_at")
        if outcome == "stop_ok":
            return {"decision": "stop", "outcome": outcome, "at": at}
        if outcome == "respawn":
            return {"decision": "keep", "outcome": outcome, "at": at}
        if outcome == "regret":
            return {"decision": "keep", "outcome": outcome, "at": at}
        if outcome == "answered":
            answer = item.get("ex_last")
            if answer in ("stop", "keep"):
                return {"decision": answer, "outcome": "answered", "at": at}

        # Rows predating schema 8 cannot order old automatic counters against answers.
        # Preserve their prior answer view while all new events carry durable timestamps.
        answer = item.get("ex_last")
        if answer in ("stop", "keep"):
            return {"decision": answer, "outcome": "answered", "at": None}
        return None

    def signatures_summary(self, limit=2000):
        """List signature records with the same evidence names used by ``why``."""
        result = []
        for item in self.db.signatures(limit=limit):
            decision = self.signature_decision(item)
            if decision is None:
                action, confidence, reason = "ask", 0.0, "no recorded signature answer"
            else:
                action, confidence, reason = decision
            answer = item.get("ex_last")
            answer = answer if answer in ("stop", "keep") else "none"
            result.append(
                {
                    "id": item["id"],
                    "owner": item["owner"],
                    "members": item["members"],
                    "answer": answer,
                    "decision": action,
                    "confidence": round(float(confidence), 2),
                    "why": reason,
                    "closes": item.get("closes", 0),
                    "stop_ok": item.get("stop_ok", 0),
                    "respawn": item.get("respawn", 0),
                    "probation": item.get("probation", 0),
                    "veto": item.get("veto", 0),
                    "evidence": {
                        "closes": item.get("closes", 0),
                        "stop_ok": item.get("stop_ok", 0),
                        "respawn": item.get("respawn", 0),
                        "veto": item.get("veto", 0),
                        "probation": item.get("probation", 0),
                    },
                    "last_outcome": self._signature_last_outcome(item),
                }
            )
        return result

    def legacy_invalid_summary(self, limit=1000):
        """List quarantined legacy pairs with their pending re-confirmation reviews."""
        reviews = [
            review
            for review in self.open_reviews()
            if review.get("kind") == "legacy-invalid"
        ]
        reviews = self.review_details(reviews)
        reviews_by_pair = {
            (review.get("owner"), survivor): review
            for review in reviews
            for survivor in review.get("survivors", [])
        }
        records = []
        for pair in self.pairs_summary(limit=MAX_PAIRS):
            raw = self.data.get("pairs", {}).get(
                self.pkey(pair["owner"], pair["leftover"]), {}
            )
            if raw.get("source") != "legacy-invalid":
                continue
            review = reviews_by_pair.get((pair["owner"], pair["leftover"]))
            records.append(
                {
                    **pair,
                    "source": "legacy-invalid",
                    "legacy_answer": (review or {}).get("answer"),
                    "review_id": (review or {}).get("id"),
                }
            )
        return {
            "records": records[: max(1, min(MAX_PAIRS, int(limit)))],
            "reviews": reviews,
        }

    def apps_summary(self, limit=2000):
        """List app identities and learned evidence in the shared CLI/dashboard shape."""
        identities = {item["key"]: item for item in self.db.app_identities(limit)}
        keys = set(identities)
        keys.update(self.data.get("exes", {}))
        keys.update(self.data.get("standalone", {}))
        keys.update(self.data.get("noise", {}))
        for pair_key in self.data.get("pairs", {}):
            owner, separator, leftover = pair_key.partition(SEP)
            if separator:
                keys.update((owner, leftover))

        pairs_by_key = {}
        for pair in self.pairs_summary(limit=MAX_PAIRS):
            pairs_by_key.setdefault(pair["owner"], []).append(pair)
            pairs_by_key.setdefault(pair["leftover"], []).append(pair)

        records = []
        for key in sorted(keys):
            identity = identities.get(key) or {}
            counters = self.peek(key)
            keep_weight = (
                counters["user_keep"]
                + counters["shared_hits"]
                + 0.5 * counters["respawned"]
            )
            kill_weight = counters["user_kill"]
            total_weight = keep_weight + kill_weight
            confidence = (
                abs(keep_weight - kill_weight) / total_weight if total_weight else 0.0
            )
            related_pairs = pairs_by_key.get(key, [])
            outcomes = [
                {
                    "owner": pair["owner"],
                    "leftover": pair["leftover"],
                    **pair["last_outcome"],
                }
                for pair in related_pairs
                if isinstance(pair.get("last_outcome"), dict)
                and pair["last_outcome"].get("outcome")
            ]
            outcomes.sort(key=lambda item: item.get("at") or 0, reverse=True)
            decision, why = self.default_action(key)
            records.append(
                {
                    "key": key,
                    "display": identity.get("display") or key,
                    "kind": identity.get("kind") or key.partition(":")[0],
                    "identity_confidence": identity.get("confidence"),
                    "decision": decision,
                    "confidence": round(confidence, 2),
                    "why": why,
                    "evidence": {
                        "instances": int(identity.get("instances") or 0),
                        "pairs": len(related_pairs),
                        "signatures": len(self.signature_summaries(key, limit=100)),
                        "closes": sum(
                            int(pair.get("closes", 0) or 0) for pair in related_pairs
                        ),
                        "stop_ok": sum(
                            int(pair.get("stop_ok", 0) or 0) for pair in related_pairs
                        ),
                        "respawn": sum(
                            int(pair.get("respawn", 0) or 0) for pair in related_pairs
                        ),
                        "shared_hits": round(counters["shared_hits"], 2),
                        "user_keep": round(counters["user_keep"], 2),
                        "user_kill": round(counters["user_kill"], 2),
                    },
                    "last_outcome": outcomes[0] if outcomes else None,
                }
            )
        return records[: max(1, min(db.MAX_APPS, int(limit)))]

    def note_noise(self, leftover):
        """One close classified as launcher/invalid-owner noise: counted per leftover key in
        data["noise"], never turned into a pair. Bad owners earn no evidence at all."""
        if not self._ok(leftover):
            return False
        n = self.data.setdefault("noise", {})
        n[leftover] = n.get(leftover, 0) + 1
        self.dirty = True
        return True

    def observe_close(self, owner, leftover, day=None, launcher=False):
        """A close was seen with `leftover` still running. Weight 0 evidence: counts only toward
        the burn-in. A launcher close, or a close whose owner is not a real application (see
        policy.bad_owner), is noise instead: it increments the noise counter and creates no pair."""
        if not self._ok(leftover):
            return False
        if launcher or policy.bad_owner(owner, self.deny) or not self._ok(owner):
            return self.note_noise(leftover)
        p = self._pair(owner, leftover)
        p["closes"] += 1
        p["last_close_day"] = int(self.now() // DAY) if day is None else int(day)
        self.data["closes"] += 1
        return True

    def observe_kill_inferred(self, owner, leftover, day=None):
        """The user killed `leftover` in the shell (pid vanished, kill args matched): weight 0.25.
        An invalid owner never gains pair evidence."""
        if not self._ok(owner, leftover) or policy.bad_owner(owner, self.deny):
            return False
        p = self._pair(owner, leftover)
        p["stop"] += W_INFERRED
        p["kills"] += 1
        p["inferred_kills"] += 1.0
        d = int(self.now() // DAY) if day is None else int(day)
        if d not in p["days"]:
            p["days"] = (p["days"] + [d])[-32:]
        return True

    def respawn(self, key, same_owner):
        """A stopped key came back. Counts (respawned +1) only under a different owner or when
        self-started; re-running the same command (same_owner) is not a respawn."""
        if same_owner or not isinstance(key, str) or not key:
            return False
        self.bump(key, "respawned", 1.0)
        return True

    def auto_stopped(
        self,
        owner,
        leftover,
        signature_id=None,
        stop_id=None,
        count_signature_probation=True,
    ):
        """Record a pair-authorized automatic stop and open its durable outcome window."""
        if self._ok(owner, leftover) and not policy.bad_owner(owner, self.deny):
            pair = self._pair(owner, leftover)
            now = self.now()
            signature_id = signature_id or pair.get("sig")
            if signature_id:
                pair["sig"] = signature_id
            stop_id = stop_id or _new_id()
            pair["probation"] = int(pair.get("probation", 0)) + 1
            pair["last_auto_stop"] = now
            pair["pending_stop"] = {
                "ts": now,
                "signature_id": signature_id,
                "stop_id": stop_id,
                "respawn_recorded": False,
                "stop_ok_recorded": False,
            }
            if signature_id and count_signature_probation:
                self.signature_outcome(signature_id, "probation")
            self.dirty = True

    def in_probation(self, owner, leftover, limit=None):
        """Whether this pair's next automatic stop is still inside graceful-only probation."""
        pair = self.data["pairs"].get(self.pkey(owner, leftover))
        limit = self.probation_stops if limit is None else max(0, int(limit))
        return bool(pair and int(pair.get("probation", 0)) < limit)

    def signature_in_probation(self, signature_id, limit=None):
        """Unknown signature state stays graceful-only; known signatures use their stop count."""
        if not signature_id:
            return False
        signature = self.db.signature(signature_id)
        limit = self.probation_stops if limit is None else max(0, int(limit))
        return signature is None or int(signature.get("probation", 0)) < limit

    def stop_in_probation(self, owner, leftover, limit=None):
        """Pair and linked-signature probation both constrain learned automatic stops."""
        pair = self.data["pairs"].get(self.pkey(owner, leftover))
        if self.in_probation(owner, leftover, limit):
            return True
        signature_id = pair.get("sig") if isinstance(pair, dict) else None
        return self.signature_in_probation(signature_id, limit)

    def pending_auto_stops(self):
        """Return current automatic-stop watches as immutable owner/key/pending snapshots."""
        return [
            (owner, leftover, dict(pair["pending_stop"]))
            for pair_key, pair in self.data["pairs"].items()
            if isinstance(pair, dict) and isinstance(pair.get("pending_stop"), dict)
            for owner, separator, leftover in (pair_key.partition(SEP),)
            if separator
        ]

    def auto_stop_success(self, owner, leftover, signature_id=None):
        """Record one no-respawn result after its window; duplicate observations are inert."""
        pair = self.data["pairs"].get(self.pkey(owner, leftover))
        pending = pair.get("pending_stop") if isinstance(pair, dict) else None
        if not isinstance(pending, dict) or pending.get("stop_ok_recorded"):
            return False
        recorded_signature = pending.get("signature_id")
        if signature_id and recorded_signature and signature_id != recorded_signature:
            return False
        pair["stop_ok"] = int(pair.get("stop_ok", 0)) + 1
        pair["self_stop"] = float(pair.get("self_stop", 0.0)) + W_STOP_OK
        outcome_at = self.now()
        pair["last_auto_outcome"] = {
            "decision": "stop",
            "outcome": "stop_ok",
            "at": outcome_at,
        }
        pending["stop_ok_recorded"] = True
        if recorded_signature:
            stop_id = pending.get("stop_id")
            related = [
                candidate["pending_stop"]
                for candidate in self.data["pairs"].values()
                if isinstance(candidate, dict)
                and isinstance(candidate.get("pending_stop"), dict)
                and candidate["pending_stop"].get("signature_id") == recorded_signature
                and candidate["pending_stop"].get("stop_id") == stop_id
            ]
            if not any(item.get("signature_stop_ok_recorded") for item in related):
                self.signature_outcome(recorded_signature, "stop_ok")
            for item in related:
                item["signature_stop_ok_recorded"] = True
        self.dirty = True
        return True

    def auto_stop_respawn(self, owner, leftover, signature_id=None):
        """Record a respawn inside the stop window as decaying keep evidence."""
        pair = self.data["pairs"].get(self.pkey(owner, leftover))
        pending = pair.get("pending_stop") if isinstance(pair, dict) else None
        if not isinstance(pending, dict) or pending.get("respawn_recorded"):
            return False
        recorded_signature = pending.get("signature_id")
        if signature_id and recorded_signature and signature_id != recorded_signature:
            return False
        outcome_at = self.now()
        pair["respawn"] = int(pair.get("respawn", 0)) + 1
        pair["respawn_weight"] = float(pair.get("respawn_weight", 0.0)) + W_RESPAWN
        pair["keep"] = float(pair.get("keep", 0.0)) + W_RESPAWN
        pair["last_keep"] = outcome_at
        pair["last_auto_outcome"] = {
            "decision": "keep",
            "outcome": "respawn",
            "at": outcome_at,
        }
        pending["respawn_recorded"] = True
        if recorded_signature:
            stop_id = pending.get("stop_id")
            related = [
                candidate["pending_stop"]
                for candidate in self.data["pairs"].values()
                if isinstance(candidate, dict)
                and isinstance(candidate.get("pending_stop"), dict)
                and candidate["pending_stop"].get("signature_id") == recorded_signature
                and candidate["pending_stop"].get("stop_id") == stop_id
            ]
            if not any(item.get("signature_respawn_recorded") for item in related):
                self.signature_outcome(recorded_signature, "respawn")
            for item in related:
                item["signature_respawn_recorded"] = True
        self.dirty = True
        return True

    def expire_auto_stops(self, now=None, respawn_window=None, revive_window=None):
        """Finish durable stop watches as their 60-second and revival windows elapse."""
        now = self.now() if now is None else now
        respawn_window = (
            self.respawn_window if respawn_window is None else max(0.0, respawn_window)
        )
        revive_window = (
            self.revive_window if revive_window is None else max(0.0, revive_window)
        )
        for owner, leftover, pending in self.pending_auto_stops():
            timestamp = pending.get("ts")
            if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
                continue
            if now - timestamp >= respawn_window and not pending.get(
                "respawn_recorded"
            ):
                self.auto_stop_success(owner, leftover, pending.get("signature_id"))
            if now - timestamp >= revive_window:
                pair = self.data["pairs"].get(self.pkey(owner, leftover))
                if isinstance(pair, dict):
                    pair.pop("pending_stop", None)
                    self.dirty = True

    def regret(self, owner, leftover, signature_id=None, window=None, suspend=None):
        """A same-pair revival adds durable keep evidence and suspends authority."""
        p = (
            self._pair(owner, leftover, create=False)
            if self._ok(owner, leftover)
            else None
        )
        pending = p.get("pending_stop") if p else None
        last_auto_stop = (
            pending.get("ts")
            if isinstance(pending, dict)
            else p.get("last_auto_stop")
            if p
            else 0
        )
        window = self.regret_window if window is None else max(0.0, window)
        suspend = self.regret_suspend if suspend is None else max(0.0, suspend)
        recorded_signature = (
            pending.get("signature_id") if isinstance(pending, dict) else None
        )
        if (
            not p
            or not last_auto_stop
            or self.now() - last_auto_stop > window
            or (
                signature_id
                and recorded_signature
                and signature_id != recorded_signature
            )
        ):
            return False
        regret_at = self.now()
        p["regret_keep"] = float(p.get("regret_keep", 0.0)) + W_REGRET
        p["last_keep"] = regret_at
        p["last_auto_outcome"] = {
            "decision": "keep",
            "outcome": "regret",
            "at": regret_at,
        }
        p["suspended_until"] = regret_at + suspend
        if recorded_signature:
            self.db.suspend_signature(
                recorded_signature,
                p["suspended_until"],
                now=regret_at,
                outcome="regret",
            )
        p["last_auto_stop"] = 0.0
        p.pop("pending_stop", None)
        self.dirty = True
        return True

    def standalone(self, key):
        return key in self.data["standalone"]

    def owners_of(self, leftover, limit=3):
        """Owners that historically had this leftover key, strongest first."""
        suffix = SEP + leftover
        rows = [
            (self._pweight(p) + p.get("closes", 0) * 0.01, k[: -len(suffix)])
            for k, p in self.data["pairs"].items()
            if k.endswith(suffix)
        ]
        return [o for _w, o in sorted(rows, reverse=True)[:limit]]

    def _decide(self, owner, p):
        """decide() behind the owner-hygiene gate: an invalid owner never asks, stops or keeps."""
        if isinstance(p, dict) and p.get("source") == "legacy-invalid":
            return "invalid", 0.0, "invalid legacy owner: requires review"
        why = policy.bad_owner(owner, self.deny)
        if why:
            return "invalid", 0.0, "invalid owner: %s" % why
        now = self.now()
        if isinstance(p, dict) and p.get("sig"):
            signature = self.db.signature(p["sig"])
            ex_ts = p.get("ex_ts", 0)
            if (
                self._signature_suspended(signature, now)
                and isinstance(ex_ts, (int, float))
                and not isinstance(ex_ts, bool)
                and ex_ts <= float(signature.get("suspended_at", 0))
            ):
                return self._suspended_signature_decision(signature)
        return decide(
            p,
            now,
            authority=self.learn_authority,
            allow_self_authority=self.allow_self_authority,
            learn=self.learn,
        )

    def pair_decision(self, owner, leftover):
        """(action, confidence, why); action in ask|stop|keep|standalone|invalid."""
        if self.standalone(leftover):
            return "standalone", 1.0, "answered: standalone app"
        p = self.data["pairs"].get(self.pkey(owner, leftover))
        return self._decide(owner, p)

    def pair_explicit(self, owner, leftover):
        """True when the pair decision is "stop" because the user answered it (SIGKILL is allowed
        only then). An invalid owner is never explicit."""
        return self.explicit_stop(self.pair_decision(owner, leftover))

    @staticmethod
    def explicit_stop(decision):
        """Whether a stop decision came from an explicit pair or signature answer."""
        if not isinstance(decision, (tuple, list)) or len(decision) < 3:
            return False
        action, _confidence, why = decision[:3]
        return (
            action == "stop"
            and isinstance(why, str)
            and why.startswith(("answered stop", "signature answered stop"))
        )

    def _signature_ask_key(self, signature):
        if isinstance(signature, dict):
            matched = self.match_signature(signature)
            return (matched or {}).get("id") or signature.get("id")
        return signature if isinstance(signature, str) else None

    def can_ask(self, pair, now=None, signature=None):
        """Limit questions to 3/day and one pair or survivor signature per seven days."""
        if not pair or policy.bad_owner(pair[0], self.deny):
            return False
        now = self.now() if now is None else now
        a = self.data["asked"]
        if a.get("day") == int(now // DAY) and a.get("n", 0) >= ASK_PER_DAY:
            return False
        signature_id = self._signature_ask_key(signature)
        asked_signatures = self.data.get("signature_asked", {})
        last_signature_asked = (
            asked_signatures.get(signature_id)
            if isinstance(asked_signatures, dict)
            else None
        )
        if (
            isinstance(last_signature_asked, (int, float))
            and not isinstance(last_signature_asked, bool)
            and now - last_signature_asked < ASK_PAIR_GAP
        ):
            return False
        p = self.data["pairs"].get(self.pkey(*pair))
        if p and p.get("source") == "legacy-invalid":
            return False
        return not (p and p.get("last_asked") and now - p["last_asked"] < ASK_PAIR_GAP)

    def mark_asked(self, pairs, now=None, signature=None):
        """Record one shown question: one daily count and seven-day pair/signature stamps."""
        now = self.now() if now is None else now
        a = self.data["asked"]
        day = int(now // DAY)
        if a.get("day") != day:
            a["day"], a["n"] = day, 0
        a["n"] += 1
        for o, l in pairs:
            pair = self.data["pairs"].get(self.pkey(o, l))
            if (
                self._ok(o, l)
                and not policy.bad_owner(o, self.deny)
                and not (pair and pair.get("source") == "legacy-invalid")
            ):
                self._pair(o, l)["last_asked"] = now
        signature_id = self._signature_ask_key(signature)
        if signature_id:
            signatures = self.data.setdefault("signature_asked", {})
            if not isinstance(signatures, dict):
                signatures = self.data["signature_asked"] = {}
            signatures = {
                identifier: ts
                for identifier, ts in signatures.items()
                if isinstance(ts, (int, float)) and now - ts < ASK_PAIR_GAP
            }
            signatures[signature_id] = now
            if len(signatures) > 4096:
                signatures = dict(
                    sorted(signatures.items(), key=lambda item: item[1])[-4096:]
                )
            self.data["signature_asked"] = signatures
        self.dirty = True

    def pairs_summary(self, limit=50):
        out = []
        signatures = {}
        for k, p in self.data["pairs"].items():
            owner, _, leftover = k.partition(SEP)
            action, conf, why = self._decide(owner, p)
            signature_id = p.get("sig")
            if signature_id and signature_id not in signatures:
                signatures[signature_id] = self.db.signature(signature_id)
            signature = signatures.get(signature_id)
            inherited = None
            if (
                signature
                and not self._signature_suspended(signature)
                and signature.get("ex_last") in ("stop", "keep")
            ):
                if signature.get("ex_" + signature["ex_last"], 0):
                    inherited = signature["ex_last"]
            display_why = (
                "inherited from signature %s" % signature["id"]
                if inherited and signature
                else why
            )
            out.append(
                {
                    "owner": owner,
                    "leftover": leftover,
                    "action": inherited or action,
                    "decision": inherited or action,
                    "pair_action": action,
                    "inherited": inherited,
                    "signature": p.get("sig"),
                    "confidence": round(1.0 if inherited else conf, 2),
                    "stop": round(
                        p.get("stop", 0) + p.get("self_stop", 0) + p.get("ex_stop", 0),
                        2,
                    ),
                    "keep": round(
                        p.get("keep", 0)
                        + p.get("regret_keep", 0)
                        + p.get("ex_keep", 0),
                        2,
                    ),
                    "closes": p.get("closes", 0),
                    "kills": p.get("kills", 0),
                    "stop_ok": p.get("stop_ok", 0),
                    "respawn": p.get("respawn", 0),
                    "probation": p.get("probation", 0),
                    "why": display_why,
                    "evidence": {
                        "closes": p.get("closes", 0),
                        "stop": round(
                            p.get("stop", 0)
                            + p.get("self_stop", 0)
                            + p.get("ex_stop", 0),
                            2,
                        ),
                        "keep": round(
                            p.get("keep", 0)
                            + p.get("regret_keep", 0)
                            + p.get("ex_keep", 0),
                            2,
                        ),
                        "stop_ok": p.get("stop_ok", 0),
                        "respawn": p.get("respawn", 0),
                        "probation": p.get("probation", 0),
                    },
                    "last_outcome": self._pair_last_outcome(p),
                }
            )
        out.sort(
            key=lambda r: (
                -(r["stop"] + r["keep"]),
                -r["closes"],
                r["owner"],
                r["leftover"],
            )
        )
        return out[:limit]

    @staticmethod
    def _pair_last_outcome(pair):
        pending = pair.get("pending_stop")
        candidates = []

        def add(decision, outcome, at, priority):
            timestamp = (
                float(at)
                if isinstance(at, (int, float))
                and not isinstance(at, bool)
                and math.isfinite(at)
                else None
            )
            candidates.append(
                (
                    timestamp is not None,
                    timestamp or 0.0,
                    priority,
                    decision,
                    outcome,
                    timestamp,
                )
            )

        answer = pair.get("ex_last")
        if answer in ("stop", "keep"):
            add(answer, "answered", pair.get("ex_ts"), 0)

        automatic = pair.get("last_auto_outcome")
        if (
            isinstance(automatic, dict)
            and automatic.get("decision") in ("stop", "keep")
            and automatic.get("outcome") in ("stop_ok", "respawn", "regret")
        ):
            add(
                automatic["decision"],
                automatic["outcome"],
                automatic.get("at"),
                1,
            )
        elif isinstance(pending, dict):
            if pending.get("respawn_recorded"):
                add("keep", "respawn", pending.get("ts"), 1)
            elif pending.get("stop_ok_recorded"):
                add("stop", "stop_ok", pending.get("ts"), 1)
            else:
                add("stop", "pending", pending.get("ts"), 1)
        else:
            # Older state lacks last_auto_outcome; the persisted action timestamps still
            # establish ordering against explicit answers and provide a best-effort label.
            if pair.get("respawn", 0):
                add("keep", "respawn", pair.get("last_keep"), 1)
            if pair.get("stop_ok", 0):
                add("stop", "stop_ok", pair.get("last_auto_stop"), 1)

        if not candidates:
            return {"decision": "ask", "outcome": None, "at": None}
        latest = max(candidates)
        return {
            "decision": latest[3],
            "outcome": latest[4],
            "at": latest[5],
        }

    # ---- derived defaults ----
    def default_action(self, key):
        """('share'|'kill', explanation). Learned 'share' defers a kill; it never overrides
        hard rules or detected edges."""
        r = self.peek(key)
        prior = (
            SEED_SHARE_PRIOR
            if (key in self.seeds.get("share", []) or self.is_persistent(key))
            else 0.0
        )
        score = prior + r["user_keep"] + r["shared_hits"] + 0.5 * r["respawned"]
        against = r["user_kill"] + 2
        action = "share" if score > against else "kill"
        why = (
            "score %.2f (seed %.1f + keep %.1f + shared_hits %.1f + 0.5*respawned %.1f; "
            "respawn is weighted half: supervisors restart things that were not needed) "
            "vs user_kill+2 = %.1f"
            % (score, prior, r["user_keep"], r["shared_hits"], r["respawned"], against)
        )
        return action, why

    def graceful_timeout(self, key, default):
        """(seconds, True) from the p95 of observed stop times. Never 0 and never skips SIGTERM:
        a key that is always SIGKILLed gets the 2 s floor, except every 10th stop gets the full
        default grace to re-probe (a self-sealed skip could never un-learn)."""
        r = self.peek(key)
        default = max(2.0, float(default))
        if r["killed"] >= 5 and r["sigkill_needed"] / max(r["killed"], 1.0) > 0.8:
            return (default if (r["stops"] + 1) % 10 == 0 else 2.0), True
        xs = sorted(r["term_exit_ms"])
        if len(xs) < 3:
            return default, True
        p95 = xs[min(len(xs) - 1, int(math.ceil(0.95 * len(xs))) - 1)]
        return min(60.0, max(2.0, p95 * 1.5 / 1000.0)), True

    def idle_grace(self, key, base):
        r = self.peek(key)
        return min(7200.0, max(min(120.0, float(base)), base * r["idle_grace_scale"]))

    def gc_outcome(self, key, respawned):
        """Adjust the idle grace after a GC stop: double when it came back, shrink 10% otherwise."""
        r = self.rec(key)
        r["idle_grace_scale"] = (
            r["idle_grace_scale"] * 2
            if respawned
            else max(0.2, r["idle_grace_scale"] * 0.9)
        )

    def explain(self, key):
        r = self.peek(key)
        action, why = self.default_action(key)
        t, graceful = self.graceful_timeout(key, 10)
        pairs = [
            x
            for x in self.pairs_summary(256)
            if x["leftover"] == key or x["owner"] == key
        ][:20]
        return {
            "key": key,
            "standalone": self.standalone(key),
            "pairs": pairs,
            "signatures": self.signature_summaries(key),
            "default_action": action,
            "why": why,
            "graceful_timeout_s": round(t, 1),
            "graceful": graceful,
            "counters": {c: round(r[c], 2) for c in COUNTERS},
            "term_exit_ms": r["term_exit_ms"],
            "idle_grace_scale": round(r["idle_grace_scale"], 2),
        }
