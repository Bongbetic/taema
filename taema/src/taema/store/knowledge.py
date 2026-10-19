"""Self-learning store: counters and timings per executable, with decay and an audit log.

Learned: whether an exe tends to be shared (default action), how long it takes to stop
gracefully, and how long an idle shared leaf should live. Not learned: protected list,
uid rules, configured cgroup and environment exclusions (see policy.py). No model, no network.
"""

import json
import math
import os
import re
import tempfile
import time
import uuid

from ..config import policy
from . import db

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
LOG_MAX = 1 << 20  # decisions.log rotates to decisions.log.1 at 1 MiB
MAX_EXES = 512
STALE_DAYS = 90
SCHEMA = 2
MAX_VETOES = 512
MAX_AUTO_ACTIONS = 10_000  # durable undo context; status exposes only a recent view
DAILY_EXPORT_RE = re.compile(r"^state-export-(\d{8})\.json$")
DAILY_EXPORTS_KEPT = 3

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
W_REGRET = 3.0  # keep evidence added when an auto-stopped app comes back
SILENT_KILLS = 5  # shell-observed kills ...
SILENT_DAYS = 3  # ... on this many distinct days
SILENT_RATIO = 0.9
SILENT_KEEP_FREE_DAYS = 30  # no keep evidence this long
SILENT_MIN_AGE = DAY  # pair first seen more than 24 h ago
BURN_IN_DAYS = 7  # store age ...
BURN_IN_CLOSES = 20  # ... or closes seen since creation
REGRET_WINDOW = 30 * 60.0
REGRET_SUSPEND = 7 * DAY
ASK_PER_DAY = 3
ASK_PAIR_GAP = 7 * DAY
CHOICES = ("stop", "keep", "standalone")
SEP = "\0"


def decide(p, now, created, closes_total):
    """Pure pair decision from a pair record (or None). Returns (action, confidence, why).
    Explicit answers act at once; silent stop needs the Phase 4 evidence; anything else asks."""
    if not p:
        return "ask", 0.0, "no evidence"
    if p.get("suspended_until", 0) > now:
        return (
            "ask",
            0.0,
            "suspended after regret until day +%d"
            % int((p["suspended_until"] - now) // DAY + 1),
        )
    ex_s, ex_k = p.get("ex_stop", 0), p.get("ex_keep", 0)
    stop, keep = p.get("stop", 0), p.get("keep", 0)
    if (
        ex_s or ex_k
    ):  # explicit: the last answer holds until contrary evidence outweighs it
        last = p.get("ex_last") or ("stop" if ex_s >= ex_k else "keep")
        if last == "stop" and keep < ex_s:
            return (
                "stop",
                1.0,
                "answered stop (weight %.0f), contrary %.2f" % (ex_s, keep),
            )
        if last == "keep" and stop < ex_k:
            return (
                "keep",
                1.0,
                "answered keep (weight %.0f), contrary %.2f" % (ex_k, stop),
            )
        return "ask", 0.0, "answer overturned by contrary evidence"
    if p.get("launches") and not p.get("kills"):
        return "keep", 0.5, "launcher pattern: survivors are what the job started"
    tot = stop + keep
    ratio = stop / tot if tot else 0.0
    kills, days = p.get("kills", 0), len(p.get("days", ()))
    burn = now - created >= BURN_IN_DAYS * DAY or closes_total >= BURN_IN_CLOSES
    quiet = not keep and now - p.get("last_keep", 0) > SILENT_KEEP_FREE_DAYS * DAY
    old = now - p.get("first_seen", now) > SILENT_MIN_AGE
    if (
        kills >= SILENT_KILLS
        and days >= SILENT_DAYS
        and ratio >= SILENT_RATIO
        and quiet
        and old
        and burn
    ):
        return (
            "stop",
            ratio,
            "silent: %d kills on %d days, ratio %.2f" % (kills, days, ratio),
        )
    if keep > stop and keep >= 1:
        return "keep", keep / tot, "keep evidence %.2f vs stop %.2f" % (keep, stop)
    return (
        "ask",
        ratio,
        "kills %d/%d, days %d/%d, ratio %.2f, quiet %s, old %s, burn-in %s"
        % (kills, SILENT_KILLS, days, SILENT_DAYS, ratio, quiet, old, burn),
    )


class Store:
    def __init__(self, state_dir, seeds=None, now=time.time, read_only=False, deny=()):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "state.db")
        self.legacy_path = os.path.join(state_dir, "knowledge.json")
        self.log_path = os.path.join(state_dir, "decisions.log")
        self.feedback_path = os.path.join(state_dir, "feedback.jsonl")
        self.now = now
        self.seeds = seeds or {}
        self.read_only = read_only  # CLI: the daemon is the single writer
        self.deny = tuple(deny)  # configured owner-deny entries (extend the defaults)
        self.dirty = False
        self.defer_writes = False
        self.last_save = 0.0
        self.sigs = {}  # change-detection signatures for log lines (see changed())
        self.db = db.StateDB(self.path, read_only=self.read_only, deny=self.deny)
        self.db.import_legacy(self.legacy_path, now=self.now(), deny=self.deny)
        self.recovery = self.db.load_recovery()
        self.data = self._fresh()
        self._load()
        self._decay()
        if self.recovery:
            self.log(
                event="store_recovered",
                source=self.recovery.get("source"),
                quarantined=self.recovery.get("quarantined"),
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
            "reviews": [],
            "review_seq": 0,
            "vetoes": [],
            "auto_actions": [],
            "feedback_ids": [],
            "leftover_expiries": {},
        }

    def _load(self):
        self.data = self.db.load_state(self.data)

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
        self.db.save_state(self.data, now=self.now())
        self.dirty = False
        self.last_save = self.now()

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

    def log(self, **fields):
        fields["ts"] = round(self.now(), 3)
        self._mkdir()
        try:
            if os.stat(self.log_path).st_size >= LOG_MAX:
                os.replace(self.log_path, self.log_path + ".1")
        except OSError:
            pass
        fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(fields, sort_keys=True) + "\n")

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
    def _valid_veto_target(target):
        if not isinstance(target, dict) or target.get("kind") not in (
            "scope",
            "app",
            "pid",
        ):
            return False
        value = target.get("value")
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return False
        value = str(value)
        if not value or len(value) > 256 or SEP in value:
            return False
        if target["kind"] == "pid":
            try:
                pid = int(value)
            except ValueError:
                return False
            start = target.get("start")
            return (
                pid > 1
                and isinstance(start, int)
                and not isinstance(start, bool)
                and start > 0
            )
        return isinstance(target.get("start"), type(None))

    @staticmethod
    def _target(veto):
        return {
            "kind": veto["kind"],
            "value": veto["value"],
            "start": veto.get("start"),
        }

    @staticmethod
    def describe_veto(veto):
        label = "%s %s" % (veto["kind"], veto["value"])
        if veto["kind"] == "pid" and veto.get("start") is not None:
            label += " (starttime %s)" % veto["start"]
        return label

    def add_veto(self, kind, value, start=None, identifier=None, reason=""):
        """Create a durable veto for one scope, app key, or pid/start-time instance."""
        target = {"kind": kind, "value": value, "start": start}
        if not self._valid_veto_target(target):
            return None
        target["value"] = str(target["value"])
        if identifier is not None and (
            not isinstance(identifier, str) or not identifier or len(identifier) > 128
        ):
            return None
        identifier = identifier or uuid.uuid4().hex
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
        self._prune_vetoes()
        if len(self.data["vetoes"]) >= MAX_VETOES:
            return None
        veto = {"id": identifier, **target, "created": self.now()}
        if isinstance(reason, str) and reason:
            veto["reason"] = reason[:256]
        self.data["vetoes"].append(veto)
        self.dirty = True
        self.log(event="veto_added", target=self._target(veto))
        return dict(veto)

    def remove_veto(self, target):
        """Remove only a matching veto. PID removal may omit start to clear that pid's instances."""
        if not isinstance(target, dict) or target.get("kind") not in (
            "scope",
            "app",
            "pid",
        ):
            return []
        value = target.get("value")
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return []
        value = str(value)
        start = target.get("start")
        if start is not None and (
            not isinstance(start, int) or isinstance(start, bool)
        ):
            return []
        removed = []
        keep = []
        for veto in self.data["vetoes"]:
            same = (
                isinstance(veto, dict)
                and veto.get("kind") == target["kind"]
                and veto.get("value") == value
                and (start is None or veto.get("start") == start)
            )
            (removed if same else keep).append(veto)
        if removed:
            self.data["vetoes"] = keep
            self.dirty = True
            self.log(
                event="veto_removed",
                target={"kind": target["kind"], "value": value, "start": start},
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
        known_ids = set(self.data.get("feedback_ids", []))
        paths = (self.feedback_path + ".replay", self.feedback_path)
        for path in paths:
            try:
                with open(path) as f:
                    lines = list(f)
            except OSError:
                continue
            for line in lines:
                try:
                    op = json.loads(line)
                except ValueError:
                    continue
                if (
                    not isinstance(op, dict)
                    or op.get("v") != 1
                    or op.get("id") in known_ids
                ):
                    continue
                op_id = op.get("id")
                if not isinstance(op_id, str) or not op_id or len(op_id) > 128:
                    continue
                known_ids.add(op_id)
                if op.get("op") == "veto" and self._valid_veto_target(op.get("target")):
                    target = dict(op["target"])
                    vetoes.append({"id": op_id, **target, "created": self.now()})
                elif op.get("op") == "unveto":
                    target = op.get("target")
                    if isinstance(target, dict):
                        start = target.get("start")
                        vetoes = [
                            v
                            for v in vetoes
                            if not (
                                v.get("kind") == target.get("kind")
                                and v.get("value") == str(target.get("value"))
                                and (start is None or v.get("start") == start)
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
                                vetoes.append(
                                    {
                                        "id": "%s:%d" % (op_id, index),
                                        **target,
                                        "created": self.now(),
                                    }
                                )
        return vetoes

    @staticmethod
    def _veto_expired(veto, now):
        expires = veto.get("expires")
        return (
            isinstance(expires, (int, float))
            and not isinstance(expires, bool)
            and expires <= now
        )

    def _prune_vetoes(self):
        now = self.now()
        vetoes = self.data.get("vetoes", [])
        kept = [
            veto
            for veto in vetoes
            if not isinstance(veto, dict) or not self._veto_expired(veto, now)
        ]
        if len(kept) != len(vetoes):
            self.data["vetoes"] = kept
            self.dirty = True

    def match_veto(self, scope=None, members=(), include_pending=True):
        """Return the first veto matching a scope or observed member identities."""
        for veto in self._active_vetoes(include_pending):
            kind, value = veto.get("kind"), veto.get("value")
            if (
                kind == "scope"
                and isinstance(scope, str)
                and (scope == value or scope.startswith(value.rstrip("/") + "/"))
            ):
                return dict(veto)
            for member in members or ():
                if not isinstance(member, dict):
                    continue
                if kind == "app" and value in member.get("apps", ()):
                    return dict(veto)
                if (
                    kind == "pid"
                    and str(member.get("pid")) == value
                    and (
                        member.get("start") is None
                        or member.get("start") == veto.get("start")
                    )
                ):
                    return dict(veto)
        return None

    def record_auto_action(self, scope, why, pairs=(), apps=()):
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
            "id": uuid.uuid4().hex,
            "scope": str(scope)[:256],
            "why": str(why)[:512],
            "pairs": normalized_pairs[:32],
            "apps": normalized_apps[:64],
            "ts": self.now(),
        }
        actions = self.data.setdefault("auto_actions", [])
        actions.append(action)
        del actions[:-MAX_AUTO_ACTIONS]
        self.dirty = True
        return dict(action)

    def auto_action(self, identifier=None):
        actions = [a for a in self.data.get("auto_actions", []) if isinstance(a, dict)]
        if identifier is None:
            return dict(actions[-1]) if actions else None
        action = next((a for a in actions if a.get("id") == identifier), None)
        return dict(action) if action else None

    def undo_auto_action(self, identifier=None, feedback_id=None):
        """Veto the apps from one automatic stop and add explicit keep evidence to its pairs."""
        action = self.auto_action(identifier)
        if not action:
            return None
        apps = action.get("apps") or [
            pair[1]
            for pair in action.get("pairs", [])
            if isinstance(pair, list) and len(pair) == 2
        ]
        targets = [("app", app) for app in dict.fromkeys(apps)]
        if not targets and action.get("scope"):
            targets = [("scope", action["scope"])]
        self._prune_vetoes()
        if len(self.data["vetoes"]) + len(targets) > MAX_VETOES:
            return None
        vetoes = []
        for index, (kind, value) in enumerate(targets):
            veto = self.add_veto(
                kind,
                value,
                identifier=("%s:%d" % (feedback_id, index)) if feedback_id else None,
                reason="undo automatic stop",
            )
            if veto:
                vetoes.append(veto)
        for pair in action.get("pairs", []):
            if isinstance(pair, list) and len(pair) == 2:
                self.answer(pair[0], pair[1], "keep")
        self.log(
            event="undo",
            action_id=action.get("id"),
            scope=action.get("scope"),
            vetoes=[self._target(v) for v in vetoes],
            pairs=action.get("pairs", [])[:8],
        )
        self.dirty = True
        return {"action": action, "vetoes": vetoes}

    # ---- feedback ----
    def apply_op(self, op, key):
        """One explicit user answer: keep | forget | kill. Returns False for a bad op or key."""
        if (
            op not in ("keep", "forget", "kill")
            or not isinstance(key, str)
            or not key
            or len(key) > 256
        ):
            return False
        if op == "keep":
            self.bump(key, "user_keep", 3.0)
        elif op == "kill":
            self.bump(key, "user_kill", 1.0)
        else:
            self.forget(key)
        self.log(event=op, exe=key)
        return True

    def apply_feedback_command(self, msg):
        """Apply one versioned offline-safe policy operation once, keyed by its client id."""
        if not isinstance(msg, dict) or msg.get("v") != 1:
            return None
        op_id, op = msg.get("id"), msg.get("op")
        if not isinstance(op_id, str) or not op_id or len(op_id) > 128:
            return None
        ids = self.data.setdefault("feedback_ids", [])
        if op_id in ids:
            return {"ok": True, "duplicate": True}
        if op == "veto":
            target = msg.get("target")
            if not self._valid_veto_target(target):
                return None
            veto = self.add_veto(
                target["kind"],
                target["value"],
                target.get("start"),
                identifier=op_id,
                reason=msg.get("reason", ""),
            )
            if veto is None:
                return None
            result = {"target": self._target(veto)}
        elif op == "unveto":
            target = msg.get("target")
            if not isinstance(target, dict):
                return None
            removed = self.remove_veto(target)
            result = {"removed": [self._target(v) for v in removed]}
        elif op == "undo":
            action_id = msg.get("action_id")
            if not isinstance(action_id, str) or not action_id:
                return None
            undone = self.undo_auto_action(action_id, feedback_id=op_id)
            if not undone:
                return None
            result = {
                "action_id": action_id,
                "targets": [self._target(v) for v in undone["vetoes"]],
                "pairs": undone["action"].get("pairs", []),
            }
        elif op == "vetoed":
            target, trigger = msg.get("target"), msg.get("trigger")
            if not isinstance(target, dict) or not isinstance(trigger, str):
                return None
            self.log(event="vetoed", target=target, trigger=trigger)
            result = {"target": target}
        else:
            return None
        ids.append(op_id)
        del ids[:-4096]
        self.dirty = True
        return {"ok": True, **result}

    def apply_feedback(self, path=None):
        """Replay and remove feedback.jsonl (written by the CLI while the daemon was down)."""
        path = path or self.feedback_path
        work = path + ".replay"
        if os.path.exists(path):
            try:
                if os.path.exists(
                    work
                ):  # leftover of a crash: keep it, append the new lines
                    with open(path, "rb") as src, open(work, "ab") as dst:
                        dst.write(src.read())
                    os.unlink(path)
                else:
                    os.replace(path, work)
            except OSError:
                return 0
        n = 0
        try:
            with open(work) as f:
                for line in f:
                    try:
                        m = json.loads(line)
                        if not isinstance(m, dict):
                            continue
                        if m.get("v") == 1:
                            result = self.apply_feedback_command(m)
                            if result and not result.get("duplicate"):
                                n += 1
                        elif self.apply_op(m.get("op"), m.get("key")):
                            n += 1
                    except ValueError:
                        continue
            os.unlink(work)
        except FileNotFoundError:
            return 0
        except OSError:
            pass
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

    def forget(self, key):
        self.dirty = True
        return self.data["exes"].pop(key, None) is not None

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
            "ex_stop",
            "ex_keep",
            "closes",
            "kills",
            "launches",
            "last_asked",
            "last_auto_stop",
            "last_keep",
            "suspended_until",
        ):
            p.setdefault(f, 0 if f in ("closes", "kills", "launches") else 0.0)
        p.setdefault("days", [])
        p["last_seen"] = self.now()
        self.dirty = True
        return p

    @staticmethod
    def _pweight(p):
        return (
            p.get("stop", 0)
            + p.get("keep", 0)
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

    def review_holds_scope(self, scope):
        """Pair and leftover scope reviews hold; adopt reviews for shared/unit scopes are informational."""
        return any(
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

    def add_review(self, owner, members, scope):
        """Record one durable review for members moved to a leftover scope."""
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
        }
        reviews.append(review)
        self.data["review_seq"] = review_id
        self.dirty = True
        return dict(review)

    def add_scope_review(self, scope, reason):
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
        p["keep" if choice == "stop" else "stop"] = 0.0
        p["suspended_until"] = 0.0
        if choice == "keep":
            p["last_keep"] = self.now()
        return True

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

    def auto_stopped(self, owner, leftover):
        if self._ok(owner, leftover) and not policy.bad_owner(owner, self.deny):
            self._pair(owner, leftover)["last_auto_stop"] = self.now()

    def regret(self, owner, leftover):
        """The leftover came back within 30 min of an auto-stop: keep +3, suspended for 7 days
        (the pair asks again). True when it was a regret."""
        p = (
            self._pair(owner, leftover, create=False)
            if self._ok(owner, leftover)
            else None
        )
        if (
            not p
            or not p["last_auto_stop"]
            or self.now() - p["last_auto_stop"] > REGRET_WINDOW
        ):
            return False
        p["keep"] += W_REGRET
        p["last_keep"] = self.now()
        p["suspended_until"] = self.now() + REGRET_SUSPEND
        p["last_auto_stop"] = 0.0
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
        return decide(p, self.now(), self.data["created"], self.data["closes"])

    def pair_decision(self, owner, leftover):
        """(action, confidence, why); action in ask|stop|keep|standalone|invalid."""
        if self.standalone(leftover):
            return "standalone", 1.0, "answered: standalone app"
        p = self.data["pairs"].get(self.pkey(owner, leftover))
        return self._decide(owner, p)

    def pair_explicit(self, owner, leftover):
        """True when the pair decision is "stop" because the user answered it (SIGKILL is allowed
        only then). An invalid owner is never explicit."""
        action, _conf, why = self.pair_decision(owner, leftover)
        return action == "stop" and why.startswith("answered stop")

    def can_ask(self, pair, now=None):
        """pair = (owner, leftover). At most 3 questions per day, each pair once per 7 days.
        A pair with an invalid owner is never asked about."""
        if not pair or policy.bad_owner(pair[0], self.deny):
            return False
        now = self.now() if now is None else now
        a = self.data["asked"]
        if a.get("day") == int(now // DAY) and a.get("n", 0) >= ASK_PER_DAY:
            return False
        p = self.data["pairs"].get(self.pkey(*pair))
        if p and p.get("source") == "legacy-invalid":
            return False
        return not (p and p.get("last_asked") and now - p["last_asked"] < ASK_PAIR_GAP)

    def mark_asked(self, pairs, now=None):
        """Record one question covering `pairs` [(owner, leftover)]: one daily count, per-pair stamp."""
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
        self.dirty = True

    def pairs_summary(self, limit=50):
        out = []
        for k, p in self.data["pairs"].items():
            owner, _, leftover = k.partition(SEP)
            action, conf, why = self._decide(owner, p)
            out.append(
                {
                    "owner": owner,
                    "leftover": leftover,
                    "action": action,
                    "confidence": round(conf, 2),
                    "stop": round(p.get("stop", 0) + p.get("ex_stop", 0), 2),
                    "keep": round(p.get("keep", 0) + p.get("ex_keep", 0), 2),
                    "closes": p.get("closes", 0),
                    "kills": p.get("kills", 0),
                    "why": why,
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
            "default_action": action,
            "why": why,
            "graceful_timeout_s": round(t, 1),
            "graceful": graceful,
            "counters": {c: round(r[c], 2) for c in COUNTERS},
            "term_exit_ms": r["term_exit_ms"],
            "idle_grace_scale": round(r["idle_grace_scale"], 2),
        }
