"""SQLite connection, schema migration, and persistence for :mod:`store.knowledge`."""

from contextlib import contextmanager
from collections import deque
import filecmp
import glob
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
import time
from urllib.parse import quote

from ..config import policy

BUSY_TIMEOUT_MS = 2000
SCHEMA_VERSION = 10
DAY = 86400
MAX_INSTANCES = 50_000
MAX_EVENTS = 200_000
MAX_DECISIONS = 10_000
MAX_APPS = 2_000
MAX_PAIRS = 1_000
MAX_SIGNATURES_PER_OWNER = 256
MAX_VETOES = 512
MAX_OPEN_REVIEWS = 128
INSTANCE_RETENTION = 90 * DAY
EVENT_RETENTION = 90 * DAY
DECISION_RETENTION = 180 * DAY
MEM_SAMPLE_RETENTION = 7 * DAY
MEM_ROLLUP_RETENTION = 365 * DAY
PAIR_RETENTION = 30 * DAY
REVIEW_RETENTION = 30 * DAY
LEGACY_BACKUP_RETENTION = 30 * DAY
LEGACY_EVENT_LIMIT = 10_000
PARENT_EVIDENCE = ("co_birth", "cgroup", "job", "runtime", "window", "launch")
_LEGACY_MARKER = "migration.legacy_import"
_RECOVERY_MARKER = "store.recovery"
_DAILY_EXPORT_RE = re.compile(r"^state-export-(\d{8})\.json$")

_MIGRATIONS = {
    1: """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE exes (
            key TEXT PRIMARY KEY,
            counters TEXT NOT NULL,
            term_exit_ms TEXT NOT NULL,
            idle_grace_scale REAL NOT NULL DEFAULT 1.0,
            stops INTEGER NOT NULL DEFAULT 0,
            last_seen REAL,
            payload TEXT NOT NULL
        );
        CREATE TABLE pairs (
            owner TEXT NOT NULL,
            leftover TEXT NOT NULL,
            sig TEXT,
            stop REAL DEFAULT 0,
            keep REAL DEFAULT 0,
            ex_stop REAL DEFAULT 0,
            ex_keep REAL DEFAULT 0,
            ex_last TEXT,
            ex_ts REAL,
            closes INTEGER DEFAULT 0,
            kills INTEGER DEFAULT 0,
            launches INTEGER DEFAULT 0,
            stop_ok INTEGER DEFAULT 0,
            respawn INTEGER DEFAULT 0,
            days TEXT,
            probation INTEGER DEFAULT 0,
            first_seen REAL,
            last_seen REAL,
            last_asked REAL DEFAULT 0,
            last_auto_stop REAL DEFAULT 0,
            last_keep REAL DEFAULT 0,
            suspended_until REAL DEFAULT 0,
            source TEXT DEFAULT 'observed',
            payload TEXT NOT NULL,
            PRIMARY KEY (owner, leftover)
        );
        CREATE TABLE standalone (
            key TEXT PRIMARY KEY,
            n INTEGER,
            ts REAL,
            payload TEXT NOT NULL
        );
        CREATE TABLE asked (day INTEGER PRIMARY KEY, n INTEGER NOT NULL);
        CREATE TABLE noise (key TEXT PRIMARY KEY, n INTEGER NOT NULL);
    """,
    2: """
        CREATE TABLE apps (
            key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            display TEXT,
            exe TEXT,
            dev INTEGER,
            ino INTEGER,
            desktop_id TEXT,
            unit TEXT,
            first_seen REAL,
            last_seen REAL,
            instances INTEGER NOT NULL DEFAULT 0,
            on_last_window TEXT NOT NULL DEFAULT 'ask',
            windowless_grace REAL,
            confidence TEXT NOT NULL DEFAULT 'high'
        );
        CREATE TABLE instances (
            id TEXT PRIMARY KEY,
            app TEXT NOT NULL REFERENCES apps(key),
            pid INTEGER,
            start INTEGER,
            born REAL,
            windowless REAL,
            exited REAL,
            parent_app TEXT,
            scope TEXT,
            terminal INTEGER,
            class TEXT,
            runtime TEXT,
            launched_by TEXT,
            survivors TEXT
        );
        CREATE INDEX instances_app_born ON instances(app, born);
        CREATE TABLE parents (
            app TEXT NOT NULL,
            parent TEXT NOT NULL,
            co_birth INTEGER,
            cgroup INTEGER,
            job INTEGER,
            runtime INTEGER,
            window INTEGER,
            launch INTEGER,
            last REAL,
            PRIMARY KEY (app, parent)
        );
        CREATE TABLE signatures (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            members TEXT NOT NULL,
            runtime TEXT,
            tty INTEGER,
            kind TEXT NOT NULL DEFAULT 'exit',
            closes INTEGER DEFAULT 0,
            stop_ok INTEGER DEFAULT 0,
            respawn INTEGER DEFAULT 0,
            ex_stop REAL DEFAULT 0,
            ex_keep REAL DEFAULT 0,
            ex_last TEXT,
            first_seen REAL,
            last_seen REAL
        );
        CREATE INDEX signatures_owner ON signatures(owner);
        CREATE TABLE vetoes (
            id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            match TEXT NOT NULL,
            value TEXT,
            start INTEGER,
            created REAL,
            expires REAL,
            reason TEXT,
            source TEXT,
            decision_id INTEGER,
            payload TEXT NOT NULL
        );
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            kind TEXT,
            owner TEXT,
            sig TEXT,
            scope TEXT,
            pids TEXT,
            mem INTEGER,
            created REAL,
            expires REAL,
            shown REAL,
            state TEXT NOT NULL DEFAULT 'open',
            payload TEXT NOT NULL
        );
        CREATE INDEX reviews_state_expires ON reviews(state, expires);
        CREATE TABLE auto_actions (
            id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            ts REAL,
            scope TEXT,
            payload TEXT NOT NULL
        );
        CREATE TABLE feedback_applied (
            id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL UNIQUE,
            created REAL
        );
        CREATE TABLE leftover_expiries (
            scope TEXT PRIMARY KEY,
            payload TEXT NOT NULL
        );
    """,
    3: """
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY,
            ts REAL,
            kind TEXT,
            scope TEXT,
            owner TEXT,
            sig TEXT,
            stage INTEGER,
            authority TEXT,
            why TEXT,
            freed INTEGER,
            undo TEXT,
            argv TEXT,
            cwd TEXT,
            undone REAL
        );
        CREATE INDEX decisions_ts ON decisions(ts);
        CREATE TABLE events (
            seq INTEGER PRIMARY KEY,
            ts REAL,
            event TEXT,
            decision_id INTEGER REFERENCES decisions(id),
            data TEXT
        );
        CREATE INDEX events_ts ON events(ts);
        CREATE TABLE mem_samples (
            scope_key TEXT NOT NULL,
            ts REAL NOT NULL,
            current INTEGER,
            anon INTEGER,
            file INTEGER,
            swap INTEGER,
            zswap INTEGER,
            psi10 REAL,
            PRIMARY KEY (scope_key, ts)
        );
        CREATE INDEX mem_samples_ts ON mem_samples(ts);
        CREATE TABLE mem_rollup (
            app TEXT NOT NULL,
            day INTEGER NOT NULL,
            current_p50 INTEGER,
            peak INTEGER,
            reclaimed INTEGER,
            freed INTEGER,
            frozen_s INTEGER,
            PRIMARY KEY (app, day)
        );
        CREATE TABLE frozen (
            scope TEXT PRIMARY KEY,
            since REAL,
            listeners TEXT,
            decision_id INTEGER REFERENCES decisions(id)
        );
        CREATE TABLE oom_adj (
            pid INTEGER NOT NULL,
            start INTEGER NOT NULL,
            original INTEGER,
            applied INTEGER,
            PRIMARY KEY (pid, start)
        );
    """,
    4: """
        ALTER TABLE instances ADD COLUMN parent_evidence TEXT NOT NULL DEFAULT '[]';
        ALTER TABLE instances ADD COLUMN last_seen REAL;
        CREATE INDEX parents_last ON parents(last);
    """,
    5: "",
    6: "ALTER TABLE signatures ADD COLUMN probation INTEGER NOT NULL DEFAULT 0;",
    7: """
        ALTER TABLE signatures ADD COLUMN suspended_until REAL NOT NULL DEFAULT 0;
        ALTER TABLE signatures ADD COLUMN suspended_at REAL NOT NULL DEFAULT 0;
    """,
    8: """
        ALTER TABLE signatures ADD COLUMN last_outcome TEXT;
        ALTER TABLE signatures ADD COLUMN last_outcome_at REAL;
    """,
    9: "ALTER TABLE mem_samples ADD COLUMN peak INTEGER;",
    10: "ALTER TABLE frozen ADD COLUMN source TEXT NOT NULL DEFAULT 'auto';",
}


def _dump(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _load(value, fallback):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _number(value, fallback=None):
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    ):
        return value
    return fallback


def _integer(value, fallback=0):
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -(1 << 63) <= value < (1 << 63)
    ):
        return value
    return fallback


def _text(value, fallback=None):
    return value if isinstance(value, str) else fallback


def _legacy_backup(path, now):
    """Make one private, atomic backup without modifying the legacy source."""
    for candidate in sorted(glob.glob(path + ".backup-*"), reverse=True):
        try:
            if os.path.isfile(candidate) and filecmp.cmp(
                path, candidate, shallow=False
            ):
                return candidate
        except OSError:
            continue
    stamp = int(now)
    suffix = 0
    while True:
        tail = "-%d" % suffix if suffix else ""
        destination = "%s.backup-%d%s" % (path, stamp, tail)
        if not os.path.exists(destination):
            break
        suffix += 1
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(
        prefix=".%s.backup-" % os.path.basename(path), dir=directory
    )
    try:
        with os.fdopen(descriptor, "wb") as backup:
            with open(path, "rb") as source:
                shutil.copyfileobj(source, backup)
            backup.flush()
            os.fchmod(backup.fileno(), 0o600)
            os.fsync(backup.fileno())
        os.utime(temporary, (now, now))
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.chmod(destination, 0o600)
    return destination


def _prune_legacy_backups(path, now):
    """Expire only backups created by this importer after their 30-day window."""
    pattern = re.compile(
        r"^%s\.backup-\d+(?:-\d+)?$" % re.escape(os.path.basename(path))
    )
    for candidate in glob.glob(path + ".backup-*"):
        try:
            if (
                pattern.fullmatch(os.path.basename(candidate))
                and os.path.isfile(candidate)
                and os.stat(candidate).st_mtime <= (now - LEGACY_BACKUP_RETENTION)
            ):
                os.unlink(candidate)
        except OSError:
            continue


def _read_legacy_state(path):
    try:
        with open(path, encoding="utf-8") as legacy:
            value = json.load(legacy)
    except FileNotFoundError:
        return None, "missing"
    except (OSError, UnicodeError, ValueError):
        return None, "invalid_json"
    if not isinstance(value, dict) or not isinstance(value.get("exes"), dict):
        return None, "invalid_shape"
    return value, "ready"


def _read_legacy_events(state_dir):
    """Read rotated and active audit lines oldest first; malformed lines are skipped."""
    lines = deque(maxlen=LEGACY_EVENT_LIMIT)
    for name in ("decisions.log.2", "decisions.log.1", "decisions.log"):
        try:
            with open(
                os.path.join(state_dir, name), encoding="utf-8", errors="replace"
            ) as log:
                lines.extend(log)
        except OSError:
            continue
    events = []
    for line in lines:
        try:
            item = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def _has_state(connection):
    for table in (
        "exes",
        "pairs",
        "standalone",
        "asked",
        "noise",
        "apps",
        "instances",
        "parents",
        "signatures",
        "vetoes",
        "reviews",
        "auto_actions",
        "feedback_applied",
        "leftover_expiries",
        "decisions",
        "events",
        "mem_samples",
        "mem_rollup",
        "frozen",
        "oom_adj",
    ):
        if connection.execute("SELECT 1 FROM %s LIMIT 1" % table).fetchone():
            return True
    return False


def _ensure_legacy_app(connection, key, record=None):
    if not isinstance(key, str) or not key or len(key) > 512:
        return
    record = record if isinstance(record, dict) else {}
    connection.execute(
        """INSERT OR IGNORE INTO apps
           (key, kind, display, exe, first_seen, last_seen, confidence)
           VALUES (?, 'exe', ?, ?, ?, ?, 'low')""",
        (
            key,
            key,
            key,
            _number(record.get("first_seen")),
            _number(record.get("last_seen")),
        ),
    )


def _write_legacy_state(connection, state, now, deny):
    """Insert legacy Store state once, leaving already-written SQLite rows authoritative."""
    existing_pairs = bool(connection.execute("SELECT 1 FROM pairs LIMIT 1").fetchone())
    meta = {
        "version": 2,
        "created": _number(state.get("created"), now),
        "last_decay": _number(state.get("last_decay"), now),
        "closes": _integer(state.get("closes")),
        "review_seq": _integer(state.get("review_seq")),
    }
    for key, value in meta.items():
        statement = "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)"
        if not existing_pairs or key == "version":
            statement = "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)"
        connection.execute(statement, (key, _dump(value)))

    exes = state.get("exes", {})
    if isinstance(exes, dict):
        for key, record in exes.items():
            if not isinstance(key, str) or not key or not isinstance(record, dict):
                continue
            connection.execute(
                """INSERT OR IGNORE INTO exes
                   (key, counters, term_exit_ms, idle_grace_scale, stops, last_seen, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    key,
                    _dump({name: record.get(name, 0.0) for name in _COUNTERS}),
                    _dump(record.get("term_exit_ms", [])),
                    _number(record.get("idle_grace_scale"), 1.0),
                    _integer(record.get("stops")),
                    _number(record.get("last_seen")),
                    _dump(record),
                ),
            )
            _ensure_legacy_app(connection, key, record)

    pairs = state.get("pairs", {})
    if not isinstance(pairs, dict):
        pairs = {}
    reviews = state.get("reviews", [])
    if not isinstance(reviews, list):
        reviews = []
    max_review_id = max(
        (
            _integer(review.get("id"), 0)
            for review in reviews
            if isinstance(review, dict)
        ),
        default=0,
    )
    db_review_id = connection.execute(
        "SELECT coalesce(max(id), 0) FROM reviews"
    ).fetchone()[0]
    meta_review_seq = connection.execute(
        "SELECT value FROM meta WHERE key = 'review_seq'"
    ).fetchone()
    review_seq = max(
        _integer(state.get("review_seq")),
        max_review_id,
        _integer(db_review_id),
        _integer(_load(meta_review_seq["value"], 0)) if meta_review_seq else 0,
    )
    review_order = connection.execute(
        "SELECT coalesce(max(seq), -1) + 1 FROM reviews"
    ).fetchone()[0]

    for pair_key, original in pairs.items():
        if not isinstance(pair_key, str) or not isinstance(original, dict):
            continue
        owner, separator, leftover = pair_key.partition("\0")
        if not separator or not owner or not leftover or "\0" in leftover:
            continue
        record = dict(original)
        invalid = bool(
            not isinstance(owner, str)
            or len(owner) > 256
            or policy.bad_owner(owner, deny)
            or original.get("source") == "legacy-invalid"
            or not isinstance(leftover, str)
            or len(leftover) > 256
        )
        legacy_answer = _text(record.get("ex_last"))
        explicit_stop = _number(record.get("ex_stop"), 0)
        explicit_keep = _number(record.get("ex_keep"), 0)
        has_explicit_answer = bool(
            explicit_stop or explicit_keep or legacy_answer in ("stop", "keep")
        )
        if legacy_answer not in ("stop", "keep"):
            legacy_answer = "stop" if explicit_stop >= explicit_keep else "keep"
        if invalid:
            record["source"] = "legacy-invalid"
            record["ex_stop"] = 0.0
            record["ex_keep"] = 0.0
            record["ex_last"] = None
        else:
            record["source"] = _text(record.get("source"), "legacy")
        connection.execute(
            """INSERT OR IGNORE INTO pairs
               (owner, leftover, sig, stop, keep, ex_stop, ex_keep, ex_last, ex_ts,
                closes, kills, launches, stop_ok, respawn, days, probation, first_seen,
                last_seen, last_asked, last_auto_stop, last_keep, suspended_until, source,
                payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                owner,
                leftover,
                _text(record.get("sig")),
                _number(record.get("stop"), 0),
                _number(record.get("keep"), 0),
                0 if invalid else _number(record.get("ex_stop"), 0),
                0 if invalid else _number(record.get("ex_keep"), 0),
                None if invalid else _text(record.get("ex_last")),
                _number(record.get("ex_ts")),
                _integer(record.get("closes")),
                _integer(record.get("kills")),
                _integer(record.get("launches")),
                _integer(record.get("stop_ok")),
                _integer(record.get("respawn")),
                _dump(record.get("days", [])),
                _integer(record.get("probation")),
                _number(record.get("first_seen")),
                _number(record.get("last_seen")),
                _number(record.get("last_asked"), 0),
                _number(record.get("last_auto_stop"), 0),
                _number(record.get("last_keep"), 0),
                _number(record.get("suspended_until"), 0),
                _text(record.get("source"), "legacy"),
                _dump(record),
            ),
        )
        if connection.execute("SELECT changes()").fetchone()[0] == 0:
            continue

        for app_key in (owner, leftover):
            _ensure_legacy_app(connection, app_key)
        if invalid and has_explicit_answer:
            review_seq += 1
            review_order += 1
            review = {
                "id": review_seq,
                "kind": "legacy-invalid",
                "owner": owner,
                "survivors": [leftover],
                "answer": legacy_answer,
                "reason": "legacy owner identity needs confirmation",
                "created": _number(record.get("ex_ts"), now),
                "expires": now + 14 * DAY,
                "state": "open",
            }
            connection.execute(
                """INSERT INTO reviews
                   (id, seq, kind, owner, sig, scope, pids, mem, created, expires,
                    shown, state, payload)
                   VALUES (?, ?, ?, ?, NULL, NULL, '[]', NULL, ?, ?, NULL, 'open', ?)""",
                (
                    review_seq,
                    review_order - 1,
                    "legacy-invalid",
                    owner,
                    review["created"],
                    review["expires"],
                    _dump(review),
                ),
            )
    standalone = state.get("standalone", {})
    if isinstance(standalone, dict):
        for key, value in standalone.items():
            if not isinstance(key, str) or not key:
                continue
            record = value if isinstance(value, dict) else {"n": _integer(value)}
            connection.execute(
                "INSERT OR IGNORE INTO standalone(key, n, ts, payload) VALUES (?, ?, ?, ?)",
                (
                    key,
                    _integer(record.get("n")),
                    _number(record.get("ts")),
                    _dump(record),
                ),
            )
            _ensure_legacy_app(connection, key, record)

    noise = state.get("noise", {})
    if isinstance(noise, dict):
        connection.executemany(
            "INSERT OR IGNORE INTO noise(key, n) VALUES (?, ?)",
            [
                (key, _integer(value))
                for key, value in noise.items()
                if isinstance(key, str) and key
            ],
        )

    asked = state.get("asked", {})
    if isinstance(asked, dict) and "day" in asked:
        connection.execute(
            "INSERT OR IGNORE INTO asked(day, n) VALUES (?, ?)",
            (_integer(asked.get("day")), _integer(asked.get("n"))),
        )

    review_order = connection.execute(
        "SELECT coalesce(max(seq), -1) + 1 FROM reviews"
    ).fetchone()[0]
    for review in reviews:
        if not isinstance(review, dict):
            continue
        identifier = _integer(review.get("id"), -1)
        if identifier < 0:
            continue
        connection.execute(
            """INSERT OR IGNORE INTO reviews
               (id, seq, kind, owner, sig, scope, pids, mem, created, expires,
                shown, state, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                identifier,
                review_order,
                _text(review.get("kind")),
                _text(review.get("owner")),
                _text(review.get("sig")),
                _text(review.get("scope")),
                _dump(review.get("pids", [])),
                _integer(review.get("mem"), 0),
                _number(review.get("created")),
                _number(review.get("expires")),
                _number(review.get("shown")),
                _text(review.get("state"), "open"),
                _dump(review),
            ),
        )
        if isinstance(review.get("owner"), str):
            _ensure_legacy_app(connection, review["owner"])
        survivors = review.get("survivors", [])
        if isinstance(survivors, list):
            for key in survivors:
                _ensure_legacy_app(connection, key)
        review_order += 1

    vetoes = state.get("vetoes", [])
    veto_sequence = connection.execute(
        "SELECT coalesce(max(seq), -1) + 1 FROM vetoes"
    ).fetchone()[0]
    if isinstance(vetoes, list):
        for index, veto in enumerate(vetoes):
            if not isinstance(veto, dict):
                continue
            identifier = veto.get("id") or "legacy-veto-%d" % index
            connection.execute(
                """INSERT OR IGNORE INTO vetoes
                   (id, seq, kind, match, value, start, created, expires, reason,
                    source, decision_id, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(identifier),
                    veto_sequence + index,
                    str(veto.get("kind", "")),
                    _dump({"value": veto.get("value"), "start": veto.get("start")}),
                    str(veto.get("value", "")),
                    _integer(veto.get("start"), 0)
                    if veto.get("start") is not None
                    else None,
                    _number(veto.get("created")),
                    _number(veto.get("expires")),
                    _text(veto.get("reason")),
                    _text(veto.get("source")),
                    _integer(veto.get("decision_id"), 0)
                    if veto.get("decision_id") is not None
                    else None,
                    _dump(veto),
                ),
            )
            if veto.get("kind") == "app" and isinstance(veto.get("value"), str):
                _ensure_legacy_app(connection, veto["value"])

    auto_actions = state.get("auto_actions", [])
    action_sequence = connection.execute(
        "SELECT coalesce(max(seq), -1) + 1 FROM auto_actions"
    ).fetchone()[0]
    if isinstance(auto_actions, list):
        for index, action in enumerate(auto_actions):
            if not isinstance(action, dict):
                continue
            identifier = action.get("id") or "legacy-action-%d" % index
            connection.execute(
                "INSERT OR IGNORE INTO auto_actions(id, seq, ts, scope, payload) VALUES (?, ?, ?, ?, ?)",
                (
                    str(identifier),
                    action_sequence + index,
                    _number(action.get("ts")),
                    _text(action.get("scope")),
                    _dump({**action, "id": str(identifier)}),
                ),
            )
            for key in action.get("apps", []):
                _ensure_legacy_app(connection, key)
            for pair in action.get("pairs", []):
                if isinstance(pair, list):
                    for key in pair[:2]:
                        _ensure_legacy_app(connection, key)

    feedback_ids = state.get("feedback_ids", [])
    feedback_sequence = connection.execute(
        "SELECT coalesce(max(seq), -1) + 1 FROM feedback_applied"
    ).fetchone()[0]
    if isinstance(feedback_ids, list):
        connection.executemany(
            "INSERT OR IGNORE INTO feedback_applied(id, seq, created) VALUES (?, ?, NULL)",
            [
                (str(identifier), feedback_sequence + index)
                for index, identifier in enumerate(feedback_ids)
            ],
        )

    expiries = state.get("leftover_expiries", {})
    if isinstance(expiries, dict):
        connection.executemany(
            "INSERT OR IGNORE INTO leftover_expiries(scope, payload) VALUES (?, ?)",
            [
                (scope, _dump(value))
                for scope, value in expiries.items()
                if isinstance(scope, str)
            ],
        )
    connection.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('review_seq', ?)",
        (_dump(review_seq),),
    )


def _write_legacy_events(connection, events, now):
    first = connection.execute(
        "SELECT coalesce(max(seq), 0) + 1 FROM events"
    ).fetchone()[0]
    connection.executemany(
        "INSERT INTO events(seq, ts, event, decision_id, data) VALUES (?, ?, ?, NULL, ?)",
        [
            (
                first + index,
                _number(event.get("ts"), now),
                event.get("event") if isinstance(event.get("event"), str) else "legacy",
                _dump(event),
            )
            for index, event in enumerate(events)
        ],
    )


def _trim_oldest(connection, table, key, cap, order, eligible="1"):
    count = connection.execute("SELECT count(*) FROM %s" % table).fetchone()[0]
    excess = count - cap
    if excess > 0:
        connection.execute(
            "DELETE FROM %s WHERE %s IN "
            "(SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT ?)"
            % (table, key, key, table, eligible, order),
            (excess,),
        )


def _instance_evidence(value):
    value = _load(value, []) if isinstance(value, str) else value
    if not isinstance(value, (list, tuple, set)):
        return ()
    return tuple(sorted({item for item in value if item in PARENT_EVIDENCE}))


def _change_parent_evidence(deltas, app, parent, evidence, amount):
    if not app or not parent or app == parent:
        return
    counts = deltas.setdefault((app, parent), dict.fromkeys(PARENT_EVIDENCE, 0))
    for item in evidence:
        counts[item] += amount


def _apply_parent_deltas(connection, deltas, now):
    for (app, parent), counts in deltas.items():
        if not any(counts.values()):
            continue
        values = [counts[item] for item in PARENT_EVIDENCE]
        existing = connection.execute(
            "SELECT 1 FROM parents WHERE app = ? AND parent = ?", (app, parent)
        ).fetchone()
        if existing:
            connection.execute(
                """UPDATE parents SET
                     co_birth=max(0, coalesce(co_birth, 0) + ?),
                     cgroup=max(0, coalesce(cgroup, 0) + ?),
                     job=max(0, coalesce(job, 0) + ?),
                     runtime=max(0, coalesce(runtime, 0) + ?),
                     window=max(0, coalesce(window, 0) + ?),
                     launch=max(0, coalesce(launch, 0) + ?),
                     last=max(coalesce(last, 0), ?)
                   WHERE app = ? AND parent = ?""",
                (*values, now, app, parent),
            )
        elif any(value > 0 for value in values):
            connection.execute(
                """INSERT INTO parents
                   (app, parent, co_birth, cgroup, job, runtime, window, launch, last)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (app, parent, *(max(0, value) for value in values), now),
            )
    connection.execute(
        "DELETE FROM parents WHERE coalesce(co_birth, 0) = 0 "
        "AND coalesce(cgroup, 0) = 0 AND coalesce(job, 0) = 0 "
        "AND coalesce(runtime, 0) = 0 AND coalesce(window, 0) = 0 "
        "AND coalesce(launch, 0) = 0"
    )


def _delete_instances(connection, identifiers, now):
    identifiers = list(dict.fromkeys(identifiers))
    deltas = {}
    for offset in range(0, len(identifiers), 400):
        batch = identifiers[offset : offset + 400]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT id, app, parent_app, parent_evidence FROM instances "
            "WHERE id IN (%s)" % placeholders,
            batch,
        ).fetchall()
        for row in rows:
            _change_parent_evidence(
                deltas,
                row["app"],
                row["parent_app"],
                _instance_evidence(row["parent_evidence"]),
                -1,
            )
    _apply_parent_deltas(connection, deltas, now)
    for offset in range(0, len(identifiers), 400):
        batch = identifiers[offset : offset + 400]
        placeholders = ",".join("?" for _ in batch)
        connection.execute(
            "DELETE FROM instances WHERE id IN (%s)" % placeholders, batch
        )


def _protected_instance_sql(alias="instances"):
    return """(
        EXISTS (
            SELECT 1 FROM pairs AS answer
            WHERE (answer.owner = {alias}.app OR answer.leftover = {alias}.app)
              AND (answer.ex_stop > 0 OR answer.ex_keep > 0
                   OR answer.ex_last IN ('stop', 'keep')
                   OR answer.source = 'legacy-invalid')
        )
        OR EXISTS (SELECT 1 FROM standalone AS saved WHERE saved.key = {alias}.app)
        OR EXISTS (
            SELECT 1 FROM vetoes AS veto
            WHERE (veto.expires IS NULL OR veto.expires > ?)
              AND ((veto.kind = 'app' AND veto.value = {alias}.app)
                OR (veto.kind = 'pid' AND veto.value = CAST({alias}.pid AS TEXT)
                    AND veto.start = {alias}.start)
                OR (veto.kind = 'scope' AND {alias}.scope IS NOT NULL
                    AND ({alias}.scope = veto.value
                      OR instr({alias}.scope, '/' || veto.value || '/') > 0
                      OR substr({alias}.scope, -length(veto.value)) = veto.value)))
        )
    )""".format(alias=alias)


def _prune_instances(connection, now):
    protected = _protected_instance_sql()
    stale = [
        row[0]
        for row in connection.execute(
            "SELECT id FROM instances WHERE coalesce(exited, last_seen, born) < ? "
            "AND NOT %s" % protected,
            (now - INSTANCE_RETENTION, now),
        )
    ]
    _delete_instances(connection, stale, now)

    excess = connection.execute("SELECT count(*) FROM instances").fetchone()[0]
    excess -= MAX_INSTANCES
    if excess > 0:
        oldest = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM instances WHERE NOT %s "
                "ORDER BY coalesce(exited, last_seen, born, 0), id LIMIT ?" % protected,
                (now, excess),
            )
        ]
        _delete_instances(connection, oldest, now)


def _prune_app_rows(connection, now):
    _prune_instances(connection, now)
    _prune_apps(connection, now)


def _prune_apps(connection, now):
    connection.execute("CREATE TEMP TABLE _taema_app_evictions (key TEXT PRIMARY KEY)")
    query = (
        "INSERT INTO _taema_app_evictions(key) "
        "SELECT key FROM apps AS candidate "
        "WHERE NOT EXISTS (SELECT 1 FROM pairs WHERE owner = candidate.key "
        "AND (ex_stop > 0 OR ex_keep > 0 OR ex_last IN ('stop', 'keep'))) "
        "AND NOT EXISTS (SELECT 1 FROM pairs WHERE leftover = candidate.key "
        "AND (ex_stop > 0 OR ex_keep > 0 OR ex_last IN ('stop', 'keep'))) "
        "AND NOT EXISTS (SELECT 1 FROM standalone WHERE key = candidate.key) "
        "AND NOT EXISTS (SELECT 1 FROM pairs WHERE source = 'legacy-invalid' "
        "AND (owner = candidate.key OR leftover = candidate.key)) "
        "AND NOT EXISTS (SELECT 1 FROM vetoes WHERE kind = 'app' "
        "AND value = candidate.key AND (expires IS NULL OR expires > ?)) "
        "AND NOT EXISTS (SELECT 1 FROM instances AS protected "
        "WHERE protected.app = candidate.key AND %s) "
        "ORDER BY coalesce(last_seen, 0), key "
        "LIMIT max(0, (SELECT count(*) FROM apps) - ?)"
    ) % _protected_instance_sql("protected")
    connection.execute(
        query,
        (now, now, MAX_APPS),
    )
    _delete_instances(
        connection,
        [
            row[0]
            for row in connection.execute(
                "SELECT id FROM instances WHERE app IN "
                "(SELECT key FROM _taema_app_evictions)"
            )
        ],
        now,
    )
    connection.execute(
        "DELETE FROM apps WHERE key IN (SELECT key FROM _taema_app_evictions)"
    )
    connection.execute("DROP TABLE _taema_app_evictions")


def _prune(connection, now):
    """Apply documented storage bounds without evicting active vetoes or answers."""
    _prune_instances(connection, now)

    connection.execute("DELETE FROM events WHERE ts < ?", (now - EVENT_RETENTION,))
    _trim_oldest(connection, "events", "seq", MAX_EVENTS, "coalesce(ts, 0), seq")

    connection.execute(
        "DELETE FROM vetoes WHERE expires IS NOT NULL AND expires <= ?", (now,)
    )
    decision_refs = (
        "id NOT IN (SELECT decision_id FROM vetoes WHERE decision_id IS NOT NULL) "
        "AND id NOT IN (SELECT decision_id FROM frozen WHERE decision_id IS NOT NULL) "
        "AND CASE WHEN json_valid(undo) AND "
        "json_type(undo, '$._taema_audit') = 'object' THEN "
        "CASE WHEN coalesce(json_extract(undo, '$._taema_audit.undoable'), 0) = 1 "
        "AND undone IS NULL THEN CASE WHEN kind IN ('stop', 'auto_stop') THEN NOT EXISTS ("
        "SELECT 1 FROM auto_actions WHERE "
        "json_extract(auto_actions.payload, '$.id') = "
        "json_extract(decisions.undo, '$.payload.action_id')) ELSE 1 END "
        "ELSE 1 END ELSE undo IS NULL END"
    )
    expired_ids = [
        row[0]
        for row in connection.execute(
            "SELECT id FROM decisions WHERE ts < ? AND %s "
            "ORDER BY coalesce(ts, 0), id" % decision_refs,
            (now - DECISION_RETENTION,),
        )
    ]
    connection.executemany(
        "DELETE FROM events WHERE decision_id = ?",
        [(identifier,) for identifier in expired_ids],
    )
    connection.executemany(
        "DELETE FROM decisions WHERE id = ?",
        [(identifier,) for identifier in expired_ids],
    )
    count = connection.execute("SELECT count(*) FROM decisions").fetchone()[0]
    excess = count - MAX_DECISIONS
    if excess > 0:
        old_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM decisions WHERE %s "
                "ORDER BY coalesce(ts, 0), id LIMIT ?" % decision_refs,
                (excess,),
            )
        ]
        connection.executemany(
            "DELETE FROM events WHERE decision_id = ?",
            [(identifier,) for identifier in old_ids],
        )
        connection.executemany(
            "DELETE FROM decisions WHERE id = ?",
            [(identifier,) for identifier in old_ids],
        )

    connection.execute(
        "DELETE FROM mem_samples WHERE ts < ?", (now - MEM_SAMPLE_RETENTION,)
    )
    connection.execute(
        "DELETE FROM mem_rollup WHERE day < ?",
        (int(now // DAY) - MEM_ROLLUP_RETENTION // DAY,),
    )

    connection.execute(
        "DELETE FROM pairs WHERE stop + keep + ex_stop + ex_keep = 0 "
        "AND closes = 0 AND launches = 0 AND kills = 0 "
        "AND coalesce(first_seen, last_seen, 0) < ?",
        (now - PAIR_RETENTION,),
    )
    _trim_oldest(
        connection,
        "pairs",
        "owner || char(0) || leftover",
        MAX_PAIRS,
        "coalesce(last_seen, first_seen, 0), owner, leftover",
        "source != 'legacy-invalid' AND NOT (ex_last = 'keep' AND ex_keep > stop)",
    )

    connection.execute(
        "DELETE FROM signatures WHERE id IN ("
        "SELECT id FROM (SELECT id, row_number() OVER ("
        "PARTITION BY owner ORDER BY coalesce(last_seen, 0) DESC, id) AS rank "
        "FROM signatures) WHERE rank > ?) ",
        (MAX_SIGNATURES_PER_OWNER,),
    )

    _prune_apps(connection, now)

    connection.execute(
        "DELETE FROM reviews WHERE state != 'open' "
        "AND coalesce(json_extract(payload, '$.closed'), created, 0) < ?",
        (now - REVIEW_RETENTION,),
    )
    _trim_oldest(
        connection,
        "vetoes",
        "id",
        MAX_VETOES,
        "seq",
        "expires IS NOT NULL AND expires <= %s" % float(now),
    )


class StateDB:
    """One state database; read-only clients never create or migrate it."""

    def __init__(self, path, read_only=False, deny=()):
        self.path = os.path.abspath(path)
        self.read_only = read_only
        self.deny = tuple(deny)
        self.available = os.path.isfile(self.path)
        self.recovery = None
        if read_only:
            return
        self._secure_dir()
        corrupted = self.available and not self._integrity_ok()
        quarantined = self._quarantine() if corrupted else None
        if not self.available:
            quarantined = self._latest_quarantine()
            corrupted = quarantined is not None
            if quarantined:
                self._quarantine_orphaned_sidecars(quarantined)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            self._migrate(connection)
        os.chmod(self.path, 0o600)
        self.available = True
        interrupted_recovery = self._latest_quarantine() if not corrupted else None
        if interrupted_recovery and not self._has_legacy_import_marker():
            # A crash may leave the fresh schema behind before the recovery transaction
            # commits. Without the import marker it is safe to rebuild from the snapshot.
            quarantined = interrupted_recovery
            self._quarantine()
            with self.connection() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                self._migrate(connection)
            os.chmod(self.path, 0o600)
            corrupted = True
        if corrupted:
            self._restore_after_corruption(quarantined)

    def _latest_quarantine(self):
        pattern = re.compile(
            r"^%s\.corrupt-\d{8}T\d{6}Z(?:-\d+)?$"
            % re.escape(os.path.basename(self.path))
        )
        candidates = [
            os.path.join(os.path.dirname(self.path), name)
            for name in os.listdir(os.path.dirname(self.path))
            if pattern.fullmatch(name)
        ]
        return sorted(candidates, reverse=True)[0] if candidates else None

    def _has_legacy_import_marker(self):
        with self.connection() as connection:
            return bool(
                connection.execute(
                    "SELECT 1 FROM meta WHERE key = ?", (_LEGACY_MARKER,)
                ).fetchone()
            )

    def _integrity_ok(self):
        try:
            with self.connection() as connection:
                rows = connection.execute("PRAGMA quick_check").fetchall()
            return len(rows) == 1 and rows[0][0] == "ok"
        except sqlite3.OperationalError as error:
            message = str(error).lower()
            if "locked" in message or "busy" in message:
                raise
            return False
        except sqlite3.DatabaseError:
            return False

    def _quarantine(self):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        suffix = stamp
        index = 0
        while os.path.exists("%s.corrupt-%s" % (self.path, suffix)):
            index += 1
            suffix = "%s-%d" % (stamp, index)
        quarantined = "%s.corrupt-%s" % (self.path, suffix)
        for source, destination in (
            (self.path, quarantined),
            (self.path + "-wal", quarantined + "-wal"),
            (self.path + "-shm", quarantined + "-shm"),
        ):
            if os.path.exists(source):
                os.replace(source, destination)
        self._sync_directory()
        return quarantined

    def _quarantine_orphaned_sidecars(self, quarantined):
        for suffix in ("-wal", "-shm"):
            source = self.path + suffix
            if os.path.exists(source):
                destination = quarantined + suffix
                if os.path.exists(destination):
                    destination += ".orphan"
                os.replace(source, destination)
        self._sync_directory()

    def _sync_directory(self):
        directory_fd = os.open(os.path.dirname(self.path), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _restore_after_corruption(self, quarantined):
        directory = os.path.dirname(self.path)
        exports = []
        for candidate in glob.glob(os.path.join(directory, "state-export-*.json")):
            match = _DAILY_EXPORT_RE.fullmatch(os.path.basename(candidate))
            if match:
                exports.append((match.group(1), candidate))
        exports.sort(reverse=True)

        source, state = None, None
        for _day, candidate in exports:
            loaded, status = _read_legacy_state(candidate)
            if loaded is not None:
                source, state = "daily_export", loaded
                break

        if state is None:
            legacy_path = os.path.join(directory, "knowledge.json")
            backups = []
            pattern = re.compile(r"^knowledge\.json\.backup-\d+(?:-\d+)?$")
            for candidate in glob.glob(legacy_path + ".backup-*"):
                if pattern.fullmatch(os.path.basename(candidate)):
                    try:
                        backups.append((os.stat(candidate).st_mtime, candidate))
                    except OSError:
                        continue
            backups.sort(reverse=True)
            for _modified, candidate in backups:
                loaded, status = _read_legacy_state(candidate)
                if loaded is not None:
                    source, state = "legacy_backup", loaded
                    break

        source = source or "empty"
        recovered_at = int(time.time())
        recovery = {
            "source": source,
            "recovered_at": recovered_at,
            "quarantined": os.path.basename(quarantined),
        }
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if state is not None:
                    _write_legacy_state(connection, state, recovered_at, self.deny)
                connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    (_LEGACY_MARKER, _dump("recovered")),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    (_RECOVERY_MARKER, _dump(recovery)),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self.recovery = recovery

    def load_recovery(self):
        if not self.available:
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = ?", (_RECOVERY_MARKER,)
            ).fetchone()
        value = _load(row["value"], None) if row else None
        return value if isinstance(value, dict) else None

    def clear_recovery(self):
        if self.read_only or not self.available:
            return
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM meta WHERE key = ?", (_RECOVERY_MARKER,))
            connection.commit()
        self.recovery = None

    def write_available(self):
        """Return whether the single-writer slot can be acquired within busy_timeout."""
        if self.read_only or not self.available:
            return False
        try:
            with self.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            return True
        except sqlite3.OperationalError as error:
            message = str(error).lower()
            if "locked" in message or "busy" in message:
                return False
            raise

    def latest_memory_samples(self):
        """Return the newest retained sample for each scope, without creating a store."""
        if not self.available:
            return {}
        with self.connection() as connection:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(mem_samples)")
            }
            peak = "sample.peak" if "peak" in columns else "NULL AS peak"
            rows = connection.execute(
                """SELECT sample.scope_key, sample.ts, sample.current, sample.anon,
                          sample.file, sample.swap, sample.zswap, sample.psi10, %s
                   FROM mem_samples AS sample
                   JOIN (SELECT scope_key, max(ts) AS ts FROM mem_samples
                         GROUP BY scope_key) AS latest
                     ON latest.scope_key = sample.scope_key AND latest.ts = sample.ts"""
                % peak
            ).fetchall()
        return {row["scope_key"]: dict(row) for row in rows}

    def save_memory_samples(self, samples, now=None):
        """Persist changed scope samples and update daily p50/peak rollups atomically."""
        if self.read_only or not self.available:
            return 0
        now = time.time() if now is None else float(now)
        day = int(now // DAY)
        day_start = day * DAY
        rollup_scopes = set()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if samples:
                connection.executemany(
                    """INSERT OR REPLACE INTO mem_samples
                       (scope_key, ts, current, anon, file, swap, zswap, psi10, peak)
                       VALUES (:scope_key, :ts, :current, :anon, :file, :swap,
                               :zswap, :psi10, :peak)""",
                    samples,
                )
            rollup_scopes = {sample["scope_key"] for sample in samples}
            values_by_scope = {key: [] for key in rollup_scopes}
            scope_list = sorted(rollup_scopes)
            for offset in range(0, len(scope_list), 500):
                chunk = scope_list[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    """SELECT scope_key, current FROM mem_samples
                       WHERE scope_key IN (%s) AND ts >= ? AND ts < ?
                         AND current IS NOT NULL
                       ORDER BY scope_key, current"""
                    % placeholders,
                    (*chunk, day_start, day_start + DAY),
                )
                for row in rows:
                    values_by_scope[row["scope_key"]].append(row["current"])

            peaks_by_scope = {}
            for sample in samples:
                key = sample["scope_key"]
                peak = sample.get("peak") or sample.get("current") or 0
                peaks_by_scope[key] = max(peaks_by_scope.get(key, 0), peak)
            rollups = []
            for key, values in values_by_scope.items():
                if not values:
                    continue
                middle = len(values) // 2
                current_p50 = (
                    values[middle]
                    if len(values) % 2
                    else (values[middle - 1] + values[middle]) // 2
                )
                rollups.append((key, day, current_p50, peaks_by_scope[key]))
            connection.executemany(
                """INSERT INTO mem_rollup(app, day, current_p50, peak)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(app, day) DO UPDATE SET
                     current_p50=excluded.current_p50,
                     peak=max(coalesce(mem_rollup.peak, 0), excluded.peak)""",
                rollups,
            )
            connection.execute(
                "DELETE FROM mem_samples WHERE ts < ?", (now - MEM_SAMPLE_RETENTION,)
            )
            connection.execute(
                "DELETE FROM mem_rollup WHERE day < ?",
                (day - MEM_ROLLUP_RETENTION // DAY,),
            )
            connection.commit()
        return len(samples)

    def _secure_dir(self):
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)

    @contextmanager
    def connection(self):
        if self.read_only:
            if not self.available:
                yield None
                return
            uri = "file:%s?mode=ro" % quote(self.path, safe="/")
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=BUSY_TIMEOUT_MS / 1000,
            )
        else:
            connection = sqlite3.connect(
                self.path,
                timeout=BUSY_TIMEOUT_MS / 1000,
            )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = %d" % BUSY_TIMEOUT_MS)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = NORMAL")
            if self.read_only:
                connection.execute("PRAGMA query_only = ON")
            yield connection
        finally:
            connection.close()

    def record_app_identity(self, identity, instance, now=None):
        """Persist one identity and pid/start instance."""
        return self.record_app_identities(((identity, instance),), now=now)

    def set_app_desktop(self, key, desktop_id, display, now=None):
        """Point one app row at its window app id; 0 rows when unknown."""
        if self.read_only or not self.available or not isinstance(key, str) or not key:
            return 0
        now = time.time() if now is None else now
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE apps SET desktop_id = ?, display = ?, last_seen = ? "
                "WHERE key = ?",
                (
                    (desktop_id or "")[:256] or None,
                    (display or key)[:256],
                    now,
                    key,
                ),
            )
            connection.commit()
        return cursor.rowcount

    def set_app_last_window(self, key, value, now=None):
        """Record the learned last-window policy for one app; 0 rows when unknown."""
        if self.read_only or not self.available or not isinstance(key, str) or not key:
            return 0
        if value not in ("ask", "quit", "keep"):
            return 0
        now = time.time() if now is None else now
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE apps SET on_last_window = ?, last_seen = ? WHERE key = ?",
                (value, now, key),
            )
            connection.commit()
        return cursor.rowcount

    def app_identity(self, key):
        """Read the bounded presentation and executable evidence for one app key."""
        if not self.available or not isinstance(key, str) or not key:
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT key, kind, display, exe, dev, ino, desktop_id, unit, "
                "on_last_window, first_seen, last_seen, instances, confidence "
                "FROM apps WHERE key = ?",
                (key,),
            ).fetchone()
        return dict(row) if row else None

    def app_identities(self, limit=MAX_APPS):
        """Read the bounded application identity catalogue for learner views."""
        if not self.available:
            return []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT key, kind, display, exe, dev, ino, desktop_id, unit, "
                "first_seen, last_seen, instances, confidence FROM apps "
                "ORDER BY key LIMIT ?",
                (max(1, min(MAX_APPS, int(limit))),),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_app_instance(self, key):
        """Read the most recently observed pid/start provenance row for one app key."""
        if not self.available or not isinstance(key, str) or not key:
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT id, app, pid, start, born, exited, last_seen, parent_app, scope, terminal, "
                "class, runtime, launched_by, parent_evidence FROM instances WHERE app = ? "
                "ORDER BY coalesce(born, 0) DESC, id DESC LIMIT 1",
                (key,),
            ).fetchone()
        return dict(row) if row else None

    def provenance_chain(self, key, max_depth=8):
        """Read the latest retained parent chain and per-parent evidence support."""
        if (
            not self.available
            or not isinstance(key, str)
            or not key
            or not isinstance(max_depth, int)
            or isinstance(max_depth, bool)
            or max_depth < 1
        ):
            return None
        with self.connection() as connection:
            first = connection.execute(
                "SELECT id, app, pid, start, born, exited, last_seen, parent_app, scope, terminal, "
                "class, runtime, launched_by, parent_evidence FROM instances "
                "WHERE app = ? ORDER BY coalesce(born, 0) DESC, id DESC LIMIT 1",
                (key,),
            ).fetchone()
            if not first:
                return None
            result = dict(first)
            chain = []
            seen = set()
            current = key
            while current and current not in seen and len(chain) < max_depth:
                seen.add(current)
                instance = (
                    first
                    if current == key
                    else connection.execute(
                        "SELECT id, app, pid, start, born, exited, last_seen, parent_app, scope, terminal, "
                        "class, runtime, launched_by, parent_evidence FROM instances "
                        "WHERE app = ? ORDER BY coalesce(born, 0) DESC, id DESC LIMIT 1",
                        (current,),
                    ).fetchone()
                )
                if not instance:
                    break
                parent = instance["parent_app"]
                app_row = connection.execute(
                    "SELECT display FROM apps WHERE key = ?", (current,)
                ).fetchone()
                display = app_row["display"] if app_row else current
                relation = None
                if parent:
                    candidates = connection.execute(
                        "SELECT parent, coalesce(co_birth, 0) AS co_birth, "
                        "coalesce(cgroup, 0) AS cgroup, coalesce(job, 0) AS job, "
                        "coalesce(runtime, 0) AS runtime, coalesce(window, 0) AS window, "
                        "coalesce(launch, 0) AS launch FROM parents WHERE app = ?",
                        (current,),
                    ).fetchall()
                    selected = next(
                        (row for row in candidates if row["parent"] == parent), None
                    )
                    if selected:
                        counts = {
                            item: selected[item]
                            for item in PARENT_EVIDENCE
                            if selected[item] > 0
                        }
                        support = sum(counts.values())
                        total = sum(
                            sum(row[item] for item in PARENT_EVIDENCE)
                            for row in candidates
                        )
                        relation = {
                            "parent": parent,
                            "parent_display": None,
                            "evidence_counts": counts,
                            "confidence": support / total if total else None,
                        }
                    else:
                        relation = {
                            "parent": parent,
                            "parent_display": None,
                            "evidence_counts": {},
                            "confidence": None,
                        }
                    parent_row = connection.execute(
                        "SELECT display FROM apps WHERE key = ?", (parent,)
                    ).fetchone()
                    relation["parent_display"] = (
                        parent_row["display"] if parent_row else parent
                    )
                chain.append({"app": current, "display": display, "relation": relation})
                current = parent
            result["chain"] = chain
            result["chain_text"] = " ← ".join(
                [item["display"] or item["app"] for item in chain]
                + (
                    [chain[-1]["relation"]["parent_display"]]
                    if chain and chain[-1]["relation"]
                    else []
                )
            )
            return result

    def record_app_identities(self, identities, now=None):
        """Persist one observe pass of identities in a single bounded transaction."""
        if self.read_only or not self.available:
            return 0
        now = time.time() if now is None else now
        apps, instances = {}, {}
        for identity, instance in identities:
            key = getattr(identity, "key", None)
            pid, start = instance.get("pid"), instance.get("start")
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 512
                or not isinstance(pid, int)
                or isinstance(pid, bool)
                or not isinstance(start, int)
                or isinstance(start, bool)
            ):
                continue
            instance_id = "%d:%d" % (pid, start)
            first_seen = _number(instance.get("born"), now)
            display = _text(getattr(identity, "display", ""), "")[:256]
            exe = _text(getattr(identity, "exe", ""), "")[:256]
            kind = _text(getattr(identity, "kind", "comm"), "comm")[:32]
            desktop_id = (_text(getattr(identity, "desktop_id")) or "")[:256] or None
            unit = (_text(getattr(identity, "unit")) or "")[:256] or None
            runtime = (
                _text(instance.get("runtime") or getattr(identity, "runtime", None))
                or ""
            )[:128] or None
            confidence = "high" if getattr(identity, "validated", False) else "low"
            apps[key] = (
                key,
                kind,
                display or key,
                exe,
                getattr(identity, "device", None),
                getattr(identity, "inode", None),
                desktop_id,
                unit,
                first_seen,
                now,
                confidence,
            )
            instances[instance_id] = (
                instance_id,
                key,
                pid,
                start,
                first_seen,
                (_text(instance.get("parent_app")) or "")[:512] or None,
                (_text(instance.get("scope")) or "")[:1024] or None,
                instance.get("terminal"),
                _text(instance.get("class") or kind, kind)[:64],
                runtime,
                (_text(instance.get("launched_by")) or "")[:256] or None,
                _number(instance.get("exited")),
                _dump(_instance_evidence(instance.get("parent_evidence"))),
                now,
            )
        if not apps:
            return 0

        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous_instances = {}
                ids = list(instances)
                for offset in range(0, len(ids), 400):
                    batch = ids[offset : offset + 400]
                    placeholders = ",".join("?" for _ in batch)
                    previous_instances.update(
                        {
                            row["id"]: row
                            for row in connection.execute(
                                "SELECT id, app, parent_app, parent_evidence "
                                "FROM instances WHERE id IN (%s)" % placeholders,
                                batch,
                            )
                        }
                    )
                connection.executemany(
                    """INSERT INTO apps
                       (key, kind, display, exe, dev, ino, desktop_id, unit,
                        first_seen, last_seen, instances, confidence)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                       ON CONFLICT(key) DO UPDATE SET
                         kind=excluded.kind, display=excluded.display, exe=excluded.exe,
                         dev=excluded.dev, ino=excluded.ino,
                         desktop_id=coalesce(excluded.desktop_id, apps.desktop_id),
                         unit=coalesce(excluded.unit, apps.unit),
                         first_seen=min(coalesce(apps.first_seen, excluded.first_seen), excluded.first_seen),
                         last_seen=max(coalesce(apps.last_seen, excluded.last_seen), excluded.last_seen),
                         confidence=excluded.confidence""",
                    apps.values(),
                )
                parent_deltas = {}
                for row in instances.values():
                    old = previous_instances.get(row[0])
                    new_relation = (row[1], row[5])
                    new_evidence = _instance_evidence(row[12])
                    if old:
                        old_relation = (old["app"], old["parent_app"])
                        old_evidence = _instance_evidence(old["parent_evidence"])
                        if old_relation == new_relation:
                            _change_parent_evidence(
                                parent_deltas,
                                *old_relation,
                                old_evidence,
                                -1,
                            )
                            _change_parent_evidence(
                                parent_deltas,
                                *new_relation,
                                new_evidence,
                                1,
                            )
                        else:
                            _change_parent_evidence(
                                parent_deltas,
                                *old_relation,
                                old_evidence,
                                -1,
                            )
                            _change_parent_evidence(
                                parent_deltas,
                                *new_relation,
                                new_evidence,
                                1,
                            )
                    else:
                        _change_parent_evidence(
                            parent_deltas,
                            *new_relation,
                            new_evidence,
                            1,
                        )
                _apply_parent_deltas(connection, parent_deltas, now)
                connection.executemany(
                    """INSERT INTO instances
                       (id, app, pid, start, born, parent_app, scope, terminal,
                        class, runtime, launched_by, exited, parent_evidence, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET app=excluded.app,
                         parent_app=excluded.parent_app, scope=excluded.scope,
                         terminal=excluded.terminal, class=excluded.class,
                         runtime=excluded.runtime,
                         launched_by=coalesce(excluded.launched_by, instances.launched_by),
                         exited=excluded.exited,
                         parent_evidence=excluded.parent_evidence,
                         last_seen=excluded.last_seen""",
                    instances.values(),
                )
                affected = set(apps)
                affected.update(row["app"] for row in previous_instances.values())
                connection.executemany(
                    "UPDATE apps SET instances=(SELECT count(*) FROM instances WHERE app=?) WHERE key=?",
                    [(key, key) for key in affected],
                )
                _prune_app_rows(connection, now)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return len(instances)

    def _migrate(self, connection):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                "state database schema %d is newer than supported schema %d"
                % (version, SCHEMA_VERSION)
            )
        while version < SCHEMA_VERSION:
            next_version = version + 1
            migration = _MIGRATIONS[next_version]
            if next_version == 5:
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'signatures'"
                ).fetchone()
                if table:
                    columns = {
                        row["name"]
                        for row in connection.execute("PRAGMA table_info(signatures)")
                    }
                    statements = []
                    if "runtime_hash" not in columns:
                        statements.append(
                            "ALTER TABLE signatures ADD COLUMN runtime_hash TEXT;"
                        )
                    if "veto" not in columns:
                        statements.append(
                            "ALTER TABLE signatures ADD COLUMN veto INTEGER NOT NULL DEFAULT 0;"
                        )
                    statements.append(
                        "CREATE INDEX IF NOT EXISTS signatures_owner ON signatures(owner);"
                    )
                    migration = "\n".join(statements)
                else:
                    migration = """
                        CREATE TABLE signatures (
                            id TEXT PRIMARY KEY,
                            owner TEXT NOT NULL,
                            members TEXT NOT NULL,
                            runtime TEXT,
                            tty INTEGER,
                            kind TEXT NOT NULL DEFAULT 'exit',
                            closes INTEGER DEFAULT 0,
                            stop_ok INTEGER DEFAULT 0,
                            respawn INTEGER DEFAULT 0,
                            ex_stop REAL DEFAULT 0,
                            ex_keep REAL DEFAULT 0,
                            ex_last TEXT,
                            first_seen REAL,
                            last_seen REAL,
                            runtime_hash TEXT,
                            veto INTEGER NOT NULL DEFAULT 0
                        );
                        CREATE INDEX signatures_owner ON signatures(owner);
                    """
            if next_version == 9:
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mem_samples'"
                ).fetchone()
                if not table:
                    migration = ""
            if next_version == 10:
                table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'frozen'"
                ).fetchone()
                if table:
                    columns = {
                        row["name"]
                        for row in connection.execute("PRAGMA table_info(frozen)")
                    }
                    migration = (
                        ""
                        if "source" in columns
                        else "ALTER TABLE frozen ADD COLUMN source TEXT NOT NULL DEFAULT 'auto';"
                    )
                else:
                    migration = ""
            script = (
                "BEGIN IMMEDIATE;\n"
                + migration
                + "\nPRAGMA user_version = %d;\nCOMMIT;" % next_version
            )
            try:
                connection.executescript(script)
            except sqlite3.Error:
                if connection.in_transaction:
                    connection.rollback()
                raise
            version = next_version

    def import_legacy(self, path, now=None, deny=()):
        """Import the old JSON store and audit trail exactly once, in one transaction."""
        if self.read_only:
            return "read_only"
        now = time.time() if now is None else now
        _prune_legacy_backups(path, now)
        with self.connection() as connection:
            marker = connection.execute(
                "SELECT value FROM meta WHERE key = ?", (_LEGACY_MARKER,)
            ).fetchone()
        if marker:
            return _load(marker["value"], "complete")

        backup = _legacy_backup(path, now) if os.path.isfile(path) else None
        state, state_status = _read_legacy_state(path)
        events = _read_legacy_events(os.path.dirname(path))
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                marker = connection.execute(
                    "SELECT value FROM meta WHERE key = ?", (_LEGACY_MARKER,)
                ).fetchone()
                if marker:
                    connection.commit()
                    return _load(marker["value"], "complete")
                existing_state = _has_state(connection)
                if state is not None:
                    _write_legacy_state(connection, state, now, deny)
                    status = "merged" if existing_state else "imported"
                else:
                    status = state_status
                if events:
                    _write_legacy_events(connection, events, now)
                    if status == "missing":
                        status = "audit_only"
                connection.execute(
                    "INSERT INTO meta(key, value) VALUES (?, ?)",
                    (_LEGACY_MARKER, _dump(status)),
                )
                if backup:
                    connection.execute(
                        "INSERT INTO meta(key, value) VALUES (?, ?)",
                        ("migration.legacy_backup", _dump(backup)),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return status

    @staticmethod
    def _signature(row):
        if row is None:
            return None
        result = dict(row)
        result["members"] = _load(result.get("members"), [])
        return result

    def record_signature(self, signature, now=None, close=False):
        """Persist a canonical signature, optionally counting one observed close."""
        if self.read_only or not self.available:
            return False
        now = time.time() if now is None else now
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """INSERT INTO signatures
                       (id, owner, members, runtime, runtime_hash, tty, closes,
                        first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                         members=excluded.members, runtime=excluded.runtime,
                         runtime_hash=excluded.runtime_hash, tty=excluded.tty,
                         closes=coalesce(signatures.closes, 0) + ?,
                         last_seen=excluded.last_seen""",
                    (
                        signature["id"],
                        signature["owner"],
                        _dump(signature["members"]),
                        signature.get("runtime_class", ""),
                        signature.get("runtime_hash", ""),
                        int(bool(signature.get("tty"))),
                        1 if close else 0,
                        now,
                        now,
                        1 if close else 0,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return True

    def signature(self, identifier):
        """Read one signature record."""
        if not self.available or not isinstance(identifier, str):
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM signatures WHERE id = ?", (identifier,)
            ).fetchone()
        return self._signature(row)

    def signatures(self, limit=2000):
        """Read recent signatures for the bounded learner view."""
        if not self.available:
            return []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM signatures ORDER BY "
                "coalesce(last_seen, first_seen, 0) DESC, id LIMIT ?",
                (max(1, min(10_000, int(limit))),),
            ).fetchall()
        return [self._signature(row) for row in rows]

    def signatures_for_owner(self, owner):
        """Read the bounded signature history for an owner, newest first."""
        if not self.available or not isinstance(owner, str):
            return []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM signatures WHERE owner = ? "
                "ORDER BY coalesce(last_seen, first_seen, 0) DESC, id LIMIT ?",
                (owner, MAX_SIGNATURES_PER_OWNER),
            ).fetchall()
        return [self._signature(row) for row in rows]

    def signatures_for_key(self, key, limit=20):
        """Read recent signatures where a key was the owner or a survivor."""
        if not self.available or not isinstance(key, str):
            return []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM signatures AS signature WHERE owner = ? OR EXISTS ("
                "SELECT 1 FROM json_each(signature.members) AS member "
                "WHERE json_extract(member.value, '$.key') = ?) "
                "ORDER BY coalesce(last_seen, first_seen, 0) DESC, id LIMIT ?",
                (key, key, max(1, min(100, int(limit)))),
            ).fetchall()
        return [self._signature(row) for row in rows]

    def forget_signatures_for_key(self, key, preserve=(), include=()):
        """Drop signature learning for an app, retaining signatures protected by vetoes."""
        if not self.available or not isinstance(key, str):
            return []
        with self.connection() as connection:
            if connection is None:
                return []
            if not self.read_only:
                connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT id FROM signatures WHERE owner = ? OR EXISTS ("
                    "SELECT 1 FROM json_each(signatures.members) AS member "
                    "WHERE json_extract(member.value, '$.key') = ?) ",
                    (key, key),
                ).fetchall()
                identifiers = list(
                    dict.fromkeys([row["id"] for row in rows] + list(include))
                )
                if not self.read_only:
                    protected = set(preserve)
                    for identifier in identifiers:
                        if identifier in protected:
                            connection.execute(
                                "UPDATE signatures SET closes = 0, stop_ok = 0, "
                                "respawn = 0, ex_stop = 0, ex_keep = 0, ex_last = NULL, "
                                "probation = 0, veto = 0, suspended_until = 0, "
                                "suspended_at = 0, last_outcome = NULL, "
                                "last_outcome_at = NULL WHERE id = ?",
                                (identifier,),
                            )
                        else:
                            connection.execute(
                                "DELETE FROM signatures WHERE id = ?", (identifier,)
                            )
                    connection.commit()
            except Exception:
                if not self.read_only:
                    connection.rollback()
                raise
        return identifiers

    def history_timeline(self, owner=None, scope=None, since=None, limit=500):
        """Decisions, linked events, and launches for one owner or scope."""
        if not self.available:
            return {"decisions": [], "events": [], "launches": []}
        since = since if isinstance(since, (int, float)) else 0
        bare = owner is not None and owner == scope
        clauses, params = ["ts >= ?"], [since]
        if bare:
            clauses.append("(owner = ? OR scope = ? OR scope = ?)")
            params.extend([owner, scope, "scope-" + owner])
        elif owner is not None and scope is not None:
            clauses.append("(owner = ? OR scope = ?)")
            params.extend([owner, scope])
        elif owner is not None:
            clauses.append("owner = ?")
            params.append(owner)
        else:
            clauses.append("scope = ?")
            params.append(scope)
        where = " AND ".join(clauses)
        with self.connection() as connection:
            decisions = [
                dict(row)
                for row in connection.execute(
                    "SELECT id, ts, kind, scope, owner, authority, why, undone "
                    "FROM decisions WHERE %s ORDER BY ts DESC, id DESC LIMIT ?" % where,
                    (*params, limit),
                )
            ]
            ids = [row["id"] for row in decisions if isinstance(row["id"], int)]
            events = []
            if ids:
                placeholders = ",".join("?" for _ in ids)
                events = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT seq, ts, event, decision_id, data FROM events "
                        "WHERE decision_id IN (%s) ORDER BY seq" % placeholders,
                        ids,
                    )
                ]
            seen = {row["seq"] for row in events}
            extra_clauses, extra_params = ["ts >= ?"], [since]
            if bare:
                extra_clauses.append(
                    "(json_extract(data, '$.owner') = ? "
                    "OR json_extract(data, '$.scope') = ? "
                    "OR json_extract(data, '$.scope') = ?)"
                )
                extra_params.extend([owner, scope, "scope-" + owner])
            elif owner is not None and scope is not None:
                extra_clauses.append(
                    "(json_extract(data, '$.owner') = ? "
                    "OR json_extract(data, '$.scope') = ?)"
                )
                extra_params.extend([owner, scope])
            elif owner is not None:
                extra_clauses.append("json_extract(data, '$.owner') = ?")
                extra_params.append(owner)
            else:
                extra_clauses.append("json_extract(data, '$.scope') = ?")
                extra_params.append(scope)
            for row in connection.execute(
                "SELECT seq, ts, event, decision_id, data FROM events WHERE %s "
                "ORDER BY seq LIMIT ?" % " AND ".join(extra_clauses),
                (*extra_params, limit * 4),
            ):
                if row["seq"] not in seen:
                    seen.add(row["seq"])
                    events.append(dict(row))
            launches = []
            if owner is not None:
                launches = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT app, pid, start, born, scope FROM instances "
                        "WHERE app = ? AND born >= ? ORDER BY born DESC LIMIT 100",
                        (owner, since),
                    )
                ]
            elif scope is not None:
                launches = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT app, pid, start, born, scope FROM instances "
                        "WHERE scope = ? AND born >= ? ORDER BY born DESC LIMIT 100",
                        (scope, since),
                    )
                ]
        events.sort(key=lambda row: row["seq"])
        return {"decisions": decisions, "events": events, "launches": launches}

    def recent_auto_actions(self, limit=50):
        """Newest automatic actions with freed bytes and restore possibility."""
        if not self.available:
            return []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT id, seq, ts, scope, payload FROM auto_actions "
                "ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
            actions = []
            for row in rows:
                try:
                    payload = json.loads(row["payload"] or "{}")
                except ValueError:
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                actions.append(
                    {
                        "id": row["id"],
                        "ts": row["ts"],
                        "scope": row["scope"],
                        "why": payload.get("why", ""),
                        "pairs": payload.get("pairs", []),
                        "decision_id": payload.get("decision_id"),
                    }
                )
            ids = [
                action["decision_id"]
                for action in actions
                if isinstance(action["decision_id"], int)
            ]
            restore, freed = {}, {}
            if ids:
                placeholders = ",".join("?" for _ in ids)
                for row in connection.execute(
                    "SELECT id, argv, cwd FROM decisions WHERE id IN (%s)"
                    % placeholders,
                    ids,
                ):
                    try:
                        argv = json.loads(row["argv"]) if row["argv"] else None
                    except ValueError:
                        argv = None
                    restore[row["id"]] = bool(argv and row["cwd"])
                for row in connection.execute(
                    "SELECT decision_id, "
                    "SUM(CAST(json_extract(data, '$.freed_bytes') AS INTEGER)) "
                    "FROM events WHERE event = 'freed' AND decision_id IN (%s) "
                    "GROUP BY decision_id" % placeholders,
                    ids,
                ):
                    freed[row["decision_id"]] = row[1] or 0
        for action in actions:
            decision_id = action["decision_id"]
            action["freed_bytes"] = freed.get(decision_id, 0)
            action["restore_possible"] = restore.get(decision_id, False)
        return actions

    def report_window(self, start, end, guard_events):
        """Aggregate decisions, events, reviews, and rollups for one window."""
        empty = {
            "stops": {"automatic": 0, "answered": 0},
            "memory_freed_bytes": {"stop": 0, "reclaim": 0},
            "undos": 0,
            "regrets": 0,
            "reviews": {"answered": 0, "expired": 0},
            "guard_events": {"total": 0, "by_event": {}},
            "top_leftovers": [],
            "frozen": {
                "frozen_seconds": 0,
                "thaws": 0,
                "connection_thaws": 0,
                "frozen_now": 0,
            },
            "rollups": [],
        }
        if not self.available:
            return empty
        with self.connection() as connection:
            kinds = dict(
                connection.execute(
                    "SELECT kind, COUNT(*) FROM decisions "
                    "WHERE ts >= ? AND ts < ? AND kind IN "
                    "('auto_stop', 'stop', 'undo') GROUP BY kind",
                    (start, end),
                ).fetchall()
            )
            empty["stops"]["automatic"] = kinds.get("auto_stop", 0)
            empty["stops"]["answered"] = kinds.get("stop", 0)
            empty["undos"] = kinds.get("undo", 0)
            stop_bytes = connection.execute(
                "SELECT SUM(CAST(json_extract(data, '$.freed_bytes') AS INTEGER)) "
                "FROM events WHERE event = 'freed' AND ts >= ? AND ts < ?",
                (start, end),
            ).fetchone()[0]
            reclaim_bytes = connection.execute(
                "SELECT SUM(CAST(json_extract(data, '$.reclaim.reclaimed_bytes') "
                "AS INTEGER)) FROM events WHERE event = 'gc_quit' "
                "AND ts >= ? AND ts < ?",
                (start, end),
            ).fetchone()[0]
            empty["memory_freed_bytes"]["stop"] = stop_bytes or 0
            empty["memory_freed_bytes"]["reclaim"] = reclaim_bytes or 0
            empty["regrets"] = connection.execute(
                "SELECT COUNT(*) FROM events WHERE event = 'regret' "
                "AND ts >= ? AND ts < ?",
                (start, end),
            ).fetchone()[0]
            empty["reviews"]["answered"] = connection.execute(
                "SELECT COUNT(*) FROM reviews WHERE state = 'answered' "
                "AND shown >= ? AND shown < ?",
                (start, end),
            ).fetchone()[0]
            empty["reviews"]["expired"] = connection.execute(
                "SELECT COUNT(*) FROM events WHERE event = 'review_expired' "
                "AND ts >= ? AND ts < ?",
                (start, end),
            ).fetchone()[0]
            if guard_events:
                placeholders = ",".join("?" for _ in guard_events)
                by_event = dict(
                    connection.execute(
                        "SELECT event, COUNT(*) FROM events WHERE event IN (%s) "
                        "AND ts >= ? AND ts < ? GROUP BY event" % placeholders,
                        (*sorted(guard_events), start, end),
                    ).fetchall()
                )
                empty["guard_events"]["by_event"] = by_event
                empty["guard_events"]["total"] = sum(by_event.values())
            empty["top_leftovers"] = [
                {
                    "leftover": row["leftover"],
                    "launches": row["launches"],
                    "closes": row["closes"],
                    "kills": row["kills"],
                }
                for row in connection.execute(
                    "SELECT leftover, launches, closes, kills FROM pairs "
                    "ORDER BY launches + closes + kills DESC LIMIT 10"
                )
            ]
            freeze_thaw = connection.execute(
                "SELECT ts, event, json_extract(data, '$.scope') AS scope, "
                "json_extract(data, '$.reason') AS reason FROM events "
                "WHERE event IN ('freeze', 'thaw') AND ts >= ? AND ts < ? "
                "ORDER BY ts",
                (start, end),
            ).fetchall()
            frozen_since = {}
            frozen_seconds = 0
            thaws = 0
            connection_thaws = 0
            for row in freeze_thaw:
                scope = row["scope"] or ""
                if row["event"] == "freeze":
                    frozen_since.setdefault(scope, row["ts"])
                else:
                    thaws += 1
                    if (row["reason"] or "") == "connect":
                        connection_thaws += 1
                    began = frozen_since.pop(scope, None)
                    if began is not None:
                        frozen_seconds += max(0, row["ts"] - began)
            for began in frozen_since.values():
                frozen_seconds += max(0, end - began)
            empty["frozen"]["frozen_seconds"] = int(frozen_seconds)
            empty["frozen"]["thaws"] = thaws
            empty["frozen"]["connection_thaws"] = connection_thaws
            try:
                empty["frozen"]["frozen_now"] = connection.execute(
                    "SELECT COUNT(*) FROM frozen"
                ).fetchone()[0]
            except Exception:
                pass
            start_day = int(start // 86400)
            end_day = int(end // 86400)
            empty["rollups"] = [
                {
                    "app": row["app"],
                    "peak": row["peak"],
                    "current_p50": row["current_p50"],
                }
                for row in connection.execute(
                    "SELECT app, MAX(peak) AS peak, MAX(current_p50) AS current_p50 "
                    "FROM mem_rollup WHERE day >= ? AND day <= ? GROUP BY app "
                    "ORDER BY peak DESC LIMIT 5",
                    (start_day, end_day),
                )
            ]
        return empty

    def reset_counts(self):
        """Row counts for the reset plan display."""
        if not self.available:
            return {"signatures": 0, "decisions": 0, "events": 0}
        with self.connection() as connection:
            return {
                table: connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[
                    0
                ]
                for table in ("signatures", "decisions", "events")
            }

    def clear_decisions_events(self):
        """Delete all decision and event rows. Returns (decisions, events)."""
        if self.read_only or not self.available:
            return (0, 0)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                decisions = connection.execute(
                    "SELECT COUNT(*) FROM decisions"
                ).fetchone()[0]
                events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                connection.execute("DELETE FROM events")
                connection.execute("DELETE FROM decisions")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return (decisions, events)

    def clear_signatures(self):
        """Delete all signature rows. Returns the removed count."""
        if self.read_only or not self.available:
            return 0
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                count = connection.execute(
                    "SELECT COUNT(*) FROM signatures"
                ).fetchone()[0]
                connection.execute("DELETE FROM signatures")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return count

    def answer_signature(self, identifier, choice, weight, now=None):
        """Add no-decay explicit answer weight to a signature."""
        if self.read_only or not self.available or choice not in ("stop", "keep"):
            return False
        now = time.time() if now is None else now
        column = "ex_" + choice
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    "UPDATE signatures SET %s = coalesce(%s, 0) + ?, ex_last = ?, "
                    "last_seen = ?, suspended_until = 0, suspended_at = 0, "
                    "last_outcome = 'answered', last_outcome_at = ? WHERE id = ?"
                    % (column, column),
                    (weight, choice, now, now, identifier),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return cursor.rowcount == 1

    def suspend_signature(self, identifier, until, now=None, outcome=None):
        """Suspend authority and optionally persist an attributed regret outcome."""
        if (
            self.read_only
            or not self.available
            or not isinstance(identifier, str)
            or not isinstance(until, (int, float))
            or isinstance(until, bool)
            or not math.isfinite(until)
            or outcome not in (None, "regret")
        ):
            return False
        now = time.time() if now is None else now
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if outcome == "regret":
                    cursor = connection.execute(
                        "UPDATE signatures SET suspended_until = ?, suspended_at = ?, "
                        "last_seen = ?, last_outcome = 'regret', last_outcome_at = ? "
                        "WHERE id = ?",
                        (until, now, now, now, identifier),
                    )
                else:
                    cursor = connection.execute(
                        "UPDATE signatures SET suspended_until = ?, suspended_at = ?, "
                        "last_seen = ? WHERE id = ?",
                        (until, now, now, identifier),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return cursor.rowcount == 1

    def increment_signature(self, identifier, counter, amount=1, now=None):
        """Increment a bounded signature outcome counter."""
        if (
            self.read_only
            or not self.available
            or counter not in ("stop_ok", "respawn", "veto", "probation")
            or not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount < 1
        ):
            return False
        now = time.time() if now is None else now
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if counter in ("stop_ok", "respawn"):
                    cursor = connection.execute(
                        "UPDATE signatures SET %s = coalesce(%s, 0) + ?, "
                        "last_seen = ?, last_outcome = ?, last_outcome_at = ? "
                        "WHERE id = ?" % (counter, counter),
                        (amount, now, counter, now, identifier),
                    )
                else:
                    cursor = connection.execute(
                        "UPDATE signatures SET %s = coalesce(%s, 0) + ?, "
                        "last_seen = ? WHERE id = ?" % (counter, counter),
                        (amount, now, identifier),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return cursor.rowcount == 1

    def load_state(self, data):
        if not self.available:
            return data
        with self.connection() as connection:
            connection.execute("BEGIN")
            for row in connection.execute("SELECT key, value FROM meta"):
                if (
                    row["key"].startswith("migration.")
                    or row["key"] == _RECOVERY_MARKER
                ):
                    continue
                data[row["key"]] = _load(row["value"], row["value"])

            for row in connection.execute("SELECT key, payload FROM exes"):
                payload = _load(row["payload"], {})
                if isinstance(payload, dict):
                    data["exes"][row["key"]] = payload

            for row in connection.execute("SELECT owner, leftover, payload FROM pairs"):
                payload = _load(row["payload"], {})
                if isinstance(payload, dict):
                    key = row["owner"] + "\0" + row["leftover"]
                    data["pairs"][key] = payload

            for row in connection.execute("SELECT key, payload FROM standalone"):
                payload = _load(row["payload"], {})
                if isinstance(payload, dict):
                    data["standalone"][row["key"]] = payload

            for row in connection.execute("SELECT key, n FROM noise"):
                data["noise"][row["key"]] = row["n"]

            asked = connection.execute(
                "SELECT day, n FROM asked ORDER BY day DESC LIMIT 1"
            ).fetchone()
            if asked is not None:
                data["asked"] = {"day": asked["day"], "n": asked["n"]}

            data["reviews"] = [
                payload
                for row in connection.execute(
                    "SELECT payload FROM reviews ORDER BY seq"
                )
                if isinstance((payload := _load(row["payload"], None)), dict)
            ]
            data["vetoes"] = [
                payload
                for row in connection.execute("SELECT payload FROM vetoes ORDER BY seq")
                if isinstance((payload := _load(row["payload"], None)), dict)
            ]
            data["auto_actions"] = [
                payload
                for row in connection.execute(
                    "SELECT payload FROM auto_actions ORDER BY seq"
                )
                if isinstance((payload := _load(row["payload"], None)), dict)
            ]
            data["feedback_ids"] = [
                row["id"]
                for row in connection.execute(
                    "SELECT id FROM feedback_applied ORDER BY seq"
                )
            ]
            data["leftover_expiries"] = {
                row["scope"]: _load(row["payload"], None)
                for row in connection.execute(
                    "SELECT scope, payload FROM leftover_expiries"
                )
            }
            frozen = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'frozen'"
            ).fetchone()
            if frozen:
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(frozen)")
                }
                source = "source" if "source" in columns else "'auto' AS source"
                data["frozen_scopes"] = {
                    row["scope"]: {
                        "since": _number(row["since"], 0.0),
                        "listeners": _load(row["listeners"], []),
                        "decision_id": row["decision_id"],
                        "source": row["source"],
                    }
                    for row in connection.execute(
                        "SELECT scope, since, listeners, decision_id, %s FROM frozen"
                        % source
                    )
                }
        return data

    def audit_sequences(self):
        """Return persistent high-water marks for decision ids and event sequence numbers."""
        if not self.available:
            return 0, 0
        with self.connection() as connection:
            values = {
                row["key"]: _load(row["value"], 0)
                for row in connection.execute(
                    "SELECT key, value FROM meta WHERE key IN (?, ?)",
                    ("audit.decision_seq", "audit.event_seq"),
                )
            }
            decision_max = connection.execute(
                "SELECT coalesce(max(id), 0) FROM decisions"
            ).fetchone()[0]
            event_max = connection.execute(
                "SELECT coalesce(max(seq), 0) FROM events"
            ).fetchone()[0]
        return (
            max(_number(values.get("audit.decision_seq"), 0), decision_max),
            max(_number(values.get("audit.event_seq"), 0), event_max),
        )

    def events_since(self, since_seq=0, limit=1001):
        """Return retained audit events after a sequence and the event-history window."""
        if not self.available:
            return {"events": [], "oldest_seq": None, "latest_seq": 0, "more": False}
        with self.connection() as connection:
            bounds = connection.execute(
                "SELECT min(seq) AS oldest, max(seq) AS latest FROM events"
            ).fetchone()
            row = connection.execute(
                "SELECT value FROM meta WHERE key = ?", ("audit.event_seq",)
            ).fetchone()
            latest = max(
                _number(_load(row["value"], 0), 0) if row else 0,
                _number(bounds["latest"], 0),
            )
            rows = connection.execute(
                "SELECT seq, ts, event, decision_id, data FROM events "
                "WHERE seq > ? ORDER BY seq LIMIT ?",
                (since_seq, max(1, limit) + 1),
            ).fetchall()
        events = [
            {
                "seq": row["seq"],
                "ts": row["ts"],
                "event": row["event"],
                "decision_id": row["decision_id"],
                "data": _load(row["data"], {}),
            }
            for row in rows[: max(1, limit)]
        ]
        return {
            "events": events,
            "oldest_seq": bounds["oldest"],
            "latest_seq": latest,
            "more": len(rows) > max(1, limit),
        }

    @staticmethod
    def _decision(row):
        stored = _load(row["undo"], None)
        if isinstance(stored, dict) and isinstance(stored.get("_taema_audit"), dict):
            audit = stored["_taema_audit"]
            payload = stored.get("payload")
            mode = audit.get("mode") or "unknown"
            corr = audit.get("corr") or "legacy-%s" % row["id"]
            undoable = audit.get("undoable") is True
        else:
            payload = stored
            mode = "unknown"
            corr = "legacy-%s" % row["id"]
            undoable = stored is not None
        return {
            "id": row["id"],
            "ts": row["ts"] or 0,
            "kind": row["kind"] or "legacy",
            "scope": row["scope"],
            "owner": row["owner"],
            "authority": row["authority"] or "none",
            "why": row["why"] or "",
            "mode": mode,
            "corr": corr,
            "undoable": undoable and row["undone"] is None,
            "undo": payload,
            "argv": _load(row["argv"], None),
            "cwd": row["cwd"],
            "undone": row["undone"],
        }

    def decision(self, identifier):
        """Read one decision row without exposing SQLite rows to the store API."""
        if (
            not self.available
            or not isinstance(identifier, int)
            or isinstance(identifier, bool)
        ):
            return None
        with self.connection() as connection:
            row = connection.execute(
                "SELECT id, ts, kind, scope, owner, authority, why, undo, argv, cwd, undone "
                "FROM decisions WHERE id = ?",
                (identifier,),
            ).fetchone()
        return self._decision(row) if row else None

    def decisions(self, limit=50, undoable=False, kinds=None):
        """Read recent decisions, optionally limiting the result to undo targets."""
        if not self.available:
            return []
        clauses, params = [], []
        if undoable:
            clauses.append(
                "undone IS NULL AND json_valid(undo) AND "
                "coalesce(json_extract(undo, '$._taema_audit.undoable'), "
                "CASE WHEN json_type(undo, '$._taema_audit') = 'object' "
                "THEN 0 ELSE 1 END) = 1"
            )
        if kinds:
            kinds = tuple(kinds)
            if not kinds:
                return []
            clauses.append("kind IN (%s)" % ",".join("?" for _ in kinds))
            params.extend(kinds)
        predicate = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT id, ts, kind, scope, owner, authority, why, undo, argv, cwd, undone "
                "FROM decisions %s ORDER BY id DESC LIMIT ?" % predicate,
                params,
            ).fetchall()
        return [self._decision(row) for row in rows]

    def mark_decision_undone(self, identifier, at):
        """Mark one retained decision as undone without adding a schema migration."""
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE decisions SET undone = ? WHERE id = ? AND undone IS NULL",
                (at, identifier),
            )
            connection.commit()
        return cursor.rowcount == 1

    def mark_decision_restored(self, identifier, at):
        """Mark a stopped decision's one-shot relaunch in its existing undo payload."""
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE decisions SET undo = json_set(undo, '$.payload.restored_at', ?) "
                "WHERE id = ? AND json_valid(undo) "
                "AND json_type(undo, '$.payload') = 'object' "
                "AND json_type(undo, '$.payload.restored_at') IS NULL",
                (at, identifier),
            )
            connection.commit()
        return cursor.rowcount == 1

    def clear_decision_restored(self, identifier, at):
        """Release a restore reservation after the launcher could not be created."""
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE decisions SET undo = json_remove(undo, '$.payload.restored_at') "
                "WHERE id = ? AND json_valid(undo) "
                "AND json_extract(undo, '$.payload.restored_at') = ?",
                (identifier, at),
            )
            connection.commit()
        return cursor.rowcount == 1

    def save_state(
        self,
        data,
        now=None,
        decisions=(),
        events=(),
        decision_seq=None,
        event_seq=None,
    ):
        if self.read_only:
            return
        now = time.time() if now is None else now
        self._secure_dir()
        optional_meta_defaults = {
            "feedback_invalid": 0,
            "feedback_last_replay": "",
            "signature_asked": {},
            "held": False,
            "held_scopes": [],
            "snooze_until": 0.0,
            "muted_apps": [],
            "qos_scopes": {},
            "qos_exempt": {},
            "memory_scopes": {},
            "frozen_scopes": {},
            "windowless_grace": {},
            "launch_apps": {},
        }
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for key in (
                    "version",
                    "created",
                    "last_decay",
                    "closes",
                    "review_seq",
                    "signature_asked",
                    "feedback_invalid",
                    "feedback_last_replay",
                    "held",
                    "held_scopes",
                    "snooze_until",
                    "muted_apps",
                    "qos_scopes",
                    "qos_exempt",
                    "memory_scopes",
                    "windowless_grace",
                    "launch_apps",
                ):
                    value = data.get(key, optional_meta_defaults.get(key))
                    if key not in optional_meta_defaults:
                        value = data[key]
                    connection.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                        (key, _dump(value)),
                    )
                if decision_seq is not None:
                    connection.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                        ("audit.decision_seq", _dump(decision_seq)),
                    )
                if event_seq is not None:
                    connection.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                        ("audit.event_seq", _dump(event_seq)),
                    )
                connection.executemany(
                    """INSERT INTO decisions
                       (id, ts, kind, scope, owner, authority, why, undo, argv, cwd, undone)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                         ts=excluded.ts, kind=excluded.kind, scope=excluded.scope,
                         owner=excluded.owner, authority=excluded.authority,
                         why=excluded.why, undo=excluded.undo, argv=excluded.argv,
                         cwd=excluded.cwd, undone=coalesce(decisions.undone, excluded.undone)""",
                    [
                        (
                            decision["id"],
                            decision["ts"],
                            decision["kind"],
                            decision.get("scope"),
                            decision.get("owner"),
                            decision["authority"],
                            decision["why"],
                            _dump(
                                {
                                    "_taema_audit": {
                                        "mode": decision["mode"],
                                        "corr": decision["corr"],
                                        "undoable": decision.get("undoable", False),
                                    },
                                    "payload": decision.get("undo"),
                                }
                            ),
                            _dump(decision.get("argv"))
                            if decision.get("argv") is not None
                            else None,
                            decision.get("cwd"),
                            decision.get("undone"),
                        )
                        for decision in decisions
                    ],
                )
                connection.executemany(
                    """INSERT OR REPLACE INTO events
                       (seq, ts, event, decision_id, data)
                       VALUES (?, ?, ?, ?, ?)""",
                    [
                        (
                            event["seq"],
                            event["ts"],
                            event["event"],
                            event.get("decision_id"),
                            _dump(event["data"]),
                        )
                        for event in events
                    ],
                )
                connection.execute("DELETE FROM exes")
                connection.executemany(
                    """INSERT INTO exes
                       (key, counters, term_exit_ms, idle_grace_scale, stops, last_seen, payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            key,
                            _dump({name: record.get(name, 0.0) for name in _COUNTERS}),
                            _dump(record.get("term_exit_ms", [])),
                            record.get("idle_grace_scale", 1.0),
                            record.get("stops", 0),
                            record.get("last_seen"),
                            _dump(record),
                        )
                        for key, record in data["exes"].items()
                    ],
                )

                connection.execute("DELETE FROM pairs")
                pair_rows = []
                for key, record in data["pairs"].items():
                    owner, separator, leftover = key.partition("\0")
                    if not separator:
                        continue
                    pair_rows.append(
                        (
                            owner,
                            leftover,
                            record.get("sig"),
                            record.get("stop", 0),
                            record.get("keep", 0),
                            record.get("ex_stop", 0),
                            record.get("ex_keep", 0),
                            record.get("ex_last"),
                            record.get("ex_ts"),
                            record.get("closes", 0),
                            record.get("kills", 0),
                            record.get("launches", 0),
                            record.get("stop_ok", 0),
                            record.get("respawn", 0),
                            _dump(record.get("days", [])),
                            record.get("probation", 0),
                            record.get("first_seen"),
                            record.get("last_seen"),
                            record.get("last_asked", 0),
                            record.get("last_auto_stop", 0),
                            record.get("last_keep", 0),
                            record.get("suspended_until", 0),
                            record.get("source", "observed"),
                            _dump(record),
                        )
                    )
                connection.executemany(
                    """INSERT INTO pairs
                       (owner, leftover, sig, stop, keep, ex_stop, ex_keep, ex_last, ex_ts,
                        closes, kills, launches, stop_ok, respawn, days, probation, first_seen,
                        last_seen, last_asked, last_auto_stop, last_keep, suspended_until, source,
                        payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    pair_rows,
                )

                connection.execute("DELETE FROM standalone")
                connection.executemany(
                    "INSERT INTO standalone(key, n, ts, payload) VALUES (?, ?, ?, ?)",
                    [
                        (key, record.get("n", 0), record.get("ts"), _dump(record))
                        for key, record in data["standalone"].items()
                    ],
                )
                connection.execute("DELETE FROM noise")
                connection.executemany(
                    "INSERT INTO noise(key, n) VALUES (?, ?)",
                    list(data["noise"].items()),
                )
                connection.execute("DELETE FROM asked")
                asked = data.get("asked", {})
                if isinstance(asked, dict) and isinstance(asked.get("day"), int):
                    connection.execute(
                        "INSERT INTO asked(day, n) VALUES (?, ?)",
                        (asked["day"], asked.get("n", 0)),
                    )

                connection.execute("DELETE FROM reviews")
                connection.executemany(
                    """INSERT INTO reviews
                       (id, seq, kind, owner, sig, scope, pids, mem, created, expires, shown,
                        state, payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            review["id"],
                            sequence,
                            review.get("kind"),
                            review.get("owner"),
                            review.get("sig"),
                            review.get("scope"),
                            _dump(review.get("pids", [])),
                            review.get("mem"),
                            review.get("created"),
                            review.get("expires"),
                            review.get("shown"),
                            review.get("state", "open"),
                            _dump(review),
                        )
                        for sequence, review in enumerate(data["reviews"])
                        if isinstance(review, dict)
                        and isinstance(review.get("id"), int)
                    ],
                )

                connection.execute("DELETE FROM vetoes")
                connection.executemany(
                    """INSERT INTO vetoes
                       (id, seq, kind, match, value, start, created, expires, reason, source,
                        decision_id, payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            str(veto["id"]),
                            sequence,
                            veto.get("kind", ""),
                            _dump(
                                {"value": veto.get("value"), "start": veto.get("start")}
                            ),
                            str(veto.get("value", "")),
                            veto.get("start"),
                            veto.get("created"),
                            veto.get("expires"),
                            veto.get("reason"),
                            veto.get("source"),
                            veto.get("decision_id"),
                            _dump(veto),
                        )
                        for sequence, veto in enumerate(data["vetoes"])
                        if isinstance(veto, dict) and veto.get("id") is not None
                    ],
                )

                connection.execute("DELETE FROM auto_actions")
                connection.executemany(
                    "INSERT INTO auto_actions(id, seq, ts, scope, payload) VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            str(action["id"]),
                            sequence,
                            action.get("ts"),
                            action.get("scope"),
                            _dump(action),
                        )
                        for sequence, action in enumerate(data["auto_actions"])
                        if isinstance(action, dict) and action.get("id") is not None
                    ],
                )
                connection.execute("DELETE FROM feedback_applied")
                connection.executemany(
                    "INSERT INTO feedback_applied(id, seq) VALUES (?, ?)",
                    [
                        (str(identifier), sequence)
                        for sequence, identifier in enumerate(data["feedback_ids"])
                    ],
                )
                connection.execute("DELETE FROM leftover_expiries")
                connection.executemany(
                    "INSERT INTO leftover_expiries(scope, payload) VALUES (?, ?)",
                    [
                        (scope, _dump(value))
                        for scope, value in data["leftover_expiries"].items()
                    ],
                )
                connection.execute("DELETE FROM frozen")
                connection.executemany(
                    "INSERT INTO frozen(scope, since, listeners, decision_id, source) VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            scope,
                            record.get("since"),
                            _dump(record.get("listeners", [])),
                            record.get("decision_id"),
                            record.get("source", "auto"),
                        )
                        for scope, record in data.get("frozen_scopes", {}).items()
                        if isinstance(scope, str) and isinstance(record, dict)
                    ],
                )
                _prune(connection, now)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        os.chmod(self.path, 0o600)


_COUNTERS = (
    "seen",
    "shared_hits",
    "killed",
    "sigkill_needed",
    "respawned",
    "user_keep",
    "user_kill",
)
