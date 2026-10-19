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
SCHEMA_VERSION = 3
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
    """Read the latest rotated and active audit lines; malformed lines are skipped."""
    lines = deque(maxlen=LEGACY_EVENT_LIMIT)
    for name in ("decisions.log.1", "decisions.log"):
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


def _prune(connection, now):
    """Apply documented storage bounds without evicting active vetoes or answers."""
    connection.execute(
        "DELETE FROM instances WHERE coalesce(exited, born) < ?",
        (now - INSTANCE_RETENTION,),
    )
    _trim_oldest(
        connection, "instances", "id", MAX_INSTANCES, "coalesce(exited, born, 0), id"
    )

    connection.execute("DELETE FROM events WHERE ts < ?", (now - EVENT_RETENTION,))
    _trim_oldest(connection, "events", "seq", MAX_EVENTS, "coalesce(ts, 0), seq")

    connection.execute(
        "DELETE FROM vetoes WHERE expires IS NOT NULL AND expires <= ?", (now,)
    )
    decision_refs = (
        "id NOT IN (SELECT decision_id FROM vetoes WHERE decision_id IS NOT NULL) "
        "AND id NOT IN (SELECT decision_id FROM events WHERE decision_id IS NOT NULL) "
        "AND undo IS NULL"
    )
    connection.execute(
        "DELETE FROM decisions WHERE ts < ? AND %s" % decision_refs,
        (now - DECISION_RETENTION,),
    )
    _trim_oldest(
        connection,
        "decisions",
        "id",
        MAX_DECISIONS,
        "coalesce(ts, 0), id",
        decision_refs,
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

    connection.execute("CREATE TEMP TABLE _taema_app_evictions (key TEXT PRIMARY KEY)")
    connection.execute(
        "INSERT INTO _taema_app_evictions(key) "
        "SELECT key FROM apps AS candidate "
        "WHERE NOT EXISTS (SELECT 1 FROM pairs WHERE owner = candidate.key "
        "AND (ex_stop > 0 OR ex_keep > 0)) "
        "AND NOT EXISTS (SELECT 1 FROM standalone WHERE key = candidate.key) "
        "AND NOT EXISTS (SELECT 1 FROM pairs WHERE source = 'legacy-invalid' "
        "AND (owner = candidate.key OR leftover = candidate.key)) "
        "AND NOT EXISTS (SELECT 1 FROM vetoes WHERE kind = 'app' "
        "AND value = candidate.key AND (expires IS NULL OR expires > ?)) "
        "ORDER BY coalesce(last_seen, 0), key "
        "LIMIT max(0, (SELECT count(*) FROM apps) - ?)",
        (now, MAX_APPS),
    )
    connection.execute(
        "DELETE FROM instances WHERE app IN (SELECT key FROM _taema_app_evictions)"
    )
    connection.execute(
        "DELETE FROM apps WHERE key IN (SELECT key FROM _taema_app_evictions)"
    )
    connection.execute("DROP TABLE _taema_app_evictions")
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

    def _migrate(self, connection):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                "state database schema %d is newer than supported schema %d"
                % (version, SCHEMA_VERSION)
            )
        while version < SCHEMA_VERSION:
            next_version = version + 1
            script = (
                "BEGIN IMMEDIATE;\n"
                + _MIGRATIONS[next_version]
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
        return data

    def save_state(self, data, now=None):
        if self.read_only:
            return
        now = time.time() if now is None else now
        self._secure_dir()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for key in ("version", "created", "last_decay", "closes", "review_seq"):
                    connection.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                        (key, _dump(data[key])),
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
