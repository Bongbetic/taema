"""SQLite connection, schema migration, and persistence for :mod:`store.knowledge`."""

from contextlib import contextmanager
import json
import os
import sqlite3
import time
from urllib.parse import quote

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
        "NOT (ex_last = 'keep' AND ex_keep > stop)",
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

    def __init__(self, path, read_only=False):
        self.path = os.path.abspath(path)
        self.read_only = read_only
        self.available = os.path.isfile(self.path)
        if read_only:
            return
        self._secure_dir()
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            self._migrate(connection)
        os.chmod(self.path, 0o600)
        self.available = True

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

    def load_state(self, data):
        if not self.available:
            return data
        with self.connection() as connection:
            connection.execute("BEGIN")
            for row in connection.execute("SELECT key, value FROM meta"):
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
