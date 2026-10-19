"""SQLite persistence contract for the existing Store interface."""

import os
from contextlib import closing
from pathlib import Path
import stat
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from taema.store import db as store_db
from taema.store.db import StateDB
from taema.store.knowledge import Store


class StoreDatabaseTests(unittest.TestCase):
    def test_fresh_store_uses_private_versioned_wal_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary, {})
            store.bump("firefox", "seen", 2)
            store.answer("npm", "vite", "stop")
            store.add_veto("app", "firefox")
            store.save()

            self.assertEqual(Path(store.path).name, "state.db")
            self.assertEqual(stat.S_IMODE(os.stat(temporary).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(store.path).st_mode), 0o600)
            with store.db.connection() as writer:
                writer.execute("BEGIN IMMEDIATE")
                for suffix in ("-wal", "-shm"):
                    self.assertEqual(
                        stat.S_IMODE(os.stat(store.path + suffix).st_mode), 0o600
                    )
                writer.rollback()

            database = StateDB(store.path, read_only=True)
            with database.connection() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 3
                )
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode").fetchone()[0], "wal"
                )
                self.assertEqual(
                    connection.execute("PRAGMA synchronous").fetchone()[0], 1
                )
                self.assertEqual(
                    connection.execute("PRAGMA busy_timeout").fetchone()[0], 2000
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
                )
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue(
                    {
                        "meta",
                        "exes",
                        "pairs",
                        "vetoes",
                        "reviews",
                        "apps",
                        "instances",
                        "events",
                    }
                    <= tables
                )

            reopened = Store(temporary, {})
            self.assertEqual(reopened.peek("firefox")["seen"], 2)
            self.assertEqual(reopened.pair_decision("npm", "vite")[0], "stop")
            self.assertEqual(
                reopened.match_veto(members=[{"apps": ["firefox"]}])["value"], "firefox"
            )

    def test_database_upgrades_forward_from_an_older_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.db"
            with closing(sqlite3.connect(path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE exes (
                        key TEXT PRIMARY KEY, counters TEXT NOT NULL,
                        term_exit_ms TEXT NOT NULL, idle_grace_scale REAL NOT NULL,
                        stops INTEGER NOT NULL, last_seen REAL, payload TEXT NOT NULL
                    );
                    CREATE TABLE pairs (
                        owner TEXT NOT NULL, leftover TEXT NOT NULL, payload TEXT NOT NULL,
                        PRIMARY KEY (owner, leftover)
                    );
                    CREATE TABLE standalone (
                        key TEXT PRIMARY KEY, n INTEGER, ts REAL, payload TEXT NOT NULL
                    );
                    CREATE TABLE asked (day INTEGER PRIMARY KEY, n INTEGER NOT NULL);
                    CREATE TABLE noise (key TEXT PRIMARY KEY, n INTEGER NOT NULL);
                    PRAGMA user_version = 1;
                    """
                )

            Store(temporary, {})
            database = StateDB(path, read_only=True)
            with database.connection() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 3
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='instances'"
                    ).fetchone()
                )

    def test_read_only_reader_does_not_block_a_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            writer = Store(temporary, {})
            writer.bump("app", "seen")
            writer.save()
            reader_db = StateDB(writer.path, read_only=True)
            with reader_db.connection() as reader:
                reader.execute("BEGIN")
                self.assertEqual(
                    reader.execute("SELECT count(*) FROM exes").fetchone()[0], 1
                )
                with self.assertRaises(sqlite3.OperationalError):
                    reader.execute("UPDATE exes SET stops = 1")

                writer.bump("app", "seen")
                writer.save()

            self.assertEqual(Store(temporary, {}).peek("app")["seen"], 2)

    def test_concurrent_readers_and_writer_do_not_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            writer = Store(temporary, {})
            writer.save()
            errors = []
            reads = []
            stop = threading.Event()

            def write_passes():
                try:
                    for _ in range(80):
                        writer.bump("app", "seen")
                        writer.save()
                except Exception as error:
                    errors.append(error)
                finally:
                    stop.set()

            def read_passes():
                while not stop.is_set():
                    try:
                        Store(temporary, {}, read_only=True).peek("app")
                        reads.append(True)
                    except Exception as error:
                        errors.append(error)
                        stop.set()

            readers = [threading.Thread(target=read_passes) for _ in range(3)]
            for reader in readers:
                reader.start()
            writer_thread = threading.Thread(target=write_passes)
            writer_thread.start()
            writer_thread.join(timeout=10)
            stop.set()
            for reader in readers:
                reader.join(timeout=10)

            self.assertFalse(writer_thread.is_alive())
            self.assertTrue(all(not reader.is_alive() for reader in readers))
            self.assertEqual(errors, [])
            self.assertGreater(len(reads), 0)
            self.assertEqual(Store(temporary, {}).peek("app")["seen"], 80)

    def test_killed_uncommitted_writes_leave_a_valid_previous_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary, {})
            store.bump("stable", "seen")
            store.save()
            interrupted_write = (
                "import os, signal, sqlite3, sys; "
                "c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); "
                "c.execute(\"UPDATE exes SET payload='{}' WHERE key='stable'\"); "
                "os.kill(os.getpid(), signal.SIGKILL)"
            )

            for _ in range(100):
                result = subprocess.run(
                    [sys.executable, "-c", interrupted_write, store.path],
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, -9, result.stderr.decode())
                self.assertEqual(Store(temporary, {}).peek("stable")["seen"], 1)
                with closing(sqlite3.connect(store.path)) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA integrity_check").fetchone()[0],
                        "ok",
                    )

    def test_fifty_thousand_instances_do_not_load_into_daemon_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary, {})
            with closing(sqlite3.connect(store.path)) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO apps(key, kind) VALUES ('synthetic', 'exe')"
                    )
                    connection.executemany(
                        "INSERT INTO instances(id, app, born) VALUES (?, 'synthetic', ?)",
                        ((str(index), float(index)) for index in range(50_000)),
                    )

            # ru_maxrss can carry the unittest runner's peak across fork+exec.
            # Read live daemon RSS instead of inheriting the test runner's high-water mark.
            probe = (
                "import os, sys, tempfile; "
                "from taema.daemon.service import Daemon; "
                "units = tempfile.TemporaryDirectory(); "
                "cfg = {'mode': 'observe', 'paths': {'state_dir': sys.argv[1], "
                "'units_dir': units.name, 'hooks_dir': units.name, "
                "'socket': os.path.join(units.name, 'taema.sock'), "
                "'socket_fallback': os.path.join(units.name, 'fallback.sock')}, "
                "'timers': {}, 'protected': {}, 'seeds': {}, '_sources': []}; "
                "Daemon(cfg); "
                "print(next(line.split()[1] for line in open('/proc/self/status') "
                "if line.startswith('VmRSS:')))"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            result = subprocess.run(
                [sys.executable, "-c", probe, temporary],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertLessEqual(int(result.stdout.strip()), 30 * 1024)

    def test_database_pruning_applies_caps_and_preserves_protected_apps(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary, {})
            now = 1_000_000_000.0
            db = StateDB(store.path)
            day = store_db.DAY
            old = now - 200 * day
            with db.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    "INSERT INTO apps(key, kind, last_seen) VALUES (?, 'exe', ?)",
                    [
                        ("old", old),
                        ("candidate", now - 2),
                        ("answered", now - 1),
                        ("vetoed", now),
                        ("standalone", now),
                    ],
                )
                connection.execute(
                    "INSERT INTO standalone(key, n, ts, payload) "
                    "VALUES ('standalone', 1, ?, '{}')",
                    (now,),
                )
                connection.executemany(
                    "INSERT INTO instances(id, app, born) VALUES (?, ?, ?)",
                    [
                        ("stale", "old", old),
                        ("i1", "answered", now - 3),
                        ("i2", "vetoed", now - 2),
                        ("i3", "answered", now - 1),
                    ],
                )
                connection.executemany(
                    "INSERT INTO pairs(owner, leftover, ex_keep, last_seen, payload) "
                    "VALUES (?, ?, ?, ?, '{}')",
                    [
                        ("answered", "helper", 3, now),
                        ("p2", "l2", 0, now - 1),
                        ("p3", "l3", 0, now - 2),
                        ("p4", "l4", 0, now - 3),
                    ],
                )
                connection.executemany(
                    "INSERT INTO vetoes(id, seq, kind, match, value, created, "
                    "expires, decision_id, payload) "
                    "VALUES (?, ?, ?, '{}', ?, ?, ?, ?, '{}')",
                    [
                        ("veto-app", 1, "app", "vetoed", now, None, 1),
                        ("veto-expired", 2, "scope", "old", old, now - 1, None),
                    ],
                )
                connection.executemany(
                    "INSERT INTO decisions(id, ts, undo) VALUES (?, ?, ?)",
                    [(1, old, None), (2, old, None), (3, now, None), (4, old, "{}")],
                )
                connection.executemany(
                    "INSERT INTO events(seq, ts, decision_id, event) VALUES (?, ?, ?, 'x')",
                    [(1, old, None), (2, now - 2, 1), (3, now - 1, None)],
                )
                connection.executemany(
                    "INSERT INTO signatures(id, owner, members, last_seen) "
                    "VALUES (?, 'same', '[]', ?)",
                    [("s1", now - 2), ("s2", now - 1), ("s3", now)],
                )
                connection.executemany(
                    "INSERT INTO mem_samples(scope_key, ts) VALUES ('scope', ?)",
                    [(old,), (now,)],
                )
                connection.executemany(
                    "INSERT INTO mem_rollup(app, day) VALUES ('app', ?)",
                    [(int((now - 400 * day) // day),), (int(now // day),)],
                )
                connection.execute(
                    "INSERT INTO reviews(id, seq, state, created, payload) "
                    "VALUES (1, 1, 'expired', ?, ?)",
                    (now, '{"closed": %s}' % (now - 31 * day)),
                )
                with mock.patch.multiple(
                    store_db,
                    MAX_INSTANCES=2,
                    MAX_EVENTS=2,
                    MAX_DECISIONS=2,
                    MAX_APPS=2,
                    MAX_PAIRS=2,
                    MAX_SIGNATURES_PER_OWNER=2,
                ):
                    store_db._prune(connection, now)
                connection.commit()

            with db.connection() as connection:
                self.assertEqual(
                    {row[0] for row in connection.execute("SELECT key FROM apps")},
                    {"answered", "vetoed", "standalone"},
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM instances").fetchone()[0],
                    2,
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM events").fetchone()[0], 2
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM decisions").fetchone()[0],
                    2,
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT 1 FROM decisions WHERE id = 1"
                    ).fetchone()
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT 1 FROM decisions WHERE id = 4"
                    ).fetchone()
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM pairs").fetchone()[0], 2
                )
                self.assertTrue(
                    connection.execute(
                        "SELECT 1 FROM pairs WHERE owner = 'answered' "
                        "AND leftover = 'helper'"
                    ).fetchone()
                )
                self.assertEqual(
                    {row[0] for row in connection.execute("SELECT id FROM signatures")},
                    {"s2", "s3"},
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM mem_samples").fetchone()[
                        0
                    ],
                    1,
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM mem_rollup").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM reviews").fetchone()[0], 0
                )
                self.assertEqual(
                    {row[0] for row in connection.execute("SELECT id FROM vetoes")},
                    {"veto-app"},
                )


if __name__ == "__main__":
    unittest.main()
