"""Compatibility tests for the one-time 0.2 JSON to SQLite migration."""

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from taema.cli import commands
from taema.config import policy
from taema.governor import engine
from taema.store import db as store_db
from taema.store import knowledge
from taema.store.db import StateDB
from taema.store.knowledge import Store

DAY = 86400


def legacy_document(now):
    return {
        "version": 2,
        "created": now - 20 * DAY,
        "last_decay": now - DAY,
        "closes": 24,
        "review_seq": 1,
        "exes": {
            "npm": {"seen": 12.0, "user_keep": 3.0, "term_exit_ms": [100]},
            "vite": {"seen": 3.0},
        },
        "pairs": {
            "npm\0vite": {
                "first_seen": now - 10 * DAY,
                "last_seen": now - DAY,
                "stop": 0.25,
                "keep": 0.0,
                "ex_stop": 3.0,
                "ex_keep": 0.0,
                "ex_last": "stop",
                "ex_ts": now - DAY,
                "closes": 5,
                "kills": 1,
                "days": [1],
            },
            "npm\0worker": {
                "first_seen": now - 10 * DAY,
                "last_seen": now - DAY,
                "stop": 5.0,
                "keep": 0.0,
                "ex_stop": 0.0,
                "ex_keep": 0.0,
                "kills": 5,
                "closes": 5,
                "days": [1, 2, 3],
                "last_keep": 0,
            },
            "MainThread\0sh": {
                "first_seen": now - 10 * DAY,
                "ex_stop": 3.0,
                "ex_keep": 0.0,
                "ex_last": "stop",
                "ex_ts": now - DAY,
                "closes": 3,
            },
        },
        "standalone": {"browser-helper": {"n": 1, "ts": now - DAY}},
        "noise": {"sh": 4},
        "asked": {"day": int(now // DAY), "n": 2},
        "reviews": [
            {
                "id": 1,
                "kind": "close",
                "owner": "npm",
                "survivors": ["vite"],
                "pids": [123],
                "scope": "scope-npm",
                "created": now - 50,
                "expires": now + DAY,
                "state": "open",
            }
        ],
        "vetoes": [
            {
                "id": "veto-one",
                "kind": "app",
                "value": "browser-helper",
                "start": None,
                "created": now - 100,
                "expires": None,
                "reason": "user request",
            }
        ],
        "auto_actions": [
            {
                "id": "action-one",
                "ts": now - 80,
                "scope": "leftover/browser-helper",
                "why": "fixture action",
                "pairs": [["npm", "worker"]],
                "apps": ["browser-helper"],
            }
        ],
        "feedback_ids": ["feedback-one"],
        "leftover_expiries": {"leftover/browser-helper": now - 60},
    }


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.now = 1_800_000_000.0
        self.state_dir = Path(self.temporary.name)
        self.legacy_path = self.state_dir / "knowledge.json"
        self.document = legacy_document(self.now)
        self.legacy_bytes = json.dumps(self.document, sort_keys=True).encode()
        self.legacy_path.write_bytes(self.legacy_bytes)
        self.log_path = self.state_dir / "decisions.log"
        self.log_path.write_text(
            json.dumps({"ts": self.now - 2, "event": "auto_stop", "scope": "scope-x"})
            + "\n"
            + "not-json\n"
            + json.dumps({"ts": self.now - 1, "event": "undo", "scope": "scope-x"})
            + "\n",
            encoding="utf-8",
        )
        self.db_path = self.state_dir / "state.db"

    def store(self):
        return Store(str(self.state_dir), {}, now=lambda: self.now)

    def test_import_preserves_state_decisions_reviews_vetoes_and_audit(self):
        before = {
            key: knowledge.decide(
                record,
                self.now,
            )[0]
            for key, record in self.document["pairs"].items()
            if not key.startswith("MainThread\0")
        }

        store = self.store()

        for pair_key, expected in before.items():
            owner, leftover = pair_key.split("\0")
            self.assertEqual(store.pair_decision(owner, leftover)[0], expected)
        self.assertEqual(store.peek("npm")["seen"], 12.0)
        self.assertEqual(store.data["asked"], self.document["asked"])
        self.assertEqual(store.data["noise"], self.document["noise"])
        self.assertEqual(store.data["standalone"], self.document["standalone"])
        self.assertEqual(store.data["version"], self.document["version"])
        self.assertEqual(store.data["created"], self.document["created"])
        self.assertEqual(store.data["last_decay"], self.document["last_decay"])
        self.assertEqual(store.data["closes"], self.document["closes"])
        self.assertEqual(
            next(r for r in store.data["reviews"] if r.get("kind") == "close")["id"],
            1,
        )
        self.assertEqual(store.data["vetoes"][0]["id"], "veto-one")
        self.assertEqual(store.data["auto_actions"][0]["id"], "action-one")
        self.assertEqual(store.data["feedback_ids"], ["feedback-one"])
        self.assertEqual(self.legacy_path.read_bytes(), self.legacy_bytes)

        with StateDB(str(self.db_path), read_only=True).connection() as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM events").fetchone()[0], 2
            )
            confidence = {
                row[0]: row[1]
                for row in connection.execute("SELECT key, confidence FROM apps")
            }
            self.assertEqual(confidence["npm"], "low")
            self.assertEqual(confidence["vite"], "low")
            self.assertEqual(confidence["worker"], "low")

    def test_invalid_owner_answer_is_quarantined_as_an_open_review(self):
        store = self.store()
        pair = store.data["pairs"][store.pkey("MainThread", "sh")]

        self.assertEqual(pair["source"], "legacy-invalid")
        self.assertEqual((pair.get("ex_stop", 0), pair.get("ex_keep", 0)), (0, 0))
        self.assertEqual(store.pair_decision("MainThread", "sh")[0], "invalid")
        review = next(
            r for r in store.open_reviews() if r.get("kind") == "legacy-invalid"
        )
        self.assertEqual(review["owner"], "MainThread")
        self.assertEqual(review["survivors"], ["sh"])
        self.assertEqual(review["answer"], "stop")

    def test_backup_is_private_and_json_is_never_written_after_import(self):
        store = self.store()
        backups = list(self.state_dir.glob("knowledge.json.backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.legacy_bytes)
        self.assertEqual(os.stat(backups[0]).st_mode & 0o777, 0o600)

        store.bump("npm", "seen")
        store.save()
        self.assertEqual(self.legacy_path.read_bytes(), self.legacy_bytes)

    def test_backup_expires_after_thirty_days(self):
        self.store()
        backup = next(self.state_dir.glob("knowledge.json.backup-*"))
        self.now += 30 * DAY + 1

        self.store()

        self.assertFalse(backup.exists())

    def test_bad_json_is_backed_up_and_not_retried_over_sqlite_state(self):
        self.legacy_path.write_text("{broken", encoding="utf-8")
        invalid = self.legacy_path.read_bytes()
        store = self.store()
        self.assertEqual(store.data["exes"], {})
        self.assertEqual(
            next(self.state_dir.glob("knowledge.json.backup-*")).read_bytes(), invalid
        )

        self.legacy_path.write_text(
            json.dumps({"exes": {"later": {"seen": 99}}}), encoding="utf-8"
        )
        reopened = self.store()
        self.assertNotIn("later", reopened.data["exes"])

    def test_import_is_idempotent_and_does_not_replace_new_sqlite_state(self):
        store = self.store()
        store.bump("new-app", "seen", 9)
        store.save()
        self.store()

        reopened = self.store()
        self.assertEqual(reopened.peek("new-app")["seen"], 9)
        self.assertEqual(
            len(
                [
                    r
                    for r in reopened.data["reviews"]
                    if r.get("kind") == "legacy-invalid"
                ]
            ),
            1,
        )

    def test_failed_import_rolls_back_and_retries_on_next_start(self):
        write_state = store_db._write_legacy_state

        def fail_after_writing(connection, state, now, deny):
            write_state(connection, state, now, deny)
            raise RuntimeError("simulated interrupted import")

        with mock.patch.object(
            store_db, "_write_legacy_state", side_effect=fail_after_writing
        ):
            with self.assertRaisesRegex(RuntimeError, "interrupted import"):
                self.store()

        with closing(sqlite3.connect(self.db_path)) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM exes").fetchone()[0], 0
            )
            marker = connection.execute(
                "SELECT value FROM meta WHERE key = 'migration.legacy_import'"
            ).fetchone()
            self.assertIsNone(marker)

        retried = self.store()
        self.assertEqual(retried.peek("npm")["seen"], 12.0)
        self.assertEqual(len(list(self.state_dir.glob("knowledge.json.backup-*"))), 1)

    def test_process_crash_during_import_rolls_back_and_retries(self):
        source_root = Path(__file__).resolve().parents[1] / "src"
        program = """
import os
import sys
sys.path.insert(0, sys.argv[2])
from taema.store import db
write_state = db._write_legacy_state
def crash(connection, state, now, deny):
    write_state(connection, state, now, deny)
    os._exit(23)
db._write_legacy_state = crash
from taema.store.knowledge import Store
Store(sys.argv[1], {})
"""
        result = subprocess.run(
            [sys.executable, "-c", program, str(self.state_dir), str(source_root)],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 23, result.stderr.decode())

        with closing(sqlite3.connect(self.db_path)) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM exes").fetchone()[0], 0
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM meta WHERE key = 'migration.legacy_import'"
                ).fetchone()
            )

        self.assertEqual(self.store().peek("npm")["seen"], 12.0)

    def test_merge_keeps_sqlite_records_authoritative(self):
        database = StateDB(str(self.db_path))
        current = {
            "version": 2,
            "created": self.now,
            "last_decay": self.now,
            "closes": 0,
            "review_seq": 0,
            "exes": {"npm": {"seen": 77.0}},
            "pairs": {
                "npm\0vite": {
                    "ex_keep": 3.0,
                    "ex_stop": 0.0,
                    "ex_last": "keep",
                }
            },
            "standalone": {},
            "noise": {},
            "asked": {"day": 0, "n": 0},
            "reviews": [],
            "vetoes": [],
            "auto_actions": [],
            "feedback_ids": [],
            "leftover_expiries": {},
        }
        database.save_state(current, now=self.now)

        merged = self.store()

        self.assertEqual(merged.peek("npm")["seen"], 77.0)
        self.assertEqual(merged.data["exes"]["vite"]["seen"], 3.0)
        self.assertEqual(merged.pair_decision("npm", "vite")[0], "keep")

    def test_only_last_ten_thousand_valid_audit_lines_are_imported(self):
        with self.log_path.open("w", encoding="utf-8") as log:
            for index in range(10_002):
                log.write(
                    json.dumps({"ts": self.now + index, "event": "e%d" % index}) + "\n"
                )

        self.store()

        with StateDB(str(self.db_path), read_only=True).connection() as connection:
            rows = connection.execute(
                "SELECT event FROM events ORDER BY seq"
            ).fetchall()
        self.assertEqual(len(rows), 10_000)
        self.assertEqual(rows[0][0], "e2")
        self.assertEqual(rows[-1][0], "e10001")

    def test_read_only_database_reader_never_imports_or_writes_legacy_file(self):
        original = self.legacy_path.read_bytes()
        Store(str(self.state_dir), {}, now=lambda: self.now, read_only=True)
        self.assertFalse(self.db_path.exists())
        self.assertEqual(self.legacy_path.read_bytes(), original)

    def test_store_export_is_compatible_with_the_legacy_schema(self):
        store = self.store()
        exported = store.export_legacy()
        self.assertEqual(exported["version"], 2)
        self.assertEqual(exported["pairs"]["npm\0vite"]["ex_last"], "stop")
        self.assertNotIn("legacy_import", exported)

    def test_export_cli_writes_private_file(self):
        store = self.store()
        destination = self.state_dir / "downgrade.json"
        with mock.patch.object(commands, "_load", return_value=({}, store, [])):
            self.assertEqual(
                commands.main(
                    ["learn", "export", "--format", "v2", "--output", str(destination)]
                ),
                0,
            )
        document = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 2)
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)

    def test_export_cli_stdout_is_only_legacy_json(self):
        store = self.store()
        with tempfile.TemporaryFile(mode="w+") as output:
            with mock.patch.object(commands, "_load", return_value=({}, store, [])):
                with mock.patch("sys.stdout", output):
                    self.assertEqual(
                        commands.main(["learn", "export", "--format", "v2"]), 0
                    )
            output.seek(0)
            document = json.load(output)
            self.assertEqual(document["version"], 2)

    def test_anonymizer_reads_only_and_removes_user_identifiers(self):
        source = self.state_dir / "source"
        output = self.state_dir / "fixture"
        source.mkdir()
        secret = "AliceProject"
        legacy = {
            "version": 2,
            "created": self.now,
            "last_decay": self.now,
            "exes": {
                "/home/alice/AliceProject/run": {
                    "seen": 3,
                    "argv": ["/home/alice/AliceProject/run", "secret-arg"],
                    "cwd": "/home/alice/AliceProject",
                    "project_name": secret,
                }
            },
            "pairs": {
                "/home/alice/AliceProject/run\0/home/alice/.cache/worker": {
                    "ex_stop": 3,
                    "ex_keep": 0,
                    "ex_last": "stop",
                    "argv": ["secret-arg"],
                },
                "MainThread\0sh": {"ex_stop": 3, "ex_last": "stop"},
            },
            "standalone": {},
            "reviews": [],
            "vetoes": [],
            "auto_actions": [],
            "asked": {"day": 1, "n": 1},
            "noise": {},
        }
        legacy_path = source / "knowledge.json"
        legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
        log_path = source / "decisions.log"
        log_path.write_text(
            json.dumps(
                {
                    "event": "auto_stop",
                    "ts": self.now,
                    "argv": ["secret-arg"],
                    "cwd": "/home/alice/AliceProject",
                    "project": secret,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        before = legacy_path.read_bytes(), log_path.read_bytes()
        script = Path(__file__).resolve().parents[1] / "tools/anonymize_state.py"

        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--state-dir",
                str(source),
                "--output-dir",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("2 pairs", result.stdout)
        self.assertEqual((legacy_path.read_bytes(), log_path.read_bytes()), before)
        fixture_text = (output / "knowledge.json").read_text(encoding="utf-8")
        fixture_text += (output / "decisions.log").read_text(encoding="utf-8")
        for private_value in ("alice", "AliceProject", "secret-arg", "/home"):
            self.assertNotIn(private_value, fixture_text)
        fixture = json.loads((output / "knowledge.json").read_text(encoding="utf-8"))
        self.assertEqual(len(fixture["pairs"]), 2)
        self.assertIn(
            "legacy-invalid",
            {pair["source"] for pair in fixture["pairs"].values()},
        )

    def test_reference_fixture_preserves_every_valid_pair_decision(self):
        fixture_dir = Path(__file__).resolve().parent / "fixtures/legacy-v2"
        fixture_text = (fixture_dir / "knowledge.json").read_text(encoding="utf-8")
        fixture_text += (fixture_dir / "decisions.log").read_text(encoding="utf-8")
        self.assertFalse(
            any(path in fixture_text for path in ("/home/", "/media/", "/tmp/"))
        )
        self.assertFalse(
            any(
                field in fixture_text
                for field in ('"argv"', '"cwd"', '"path"', '"project_name"')
            )
        )
        source = json.loads(
            (fixture_dir / "knowledge.json").read_text(encoding="utf-8")
        )
        now = source.get("last_decay", self.now)
        expected = {}
        for pair_key, pair in source.get("pairs", {}).items():
            owner, leftover = pair_key.split("\0", 1)
            if pair.get("source") == "legacy-invalid":
                continue
            action = (
                "standalone"
                if leftover in source.get("standalone", {})
                else knowledge.decide(pair, now)[0]
            )
            expected[(owner, leftover)] = action
        state_dir = Path(self.temporary.name) / "fixture-import"
        state_dir.mkdir()
        (state_dir / "knowledge.json").write_text(json.dumps(source), encoding="utf-8")
        (state_dir / "decisions.log").write_text(
            (fixture_dir / "decisions.log").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        migrated = Store(str(state_dir), {}, now=lambda: now)
        for (owner, leftover), action in expected.items():
            self.assertEqual(migrated.pair_decision(owner, leftover)[0], action)
        active_owners = [
            owner
            for pair_key, pair in migrated.data["pairs"].items()
            if pair.get("source") != "legacy-invalid"
            for owner, _separator, _leftover in (pair_key.partition("\0"),)
        ]
        self.assertFalse(any(policy.bad_owner(owner) for owner in active_owners))
        self.assertTrue(
            all(
                row["why"]
                for row in migrated.pairs_summary()
                if row["action"] == "stop"
            )
        )
        with StateDB(migrated.path, read_only=True).connection() as connection:
            event_count = connection.execute("SELECT count(*) FROM events").fetchone()[
                0
            ]
        self.assertEqual(
            event_count,
            sum(
                bool(line.strip())
                for line in (fixture_dir / "decisions.log")
                .read_text(encoding="utf-8")
                .splitlines()
            ),
        )
        for pair_key, pair in source.get("pairs", {}).items():
            if pair.get("source") == "legacy-invalid":
                owner, leftover = pair_key.split("\0", 1)
                self.assertEqual(migrated.pair_decision(owner, leftover)[0], "invalid")
                self.assertFalse(migrated.can_ask((owner, leftover)))
                self.assertFalse(migrated.answer(owner, leftover, "keep"))

    def test_migration_does_not_call_a_process_stop(self):
        with mock.patch.object(engine, "stop") as stop:
            self.store()
        stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
