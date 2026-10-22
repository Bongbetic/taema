"""Decision identity, correlation, retention, and audit-log contracts."""

import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from taema.governor import engine
from taema.store import knowledge


class DecisionTraceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = knowledge.Store(
            self.temporary.name, now=lambda: 1000.0, mode="adopt"
        )

    def test_decisions_and_related_events_persist_with_correlation(self):
        with self.store.decision_context(
            "containment",
            scope="leftover/job-1",
            owner="npm",
            authority="mode",
            why="contain closed-job survivor",
        ) as decision:
            self.store.log(event="containment", pids=[123])

        self.store.save()
        rows = self.store.db.decisions(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            (
                rows[0]["id"],
                rows[0]["kind"],
                rows[0]["scope"],
                rows[0]["owner"],
                rows[0]["authority"],
                rows[0]["mode"],
                rows[0]["why"],
                rows[0]["corr"],
            ),
            (
                decision["id"],
                "containment",
                "leftover/job-1",
                "npm",
                "mode",
                "adopt",
                "contain closed-job survivor",
                decision["corr"],
            ),
        )
        with self.store.db.connection() as connection:
            events = connection.execute(
                "SELECT seq, decision_id, data FROM events "
                "WHERE decision_id = ? ORDER BY seq",
                (decision["id"],),
            ).fetchall()
        self.assertEqual(
            [row["seq"] for row in events], sorted(row["seq"] for row in events)
        )
        self.assertEqual(len(events), 1)
        for row in events:
            data = json.loads(row["data"])
            self.assertEqual(row["decision_id"], decision["id"])
            self.assertEqual(data["corr"], decision["corr"])
            self.assertEqual(data["mode"], "adopt")
            self.assertIn("why", data)

        records = [
            json.loads(line)
            for line in Path(self.store.log_path)
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual([record["event"] for record in records], ["containment"])
        self.assertTrue(
            all(
                {"ts", "event", "mode", "decision_id", "corr", "why"} <= record.keys()
                for record in records
            )
        )
        self.assertEqual(self.store.latest_decision()["id"], decision["id"])

    def test_sequences_survive_pruning_and_restart(self):
        first = self.store.record_decision("answer", authority="user", why="keep")
        self.store.log(event="answer", decision_id=first["id"], corr=first["corr"])
        self.store.save()
        with self.store.db.connection() as connection:
            connection.execute("DELETE FROM events")
            connection.execute("DELETE FROM decisions")
            connection.commit()

        reopened = knowledge.Store(self.temporary.name, now=lambda: 1001.0)
        second = reopened.record_decision("answer", authority="user", why="stop")
        reopened.log(event="answer", decision_id=second["id"], corr=second["corr"])
        reopened.save()
        self.assertGreater(second["id"], first["id"])
        with reopened.db.connection() as connection:
            seq = connection.execute("SELECT seq FROM events").fetchone()[0]
        self.assertGreater(seq, 1)

    def test_undo_target_is_resolved_from_the_decision_record(self):
        action = self.store.record_auto_action(
            "leftover/vite", "pair stop", [("npm", "vite")], ["vite"]
        )
        self.store.save()

        reader = knowledge.Store(
            self.temporary.name, now=lambda: 1001.0, read_only=True
        )
        latest = reader.auto_action()
        self.assertEqual(latest["decision_id"], action["decision_id"])
        self.assertEqual(latest["id"], action["id"])

        reopened = knowledge.Store(self.temporary.name, now=lambda: 1002.0)
        result = reopened.undo_auto_action(
            str(action["decision_id"]), feedback_id="undo-through-decision"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["action"]["decision_id"], action["decision_id"])
        reopened.save()
        self.assertEqual(reopened.latest_decision()["kind"], "undo")
        self.assertEqual(reopened.decision(action["decision_id"])["kind"], "auto_stop")

    def test_explicit_learning_answer_is_a_user_decision(self):
        self.assertTrue(self.store.apply_op("keep", "vim"))
        self.store.save()
        decision = self.store.latest_decision()
        self.assertEqual(decision["kind"], "answer")
        self.assertEqual(decision["authority"], "user")
        self.assertEqual(decision["mode"], "adopt")

    def test_inflight_stop_decision_is_updated_with_undo_target(self):
        with self.store.decision_context(
            "stop", scope="leftover/vite", authority="mode", why="pair learned"
        ) as decision:
            action = self.store.record_auto_action(
                "leftover/vite",
                "pair learned",
                [("npm", "vite")],
                ["vite"],
                decision=decision,
            )

        self.store.save()
        stored = self.store.decision(action["decision_id"])
        self.assertEqual(stored["kind"], "stop")
        self.assertTrue(stored["undoable"])
        self.assertEqual(stored["undo"]["action_id"], action["id"])
        with self.store.db.connection() as connection:
            event = connection.execute(
                "SELECT decision_id, data FROM events WHERE event = 'auto_stop'"
            ).fetchone()
        self.assertEqual(event["decision_id"], decision["id"])
        self.assertEqual(json.loads(event["data"])["corr"], decision["corr"])

    def test_legacy_automatic_stop_gets_a_decision_record(self):
        self.store.data["auto_actions"] = [
            {
                "id": "old-action",
                "scope": "leftover/vite",
                "why": "legacy action",
                "pairs": [["npm", "vite"]],
                "apps": ["vite"],
                "ts": 900.0,
            }
        ]

        action = self.store.auto_action()
        self.store.save()

        decision = self.store.decision(action["decision_id"])
        self.assertEqual(decision["kind"], "auto_stop")
        self.assertEqual(decision["mode"], "unknown")
        self.assertTrue(decision["undoable"])
        self.assertEqual(decision["undo"]["action_id"], "old-action")

    def test_missing_and_capacity_blocked_undo_are_decisions(self):
        self.assertIsNone(self.store.undo_auto_action())
        self.assertEqual(self.store.latest_decision()["kind"], "refusal")
        self.store.save()

        action = self.store.record_auto_action(
            "leftover/vite", "pair learned", apps=["vite"]
        )
        with mock.patch.object(knowledge, "MAX_VETOES", 0):
            self.assertIsNone(self.store.undo_auto_action(str(action["decision_id"])))

        self.store.save()
        refusal = self.store.latest_decision()
        self.assertEqual(refusal["kind"], "refusal")
        with self.store.db.connection() as connection:
            event = connection.execute(
                "SELECT decision_id FROM events WHERE event = 'undo_refused' "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(event["decision_id"], refusal["id"])

    def test_oversized_jsonl_entry_is_truncated_to_a_valid_core_record(self):
        self.store.log(event="large", detail="x" * knowledge.MAX_LOG_LINE)

        record = json.loads(
            Path(self.store.log_path).read_text(encoding="utf-8").splitlines()[0]
        )
        self.assertTrue(record["truncated"])
        self.assertLessEqual(
            Path(self.store.log_path).stat().st_size, knowledge.MAX_LOG_LINE
        )
        self.assertTrue(
            {"ts", "event", "mode", "decision_id", "corr", "why"} <= record.keys()
        )

    def test_latest_decision_includes_an_uncommitted_record(self):
        pending = self.store.record_decision("refusal", why="not yet saved")
        self.assertEqual(self.store.latest_decision()["id"], pending["id"])

    def test_adopt_move_and_stop_refusal_are_traced(self):
        cfg = {"mode": "adopt"}
        with (
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
            mock.patch.object(engine, "_inside_user", return_value=True),
            mock.patch.object(engine.cgroup, "mkleaf", return_value="/fake/app"),
            mock.patch.object(engine.cgroup, "base", return_value="/fake"),
            mock.patch.object(engine.cgroup, "move"),
            mock.patch.object(engine.inspect, "starttime", return_value=456),
            mock.patch.object(engine.policy, "app_key", return_value="test-app"),
        ):
            engine.run_ops(
                cfg,
                self.store,
                [{"op": "move", "scope": "app-test", "pids": [123]}],
                True,
            )
        self.store.save()
        decision = self.store.latest_decision()
        self.assertEqual(decision["kind"], "adopt_move")
        self.assertTrue(decision["undoable"])
        self.assertEqual(
            decision["undo"],
            {
                "operation": "adopt_standalone",
                "scope": "app-test",
                "members": [{"pid": 123, "start": 456, "key": "test-app"}],
            },
        )

        with mock.patch.object(
            engine, "self_guard", side_effect=engine.Refused("protected scope")
        ):
            with self.assertRaises(engine.Refused):
                engine.stop("/fake/scope", cfg, self.store)
        self.store.save()
        latest = self.store.latest_decision()
        self.assertEqual(latest["kind"], "stop")
        with self.store.db.connection() as connection:
            correlated = connection.execute(
                "SELECT count(*) FROM events WHERE decision_id = ? AND event = 'refusal'",
                (latest["id"],),
            ).fetchone()[0]
        self.assertEqual(correlated, 1)

    def test_audit_rotation_keeps_three_private_files_with_required_fields(self):
        with mock.patch.object(knowledge, "LOG_MAX", 500):
            for index in range(10):
                self.store.log(event="sample", why="x" * 180, index=index)

        log_files = [
            Path(self.store.log_path),
            Path(self.store.log_path + ".1"),
            Path(self.store.log_path + ".2"),
        ]
        self.assertTrue(all(path.exists() for path in log_files))
        self.assertFalse(Path(self.store.log_path + ".3").exists())
        for path in log_files:
            self.assertLessEqual(path.stat().st_size, 500)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for line in path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                self.assertTrue(
                    {"ts", "event", "mode", "decision_id", "corr", "why"}
                    <= record.keys()
                )


if __name__ == "__main__":
    unittest.main()
