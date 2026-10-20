"""Public CLI views for learned state."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from taema.cli import commands
from taema.core.identity import AppIdentity
from taema.store.knowledge import Store
from tests.test_ipc_v2 import matches

READ_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema/cli/read-v1.json").read_text()
)


class LearnCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name, {})

    def test_pairs_json_uses_the_dashboard_pair_fields_and_exposes_last_answer(self):
        self.store.observe_close("npm", "vite")
        self.store.answer("npm", "vite", "stop")
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "pairs", "--json"]), 0)

        document = json.loads(output.getvalue())
        self.assertTrue(matches(document, READ_SCHEMA, READ_SCHEMA))
        self.assertEqual(document["schema"], "taema.learn.v1")
        self.assertEqual(document["view"], "pairs")
        self.assertEqual(document["count"], 1)
        pair = document["records"][0]
        self.assertEqual((pair["owner"], pair["leftover"]), ("npm", "vite"))
        self.assertEqual(pair["action"], "stop")
        self.assertEqual(pair["decision"], "stop")
        self.assertEqual(pair["confidence"], 1.0)
        self.assertEqual(pair["closes"], 1)
        self.assertEqual(pair["evidence"]["closes"], 1)
        self.assertEqual(pair["last_outcome"]["decision"], "stop")

    def test_pairs_human_output_includes_decision_confidence_and_evidence(self):
        self.store.answer("npm", "vite", "keep")
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "pairs", "--plain"]), 0)

        self.assertIn("owner", output.getvalue())
        self.assertIn("confidence", output.getvalue())
        self.assertIn("npm", output.getvalue())
        self.assertIn("keep", output.getvalue())

    def test_pair_last_outcome_prefers_later_completed_stop_after_pending_expires(self):
        now = [100.0]
        self.store.now = lambda: now[0]
        self.store.answer("browser", "worker", "keep")
        now[0] = 200.0
        self.store.auto_stopped("browser", "worker", stop_id="stop-1")
        now[0] = 220.0
        self.store.expire_auto_stops(now=now[0], respawn_window=10, revive_window=20)
        self.assertNotIn(
            "pending_stop",
            self.store.data["pairs"][self.store.pkey("browser", "worker")],
        )
        self.store.save()

        reopened = Store(self.temporary.name, {}, now=lambda: now[0], read_only=True)
        pair = reopened.pairs_summary()[0]
        self.assertEqual(
            pair["last_outcome"],
            {"decision": "stop", "outcome": "stop_ok", "at": 220.0},
        )

    def test_pair_last_outcome_prefers_later_respawn_after_pending_expires(self):
        now = [100.0]
        self.store.now = lambda: now[0]
        self.store.answer("browser", "worker", "stop")
        now[0] = 200.0
        self.store.auto_stopped("browser", "worker", stop_id="stop-2")
        now[0] = 201.0
        self.store.auto_stop_respawn("browser", "worker")
        now[0] = 220.0
        self.store.expire_auto_stops(now=now[0], respawn_window=10, revive_window=20)
        self.store.save()

        reopened = Store(self.temporary.name, {}, now=lambda: now[0], read_only=True)
        pair = reopened.pairs_summary()[0]
        self.assertEqual(
            pair["last_outcome"],
            {"decision": "keep", "outcome": "respawn", "at": 201.0},
        )

    def test_signature_last_outcome_tracks_auto_stop_results_after_answers(self):
        now = [100.0]
        self.store.now = lambda: now[0]
        signatures = (
            {
                "id": "signature-stop-ok",
                "owner": "browser",
                "members": [{"key": "worker", "count": 1}],
                "runtime_class": "node",
                "runtime_hash": "runtime-hash",
                "tty": False,
            },
            {
                "id": "signature-respawn",
                "owner": "browser",
                "members": [{"key": "worker", "count": 2}],
                "runtime_class": "node",
                "runtime_hash": "runtime-hash",
                "tty": False,
            },
        )
        for signature in signatures:
            self.store.db.record_signature(signature, now=now[0], close=True)
            self.store.db.answer_signature(signature["id"], "stop", 3.0, now=101.0)
        now[0] = 200.0
        self.store.signature_outcome("signature-stop-ok", "stop_ok")
        now[0] = 201.0
        self.store.signature_outcome("signature-respawn", "respawn")

        reopened = Store(self.temporary.name, {}, now=lambda: now[0], read_only=True)
        summaries = {
            item["id"]: item["last_outcome"] for item in reopened.signatures_summary()
        }
        self.assertEqual(
            summaries["signature-stop-ok"],
            {"decision": "stop", "outcome": "stop_ok", "at": 200.0},
        )
        self.assertEqual(
            summaries["signature-respawn"],
            {"decision": "keep", "outcome": "respawn", "at": 201.0},
        )

    def test_apps_json_lists_identity_and_learning_evidence(self):
        now = self.store.now()
        identity = AppIdentity(
            "exe:browser:8:71", "Browser", "exe", "/usr/bin/browser", 8, 71
        )
        self.store.record_identity(identity, {"pid": 42, "start": 100, "born": now})
        self.store.bump(identity.key, "user_keep", 3)
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "apps", "--json"]), 0)

        document = json.loads(output.getvalue())
        self.assertTrue(matches(document, READ_SCHEMA, READ_SCHEMA))
        self.assertEqual(document["view"], "apps")
        app = document["records"][0]
        self.assertEqual(app["key"], identity.key)
        self.assertEqual(app["display"], "Browser")
        self.assertEqual(app["decision"], "share")
        self.assertEqual(app["confidence"], 1.0)
        self.assertEqual(app["evidence"]["user_keep"], 3)
        self.assertIsNone(app["last_outcome"])

    def test_apps_human_output_includes_evidence_and_last_outcome_columns(self):
        self.store.bump("browser", "user_keep", 3)
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "apps", "--plain"]), 0)

        rendered = output.getvalue()
        self.assertIn("decision", rendered)
        self.assertIn("confidence", rendered)
        self.assertIn("evidence", rendered)
        self.assertIn("last outcome", rendered)
        self.assertIn("user_keep=3", rendered)

    def test_show_human_lists_app_pair_and_signature_evidence(self):
        now = self.store.now()
        identity = AppIdentity("browser", "Browser", "app", "/usr/bin/browser")
        self.store.record_identity(identity, {"pid": 42, "start": 100, "born": now})
        self.store.bump("browser", "user_keep", 3)
        self.store.answer("browser", "worker", "stop")
        signature = {
            "id": "signature-browser-worker",
            "owner": "browser",
            "members": [{"key": "worker", "count": 1}],
            "runtime_class": "node",
            "runtime_hash": "runtime-hash",
            "tty": False,
        }
        self.store.db.record_signature(signature, now=now, close=True)
        self.store.db.answer_signature(signature["id"], "stop", 3.0, now=now)
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "show", "--plain"]), 0)

        rendered = output.getvalue()
        self.assertIn("app", rendered)
        self.assertIn("Browser", rendered)
        self.assertIn("browser", rendered)
        self.assertIn("worker", rendered)
        self.assertIn("signature-browser-worker", rendered)
        self.assertIn("user_keep=3.0", rendered)
        self.assertIn("browser -> worker  stop  1.00", rendered)
        self.assertIn("stop=3.0", rendered)
        self.assertIn("signature-browser-worker  browser  stop  1.00", rendered)
        self.assertIn("closes=1", rendered)
        self.assertIn("decision", rendered)
        self.assertIn("confidence", rendered)
        self.assertIn("evidence", rendered)
        self.assertIn("last outcome", rendered)
        self.assertIn("answered", rendered)

        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output := io.StringIO()),
        ):
            self.assertEqual(commands.main(["learn", "show", "--json"]), 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["view"], "show")
        self.assertTrue(matches(document, READ_SCHEMA, READ_SCHEMA))
        self.assertEqual(document["counts"]["apps"], 2)
        self.assertEqual(document["counts"]["pairs"], 1)
        self.assertEqual(document["counts"]["signatures"], 1)
        self.assertEqual(document["apps"][0]["decision"], "share")
        self.assertEqual(document["pairs"][0]["last_outcome"]["outcome"], "answered")
        self.assertEqual(document["signatures"][0]["evidence"]["closes"], 1)

    def test_signatures_json_matches_why_signature_evidence(self):
        signature = {
            "id": "signature-browser-vite",
            "owner": "browser",
            "members": [{"key": "vite", "count": 1}],
            "runtime_class": "node",
            "runtime_hash": "runtime-hash",
            "tty": False,
        }
        self.store.db.record_signature(signature, now=self.store.now(), close=True)
        self.store.db.answer_signature(
            signature["id"], "stop", 3.0, now=self.store.now()
        )
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "signatures", "--json"]), 0)

        document = json.loads(output.getvalue())
        self.assertTrue(matches(document, READ_SCHEMA, READ_SCHEMA))
        self.assertEqual(document["view"], "signatures")
        record = document["records"][0]
        self.assertEqual(record["id"], signature["id"])
        self.assertEqual(record["owner"], "browser")
        self.assertEqual(record["answer"], "stop")
        self.assertEqual(record["decision"], "stop")
        self.assertEqual(record["confidence"], 1.0)
        self.assertEqual(record["evidence"]["closes"], 1)
        self.assertEqual(record["last_outcome"]["decision"], "stop")

        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output := io.StringIO()),
        ):
            self.assertEqual(commands.main(["learn", "signatures", "--plain"]), 0)
        self.assertIn(signature["id"], output.getvalue())
        self.assertIn("last outcome", output.getvalue())

    def test_show_legacy_lists_invalid_pairs_and_their_reconfirmation_reviews(self):
        self.store.data["pairs"][self.store.pkey("MainThread", "sh")] = {
            "source": "legacy-invalid",
            "closes": 2,
        }
        self.store.data["reviews"] = [
            {
                "id": 7,
                "kind": "legacy-invalid",
                "owner": "MainThread",
                "survivors": ["sh"],
                "answer": "stop",
                "reason": "legacy owner identity needs confirmation",
                "created": self.store.now(),
                "expires": self.store.now() + 3600,
                "state": "open",
            }
        ]
        self.store.save()
        summary = self.store.legacy_invalid_summary()
        self.assertEqual(summary["records"][0]["source"], "legacy-invalid")
        self.assertEqual(summary["records"][0]["legacy_answer"], "stop")
        self.assertEqual(summary["reviews"][0]["id"], 7)
        output = io.StringIO()
        with (
            mock.patch.object(
                self.store,
                "legacy_invalid_summary",
                wraps=self.store.legacy_invalid_summary,
            ) as legacy_summary,
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["learn", "show", "--legacy", "--json"]), 0)
        legacy_summary.assert_called_once_with(limit=1000)

        document = json.loads(output.getvalue())
        self.assertTrue(matches(document, READ_SCHEMA, READ_SCHEMA))
        self.assertEqual(document["view"], "show")
        self.assertTrue(document["legacy"])
        self.assertEqual(document["records"][0]["source"], "legacy-invalid")
        self.assertEqual(document["records"][0]["legacy_answer"], "stop")
        self.assertEqual(document["reviews"][0]["id"], 7)
        self.assertEqual(document["reviews"][0]["answer"], "stop")

        with (
            mock.patch.object(commands, "_load", return_value=({}, self.store, [])),
            redirect_stdout(output := io.StringIO()),
        ):
            self.assertEqual(commands.main(["learn", "show", "--legacy", "--plain"]), 0)
        self.assertIn("legacy-invalid pairs", output.getvalue())
        self.assertIn("review #7", output.getvalue())

    def test_forget_all_queues_full_learning_reset_and_preserves_vetoes(self):
        self.store.bump("browser", "seen", 4)
        self.store.mark_standalone("browser")
        self.store.note_noise("browser")
        self.store.observe_close("browser", "worker")
        self.store.answer("browser", "worker", "stop")
        self.store.data["reviews"] = [
            {
                "id": 1,
                "kind": "legacy-invalid",
                "owner": "browser",
                "survivors": ["worker"],
                "answer": "stop",
                "created": self.store.now(),
                "expires": self.store.now() + 3600,
                "state": "open",
            },
            {
                "id": 2,
                "kind": "legacy-invalid",
                "owner": "browser",
                "survivors": ["worker"],
                "answer": "keep",
                "created": self.store.now(),
                "expires": self.store.now() + 3600,
                "state": "closed",
            },
        ]
        signature = {
            "id": "signature-browser-worker",
            "owner": "browser",
            "members": [{"key": "worker", "count": 1}],
            "runtime_class": "",
            "runtime_hash": "",
            "tty": False,
        }
        self.store.db.record_signature(signature, now=self.store.now(), close=True)
        self.store.db.answer_signature(
            signature["id"], "stop", 3.0, now=self.store.now()
        )
        ordinary_signature = {
            **signature,
            "id": "signature-browser-ordinary",
            "members": [{"key": "browser", "count": 1}],
        }
        self.store.db.record_signature(
            ordinary_signature, now=self.store.now(), close=True
        )
        self.store.db.answer_signature(
            ordinary_signature["id"], "keep", 3.0, now=self.store.now()
        )
        self.store.add_veto("app", "browser", identifier="app-veto")
        self.store.add_veto("signature", signature["id"], identifier="signature-veto")
        self.store.save()

        readonly = Store(self.temporary.name, {}, read_only=True)
        output = io.StringIO()
        with (
            mock.patch.object(commands, "_load", return_value=({}, readonly, [])),
            mock.patch.object(commands, "ask", return_value=None),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.main(["forget", "--all", "browser"]), 0)

        with open(readonly.feedback_path, encoding="utf-8") as feedback_file:
            message = json.loads(feedback_file.readline())
        self.assertEqual(message["op"], "forget")
        self.assertEqual(message["key"], "browser")
        self.assertIs(message["all"], True)
        self.assertTrue(self.store.apply_feedback_command(message)["ok"])
        self.store.save()

        reopened = Store(self.temporary.name, {}, read_only=True)
        self.assertNotIn("browser", reopened.data["exes"])
        self.assertNotIn("browser", reopened.data["standalone"])
        self.assertNotIn("browser", reopened.data["noise"])
        self.assertFalse(
            any(key.startswith("browser\0") for key in reopened.data["pairs"])
        )
        self.assertEqual([review["id"] for review in reopened.data["reviews"]], [2])
        veto_ids = {veto["id"] for veto in reopened.data["vetoes"]}
        self.assertEqual(veto_ids, {"app-veto", "signature-veto"})
        retained = reopened.db.signature(signature["id"])
        self.assertIsNotNone(retained)
        self.assertEqual((retained["ex_stop"], retained["closes"]), (0, 0))
        self.assertIsNone(retained["last_outcome"])
        self.assertIsNone(retained["last_outcome_at"])
        self.assertEqual(
            reopened.match_veto(signature=signature["id"])["id"], "signature-veto"
        )
        self.assertIsNone(reopened.db.signature(ordinary_signature["id"]))


if __name__ == "__main__":
    unittest.main()
