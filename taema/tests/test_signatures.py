"""Canonical survivor groups and signature-level learning."""

from itertools import permutations
import os
import tempfile
import unittest
from unittest import mock

from taema.cli.commands import _why_pair_report
from taema.cli.view import render_explanation
from taema.core import signature
from taema.store.knowledge import Store
from tests.test_phase0 import make_cfg


class SurvivorSignatureTests(unittest.TestCase):
    def test_invalid_signature_inputs_are_rejected_and_missing_runtime_is_empty(self):
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}):
            self.assertEqual(signature.runtime_dir_hash(), "")
        self.assertEqual(signature.runtime_dir_hash(123), "")
        with self.assertRaises(ValueError):
            signature.signature("", ["node:build"])
        with self.assertRaises(ValueError):
            signature.signature("editor", [""])
        with self.assertRaises(ValueError):
            signature.signature("editor", [{"key": "node:build", "count": True}])
        with self.assertRaises(ValueError):
            signature.signature("editor", [])

        normalized = signature.signature(
            "editor", ["node:build"], runtime_hash=7, runtime_class=None
        )
        self.assertEqual(
            (normalized["runtime_hash"], normalized["runtime_class"]), ("", "")
        )

    def test_member_count_reader_rejects_malformed_stored_data(self):
        self.assertEqual(signature.member_counts(None), {})
        self.assertEqual(signature.member_counts(["node:build"]), {})
        self.assertEqual(
            signature.member_counts([{"key": "node:build", "count": True}]), {}
        )

    def test_signature_is_stable_across_member_order_and_process_instances(self):
        members = [
            {"key": "node:build", "pid": 40, "start": 100},
            {"key": "node:serve", "pid": 41, "start": 101},
            {"key": "node:build", "pid": 42, "start": 102},
        ]
        expected = signature.signature(
            "editor", members, "runtime-hash", "container", True
        )["id"]
        for offset, order in enumerate(permutations(members)):
            changed_instances = [
                {**member, "pid": 1000 + offset * 10 + index, "start": index + 9000}
                for index, member in enumerate(order)
            ]
            self.assertEqual(
                signature.signature(
                    "editor", changed_instances, "runtime-hash", "container", True
                )["id"],
                expected,
            )

        self.assertNotEqual(
            signature.signature("editor", members, "other-runtime", "container", True)[
                "id"
            ],
            expected,
        )
        self.assertNotEqual(
            signature.signature("editor", members, "runtime-hash", "container", False)[
                "id"
            ],
            expected,
        )

    def test_signature_answer_matches_exact_and_near_groups_without_pair_authority(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            now = [1000.0]
            store = Store(temporary, {}, now=lambda: now[0])
            first = signature.signature(
                "editor",
                ["node:build", "node:serve"],
                "runtime-a",
                "container",
                False,
            )
            for member in first["members"]:
                store.observe_close("editor", member["key"])
            store.observe_signature_close(first)
            self.assertTrue(store.answer_signature("editor", first, "stop"))

            exact = store.signature_decision(first)
            self.assertIsNotNone(exact)
            self.assertEqual(exact[0], "stop")
            self.assertEqual(store.pair_decision("editor", "node:build")[0], "ask")
            self.assertEqual(
                store.data["pairs"][store.pkey("editor", "node:build")]["ex_stop"], 0
            )
            pair_display = next(
                pair
                for pair in store.pairs_summary()
                if pair["owner"] == "editor" and pair["leftover"] == "node:build"
            )
            self.assertEqual(pair_display["inherited"], "stop")
            self.assertEqual(pair_display["action"], "stop")
            self.assertEqual(pair_display["pair_action"], "ask")

            near = signature.signature(
                "editor",
                [
                    {"key": "node:build", "count": 2},
                    {"key": "node:serve", "count": 1},
                ],
                "runtime-b",
                "container",
                True,
            )
            self.assertNotEqual(near["id"], first["id"])
            self.assertEqual(store.signature_decision(near)[0], "stop")

            expanded = signature.signature(
                "editor",
                ["node:build", "node:serve", "node:lint"],
                "runtime-b",
                "container",
                False,
            )
            self.assertIsNone(store.signature_decision(expanded))
            inherited = store.signature_decisions(expanded)
            self.assertEqual(set(inherited), {"node:build", "node:serve"})
            self.assertEqual(inherited["node:build"][0], "stop")
            self.assertEqual(store.pair_decision("editor", "node:lint")[0], "ask")

    def test_signature_outcomes_are_persisted_and_reported_by_why(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(temporary, {}, now=lambda: 2000.0)
            observed = signature.signature(
                "editor", ["node:build"], "runtime-hash", "node", True
            )
            store.observe_close("editor", "node:build")
            store.observe_signature_close(observed)
            store.answer_signature("editor", observed, "keep")
            for counter in ("stop_ok", "respawn", "veto"):
                self.assertTrue(store.signature_outcome(observed["id"], counter))

            info = store.explain("node:build")
            self.assertEqual(
                info["signatures"],
                [
                    {
                        "id": observed["id"],
                        "owner": "editor",
                        "members": [{"key": "node:build", "count": 1}],
                        "answer": "keep",
                        "closes": 1,
                        "stop_ok": 1,
                        "respawn": 1,
                        "probation": 0,
                        "veto": 1,
                    }
                ],
            )
            output = render_explanation(
                "node:build",
                {
                    "learning": info,
                    "current_decision": {},
                    "protected": {},
                    "hold": {},
                    "mode_outcomes": {},
                },
            )
            self.assertIn("closes=1 stop_ok=1 respawn=1 veto=1", output)
            pair_report = _why_pair_report(
                "editor", "node:build", make_cfg(temporary), store
            )
            self.assertIn(
                "closes=1 stop_ok=1 respawn=1 veto=1",
                render_explanation("pair:editor -> node:build", pair_report),
            )


if __name__ == "__main__":
    unittest.main()
