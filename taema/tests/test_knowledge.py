import json
import os
import tempfile
import unittest
from unittest import mock

from taema.core import signature as survivor_signature
from taema.store import knowledge
from taema.store.knowledge import MAX_OPEN_REVIEWS, Store

DAY = 86400.0


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.clock = Clock()
        self.seeds = {"share": ["adb"], "kill": ["qemu"]}
        self.s = Store(self.d, self.seeds, self.clock)

    def test_seed_share_and_seed_kill(self):
        self.assertEqual(self.s.default_action("adb")[0], "share")
        self.assertEqual(self.s.default_action("qemu")[0], "kill")
        self.assertEqual(self.s.default_action("unknown")[0], "kill")

    def test_shared_hits_flip_to_share(self):
        for _ in range(3):
            self.s.bump("tool", "shared_hits")
        self.assertEqual(self.s.default_action("tool")[0], "share")

    def test_respawn_counts_half(self):
        self.s.bump("tool", "respawned", 4)  # 2.0 <= 2: still kill
        self.assertEqual(self.s.default_action("tool")[0], "kill")
        self.s.bump("tool", "respawned", 1)  # 2.5 > 2
        self.assertEqual(self.s.default_action("tool")[0], "share")

    def test_user_kill_overturns_seed(self):
        self.s.bump("adb", "user_kill", 2)
        self.assertEqual(self.s.default_action("adb")[0], "kill")

    def test_decay_after_two_weeks(self):
        self.s.bump("tool", "shared_hits", 10)
        self.s.save()
        self.clock.t += 14 * DAY
        s2 = Store(self.d, self.seeds, self.clock)
        self.assertAlmostEqual(s2.rec("tool")["shared_hits"], 10 * 0.9**2, places=3)

    def test_forget_resets(self):
        self.s.bump("tool", "shared_hits", 5)
        self.assertTrue(self.s.forget("tool"))
        self.assertEqual(self.s.default_action("tool")[0], "kill")
        self.assertFalse(self.s.forget("tool"))

    def test_graceful_timeout_p95(self):
        for ms in (1000, 1200, 1100, 4000):
            self.s.add_term_ms("slow", ms)
        t, graceful = self.s.graceful_timeout("slow", 10)
        self.assertTrue(graceful)
        self.assertAlmostEqual(t, 6.0, places=1)  # 4000 ms * 1.5

    def test_graceful_default_with_few_samples(self):
        self.assertEqual(self.s.graceful_timeout("new", 10), (10.0, True))

    def test_sigterm_never_skipped_when_it_never_works(self):
        r = self.s.rec("stubborn")
        r["killed"], r["sigkill_needed"] = 10, 9
        self.assertEqual(self.s.graceful_timeout("stubborn", 10), (2.0, True))

    def test_idle_grace_doubles_after_respawn_and_shrinks_when_clean(self):
        self.assertEqual(self.s.idle_grace("x", 600), 600)
        self.s.gc_outcome("x", respawned=True)
        self.assertEqual(self.s.idle_grace("x", 600), 1200)
        self.s.gc_outcome("x", respawned=False)
        self.assertAlmostEqual(self.s.idle_grace("x", 600), 1080)

    def test_idle_grace_bounds(self):
        for _ in range(10):
            self.s.gc_outcome("x", respawned=True)
        self.assertEqual(self.s.idle_grace("x", 600), 7200)
        for _ in range(60):
            self.s.gc_outcome("y", respawned=False)
        self.assertEqual(self.s.idle_grace("y", 600), 120)

    def test_log_is_json_lines(self):
        self.s.log(event="t", a=1)
        with open(self.s.log_path) as f:
            self.assertIn('"event": "t"', f.read())

    def test_review_queue_cap_resolves_oldest_to_keep(self):
        for i in range(MAX_OPEN_REVIEWS + 1):
            self.s.add_review(
                "owner%d" % i,
                [{"key": "helper", "pid": 1000 + i}],
                "leftover/owner-%d" % i,
            )
        self.assertEqual(self.s.review_count, MAX_OPEN_REVIEWS)
        old = next(r for r in self.s.data["reviews"] if r["id"] == 1)
        self.assertEqual(old["state"], "expired")
        self.assertEqual(self.s.pair_decision("owner0", "helper")[0], "keep")
        self.s.save()
        reloaded = Store(self.d, self.seeds, self.clock)
        self.assertEqual(reloaded.review_count, MAX_OPEN_REVIEWS)
        self.assertEqual(reloaded.data["review_seq"], MAX_OPEN_REVIEWS + 1)

    def make_review(self):
        signature = survivor_signature.signature(
            "owner", ["helper"], "runtime", "node", False
        )
        self.s.observe_close("owner", "helper")
        self.s.observe_signature_close(signature)
        review = self.s.add_review(
            "owner",
            [{"key": "helper", "pid": 42, "start": 100}],
            "leftover/owner-42",
            signature=self.s.db.signature(signature["id"]),
            memory=2 * 1024 * 1024,
            provenance="last seen under editor",
        )
        return signature, review

    def test_review_details_include_signature_memory_provenance_and_age(self):
        _signature, review = self.make_review()
        self.clock.t += 180

        (detail,) = self.s.review_details([review])

        self.assertEqual(detail["owner"], "owner")
        self.assertEqual(detail["survivors"], ["helper"])
        self.assertEqual(detail["closes"], 1)
        self.assertEqual(detail["mem"], 2 * 1024 * 1024)
        self.assertEqual(detail["age"], 180)
        self.assertEqual(detail["signature"]["id"], review["sig"])
        self.assertEqual(detail["provenance"], "last seen under editor")

    def test_mark_review_shown_counts_only_when_presented_and_limits_signature(self):
        signature, review = self.make_review()
        self.assertEqual(self.s.data["asked"]["n"], 0)

        self.assertTrue(self.s.mark_review_shown(review["id"]))
        self.assertTrue(self.s.mark_review_shown(review["id"]))
        self.assertEqual(self.s.data["asked"]["n"], 1)
        self.assertFalse(
            self.s.can_ask(("owner", "another-helper"), signature=signature)
        )

        self.s.save()
        reopened = Store(self.d, self.seeds, self.clock)
        self.assertFalse(
            reopened.can_ask(("owner", "another-helper"), signature=signature)
        )

    def test_review_provenance_fallbacks_and_candidate_showing_rules(self):
        _signature, review = self.make_review()
        review.pop("provenance")
        with mock.patch.object(
            self.s,
            "latest_app_instance",
            return_value={"scope": "", "parent_app": "editor"},
        ):
            self.assertEqual(self.s.review_details([review])[0]["provenance"], "editor")
        with (
            mock.patch.object(self.s, "latest_app_instance", return_value=None),
            mock.patch.object(
                self.s,
                "provenance_chain",
                return_value={"chain_text": "editor ← owner"},
            ),
        ):
            self.assertEqual(
                self.s.review_details([review])[0]["provenance"],
                "editor ← owner",
            )
        with (
            mock.patch.object(self.s, "latest_app_instance", return_value=None),
            mock.patch.object(self.s, "provenance_chain", return_value=None),
        ):
            self.assertEqual(
                self.s.review_details([review])[0]["provenance"], "owner identity"
            )

        self.assertFalse(self.s.mark_review_shown(999))
        self.assertFalse(self.s.mark_review_shown(review["id"], owner="editor"))
        self.s.data["asked"] = {"day": int(self.clock.t // DAY), "n": 3}
        self.assertFalse(self.s.mark_review_shown(review["id"]))
        self.s.data["asked"] = {"day": 0, "n": 0}

        ambiguous = self.s.add_provenance_review(
            [{"key": "worker", "pid": 44, "start": 102}],
            "leftover/provenance-44-102",
            candidates=[{"key": "owner"}, {"key": "editor"}],
        )
        self.assertFalse(self.s.mark_review_shown(ambiguous["id"]))
        self.assertFalse(self.s.mark_review_shown(ambiguous["id"], owner="unlisted"))
        single = self.s.add_provenance_review(
            [{"key": "worker-2", "pid": 45, "start": 103}],
            "leftover/provenance-45-103",
            candidates=[{"key": "editor"}],
        )
        self.assertTrue(self.s.mark_review_shown(single["id"]))

    def test_review_answer_applies_to_signature_and_pairs_once(self):
        signature, review = self.make_review()
        start_events = self.s._event_seq

        result = self.s.answer_review(review["id"], "stop")

        self.assertEqual(result["choice"], "stop")
        self.assertEqual(self.s.data["reviews"][0]["state"], "answered")
        self.assertEqual(self.s.pair_decision("owner", "helper")[0], "stop")
        self.assertEqual(self.s.signature_decision(signature)[0], "stop")
        self.assertGreater(self.s._event_seq, start_events)
        self.assertIsNone(self.s.answer_review(review["id"], "keep"))

    def test_never_review_adds_veto_and_standalone_review_keeps_members(self):
        signature, review = self.make_review()
        before_decisions = self.s._decision_seq
        self.assertIsNotNone(self.s.answer_review(review["id"], "never"))
        self.assertEqual(self.s._decision_seq, before_decisions + 1)
        veto = self.s.match_veto(members=[{"apps": ["helper"]}])
        self.assertEqual(veto["kind"], "app")
        self.assertEqual(self.s.pair_decision("owner", "helper")[0], "keep")
        self.assertEqual(self.s.db.signature(signature["id"])["veto"], 1)

        provenance = self.s.add_provenance_review(
            [{"key": "worker", "pid": 43, "start": 101}],
            "leftover/provenance-43-101",
            candidates=[{"key": "owner", "kind": "ancestor"}],
            reason="last seen under owner",
        )
        self.assertEqual(provenance["members"][0]["start"], 101)
        answered = self.s.answer_review(provenance["id"], "standalone", owner="owner")
        self.assertEqual(answered["members"][0]["pid"], 43)
        self.assertEqual(self.s.data["reviews"][-1]["owner"], "owner")
        self.assertTrue(self.s.standalone("worker"))
        self.assertEqual(self.s.pair_decision("owner", "worker")[0], "standalone")
        self.assertEqual(
            self.s.data["pairs"][self.s.pkey("owner", "worker")]["ex_keep"], 3.0
        )

    def test_answer_review_and_shared_answer_reject_invalid_targets(self):
        self.assertIsNone(self.s.answer_review(True, "stop"))
        self.assertIsNone(self.s.answer_review(999, "stop"))
        scope = self.s.add_scope_review("shared/worker", "idle shared scope")
        self.assertIsNone(self.s.answer_review(scope["id"], "stop"))
        ambiguous = self.s.add_provenance_review(
            [{"key": "worker", "pid": 46, "start": 104}],
            "leftover/provenance-46-104",
            candidates=[{"key": "owner"}, {"key": "editor"}],
        )
        self.assertIsNone(self.s.answer_review(ambiguous["id"], "stop"))
        self.assertIsNone(
            self.s.answer_review(ambiguous["id"], "stop", owner="unlisted")
        )

        self.assertFalse(self.s.apply_answer("", ["helper"], "stop"))
        self.assertFalse(self.s.apply_answer("owner", "helper", "stop"))
        self.assertFalse(self.s.apply_answer("owner", [], "stop"))
        self.assertFalse(self.s.apply_answer("owner", ["helper"], "later"))
        self.assertFalse(self.s.apply_answer("MainThread", ["helper"], "stop"))
        self.s.data["pairs"][self.s.pkey("owner", "helper")] = {
            "source": "legacy-invalid"
        }
        self.assertFalse(self.s.apply_answer("owner", ["helper"], "stop"))

    def test_answer_refuses_wrong_signature_owner_and_full_veto_store(self):
        foreign_signature = survivor_signature.signature(
            "other", ["helper"], "runtime", "node", False
        )
        self.s.ensure_signature("other", foreign_signature)
        self.assertFalse(
            self.s.apply_answer(
                "owner",
                ["helper"],
                "stop",
                signature_id=foreign_signature["id"],
            )
        )

        self.s.data["vetoes"] = [
            {
                "id": "v-%d" % index,
                "kind": "app",
                "value": "existing-%d" % index,
                "created": self.clock.t,
            }
            for index in range(knowledge.db.MAX_VETOES)
        ]
        self.assertFalse(self.s.apply_answer("owner", ["helper"], "never"))

    def test_corrupt_signature_cooldown_does_not_break_pair_checks(self):
        self.s.data["signature_asked"] = {"signature-id": "bad timestamp"}
        self.assertTrue(self.s.can_ask(("owner", "helper"), signature="signature-id"))
        self.s.data["signature_asked"] = "bad map"
        self.s.mark_asked([("owner", "helper")], signature="signature-id")
        self.assertEqual(self.s.data["signature_asked"]["signature-id"], self.clock.t)

    def test_veto_matches_scope_app_and_pid_instance(self):
        self.s.add_veto("scope", "leftover/firefox")
        self.s.add_veto("app", "node:vite.js")
        self.s.add_veto("pid", "42", start=1234)

        self.assertEqual(self.s.match_veto(scope="leftover/firefox")["kind"], "scope")
        self.assertEqual(
            self.s.match_veto(
                members=[{"pid": 7, "start": 8, "apps": ["node:vite.js"]}]
            )["kind"],
            "app",
        )
        self.assertEqual(
            self.s.match_veto(members=[{"pid": 42, "start": 1234}])["kind"], "pid"
        )
        self.assertIsNone(self.s.match_veto(members=[{"pid": 42, "start": 1235}]))

    def test_offline_veto_feedback_is_versioned_and_idempotent(self):
        op = {
            "v": 1,
            "id": "op-1",
            "op": "veto",
            "target": {"kind": "app", "value": "firefox"},
        }
        with open(self.s.feedback_path, "w") as f:
            f.write(json.dumps(op) + "\n")
            f.write(json.dumps(op) + "\n")

        self.assertEqual(self.s.apply_feedback(), 1)
        self.assertEqual(self.s.apply_feedback(), 0)
        self.assertEqual(
            self.s.match_veto(members=[{"pid": 1, "start": 2, "apps": ["firefox"]}])[
                "value"
            ],
            "firefox",
        )
        self.assertEqual(self.s.data["feedback_ids"], ["op-1"])

    def test_v2_feedback_replay_is_idempotent_and_counts_invalid_lines(self):
        op = {"v": 2, "id": "keep-1", "op": "keep", "key": "adb"}
        with open(self.s.feedback_path, "w") as queue:
            queue.write(json.dumps(op) + "\n")
            queue.write(json.dumps(op) + "\n")
            queue.write('{"v":2,"id":"partial","op":"keep"')

        self.assertEqual(self.s.pending_feedback_invalid(), 1)
        self.assertEqual(self.s.apply_feedback(), 1)
        self.assertEqual(self.s.peek("adb")["user_keep"], 3.0)
        self.assertEqual(self.s.data["feedback_invalid"], 1)
        self.assertFalse(os.path.exists(self.s.feedback_path + ".replay"))
        self.assertFalse(os.path.exists(self.s.feedback_path))

        reopened = Store(self.d, self.seeds, self.clock)
        with open(reopened.feedback_path, "w") as queue:
            queue.write(json.dumps(op) + "\n")
        self.assertEqual(reopened.apply_feedback(), 0)
        self.assertEqual(reopened.peek("adb")["user_keep"], 3.0)

    def test_feedback_replay_survives_commit_before_queue_removal(self):
        op = {"v": 2, "id": "kill-1", "op": "kill", "key": "vite"}
        with open(self.s.feedback_path, "w") as queue:
            queue.write(json.dumps(op) + "\n")
        replay = self.s.feedback_path + ".replay"
        unlink = knowledge.os.unlink

        def fail_replay_removal(path):
            if path == replay:
                raise OSError("simulated crash window")
            return unlink(path)

        with mock.patch.object(knowledge.os, "unlink", side_effect=fail_replay_removal):
            self.assertEqual(self.s.apply_feedback(), 1)
        self.assertTrue(os.path.exists(replay))
        self.assertEqual(self.s.peek("vite")["user_kill"], 1.0)

        recovered = Store(self.d, self.seeds, self.clock)
        self.assertEqual(recovered.apply_feedback(), 0)
        self.assertEqual(recovered.peek("vite")["user_kill"], 1.0)
        self.assertFalse(os.path.exists(replay))

    def test_v2_feedback_dispatches_pair_and_control_operations(self):
        operations = [
            {
                "v": 2,
                "id": "answer-1",
                "op": "answer",
                "owner": "npm",
                "leftovers": ["vite"],
                "choice": "keep",
            },
            {
                "v": 2,
                "id": "teach-1",
                "op": "teach",
                "owner": "npm",
                "leftovers": ["webpack"],
                "choice": "stop",
            },
            {"v": 2, "id": "mute-1", "op": "mute", "app": "firefox", "muted": True},
            {"v": 2, "id": "hold-1", "op": "hold", "scope": "scope-x", "held": True},
            {"v": 2, "id": "hold-2", "op": "hold", "held": True},
            {"v": 2, "id": "hold-3", "op": "hold", "held": False},
            {
                "v": 2,
                "id": "snooze-1",
                "op": "snooze",
                "until": self.clock.t + 60,
            },
        ]
        for operation in operations:
            self.assertTrue(self.s.apply_feedback_command(operation)["ok"])

        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "keep")
        self.assertEqual(self.s.pair_decision("npm", "webpack")[0], "stop")
        self.assertEqual(self.s.data["muted_apps"], ["firefox"])
        self.assertEqual(self.s.hold_reason("scope-x"), "snoozed")
        self.assertTrue(self.s.review_holds_scope("scope-x"))
        self.assertTrue(self.s.data["held_scopes"] == ["scope-x"])

    def test_undo_vetoes_the_stopped_app_and_keeps_its_pair(self):
        action = self.s.record_auto_action(
            "leftover/vite", "pair stop", [("npm", "vite")], ["vite"]
        )
        undone = self.s.undo_auto_action(action["id"], feedback_id="undo-1")

        self.assertEqual(undone["vetoes"][0]["value"], "vite")
        self.assertEqual(
            self.s.match_veto(members=[{"pid": 7, "start": 8, "apps": ["vite"]}])[
                "kind"
            ],
            "app",
        )
        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "keep")

    def test_offline_unveto_replay_removes_only_the_named_veto(self):
        veto = self.s.add_veto("app", "firefox")
        op = {
            "v": 1,
            "id": "remove-1",
            "op": "unveto",
            "target": {"kind": "app", "value": "firefox", "start": None},
        }
        with open(self.s.feedback_path, "w") as f:
            f.write(json.dumps(op) + "\n")

        self.assertEqual(self.s.apply_feedback(), 1)
        self.assertIsNone(
            self.s.match_veto(members=[{"pid": 7, "start": 8, "apps": ["firefox"]}])
        )
        self.assertEqual(veto["value"], "firefox")

    def test_veto_cap_refuses_new_protection_without_evicting_active_vetoes(self):
        with mock.patch.object(knowledge, "MAX_VETOES", 2):
            self.s.add_veto("app", "one")
            self.s.add_veto("app", "two")
            self.assertIsNone(self.s.add_veto("app", "three"))
        self.assertEqual({v["value"] for v in self.s.data["vetoes"]}, {"one", "two"})

    def test_zero_weight_pairs_remain_for_thirty_days(self):
        self.s._pair("owner", "leftover")
        self.s.enforce_caps()
        key = self.s.pkey("owner", "leftover")
        self.assertIn(key, self.s.data["pairs"])
        self.clock.t += knowledge.PAIR_RETENTION + 1
        self.s.enforce_caps()
        self.assertNotIn(key, self.s.data["pairs"])

    def test_pair_cap_does_not_evict_an_active_keep_answer(self):
        with mock.patch.object(knowledge, "MAX_PAIRS", 1):
            self.assertTrue(self.s.answer("owner-one", "helper", "keep"))
            self.assertTrue(self.s.answer("owner-two", "helper", "keep"))
        self.assertEqual(self.s.pair_decision("owner-one", "helper")[0], "keep")
        self.assertEqual(self.s.pair_decision("owner-two", "helper")[0], "keep")

    def test_closed_leftover_reviews_expire_after_thirty_days(self):
        self.s.data["reviews"] = [
            {
                "id": 1,
                "kind": "scope",
                "scope": "leftover/old",
                "state": "expired",
                "created": self.clock.t - knowledge.REVIEW_RETENTION - 1,
                "closed": self.clock.t - knowledge.REVIEW_RETENTION - 1,
            }
        ]
        self.s.expire_reviews()
        self.assertEqual(self.s.data["reviews"], [])

    def test_pending_offline_undo_vetoes_before_replay_and_keeps_after_replay(self):
        action = self.s.record_auto_action(
            "leftover/vite", "pair stop", [("npm", "vite")], ["vite"]
        )
        op = {"v": 1, "id": "undo-pending", "op": "undo", "action_id": action["id"]}
        with open(self.s.feedback_path, "w") as f:
            f.write(json.dumps(op) + "\n")

        self.assertEqual(
            self.s.match_veto(members=[{"pid": 7, "apps": ["vite"]}])["value"], "vite"
        )
        self.assertEqual(self.s.apply_feedback(), 1)
        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "keep")
        self.assertEqual(
            self.s.match_veto(members=[{"pid": 7, "apps": ["vite"]}])["value"], "vite"
        )


if __name__ == "__main__":
    unittest.main()
