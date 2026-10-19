import json
import tempfile
import unittest

from taema.knowledge import MAX_OPEN_REVIEWS, Store

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
