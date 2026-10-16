import tempfile
import unittest

from taema.knowledge import Store

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
        self.assertAlmostEqual(s2.rec("tool")["shared_hits"], 10 * 0.9 ** 2, places=3)

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

    def test_skip_sigterm_when_it_never_works(self):
        r = self.s.rec("stubborn")
        r["killed"], r["sigkill_needed"] = 10, 9
        self.assertEqual(self.s.graceful_timeout("stubborn", 10), (0.0, False))

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


if __name__ == "__main__":
    unittest.main()
