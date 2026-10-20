"""Pure learning decisions and fixed-condition monotonicity checks."""

import unittest

from taema.model.learning import DAY, decide_pair


class LearningDecisionTests(unittest.TestCase):
    def silent_pair(self):
        now = 100 * DAY
        return now, {
            "first_seen": now - 8 * DAY,
            "closes": 0,
            "stop": 1.25,
            "keep": 0.0,
            "kills": 5,
            "inferred_kills": 5.0,
            "days": [10, 11, 12],
            "last_keep": 0,
            "suspended_until": 0,
        }

    def test_successful_stops_confidence_does_not_grant_default_authority(self):
        now = 100 * DAY
        pair = {
            "first_seen": now - 10 * DAY,
            "stop_ok": 3,
            "self_stop": 1.5,
            "days": [],
        }

        self.assertEqual(decide_pair(pair, now)[0], "ask")
        self.assertEqual(
            decide_pair(
                pair,
                now,
                authority="aggressive",
                allow_self_authority=True,
            )[0],
            "stop",
        )
        self.assertEqual(
            decide_pair(
                pair,
                now,
                authority="learned",
                allow_self_authority=True,
            )[0],
            "ask",
        )

    def test_inferred_evidence_meets_the_pair_threshold(self):
        now, pair = self.silent_pair()

        action, confidence, reason = decide_pair(pair, now)

        self.assertEqual(action, "stop")
        self.assertEqual(confidence, 1.0)
        self.assertIn("5 kills on 3 days", reason)

    def test_regret_keep_and_suspension_override_learned_stop(self):
        now, pair = self.silent_pair()
        pair["regret_keep"] = 3.0
        pair["suspended_until"] = now + DAY

        action, _confidence, reason = decide_pair(pair, now)

        self.assertEqual(action, "ask")
        self.assertIn("suspended after regret", reason)

    def test_explicit_stop_evidence_is_monotone(self):
        now = 100 * DAY
        for weight in range(3, 12):
            with self.subTest(weight=weight):
                self.assertEqual(
                    decide_pair({"ex_stop": float(weight), "ex_last": "stop"}, now)[0],
                    "stop",
                )

    def test_keep_evidence_never_reauthorizes_a_silent_stop(self):
        now, pair = self.silent_pair()
        previous_stop = True
        for keep in (0.0, 0.1, 0.5, 1.0, 3.0, 10.0):
            pair["keep"] = keep
            action = decide_pair(pair, now)[0]
            is_stop = action == "stop"
            self.assertFalse(is_stop and not previous_stop)
            previous_stop = is_stop


if __name__ == "__main__":
    unittest.main()
