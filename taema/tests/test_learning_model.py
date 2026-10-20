"""Pure learning decisions and fixed-condition monotonicity checks."""

import unittest
from dataclasses import FrozenInstanceError
from itertools import product

from taema.model.learning import DAY, PairEvidence, decide_pair


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

        evidence = PairEvidence.from_record(pair, now)
        self.assertEqual(decide_pair(evidence, now)[0], "ask")
        self.assertEqual(
            decide_pair(
                evidence,
                now,
                authority="aggressive",
                allow_self_authority=True,
            )[0],
            "stop",
        )
        self.assertEqual(
            decide_pair(
                evidence,
                now,
                authority="learned",
                allow_self_authority=True,
            )[0],
            "ask",
        )

    def test_inferred_evidence_meets_the_pair_threshold(self):
        now, pair = self.silent_pair()

        action, confidence, reason = decide_pair(
            PairEvidence.from_record(pair, now), now
        )

        self.assertEqual(action, "stop")
        self.assertEqual(confidence, 1.0)
        self.assertIn("5 kills on 3 days", reason)

    def test_regret_keep_and_suspension_override_learned_stop(self):
        now, pair = self.silent_pair()
        pair["regret_keep"] = 3.0
        pair["suspended_until"] = now + DAY

        action, _confidence, reason = decide_pair(
            PairEvidence.from_record(pair, now), now
        )

        self.assertEqual(action, "ask")
        self.assertIn("suspended after regret", reason)

    def test_explicit_stop_evidence_is_monotone(self):
        now = 100 * DAY
        for inferred_stop, contrary_keep, self_stop, authority, allow_self in product(
            (0.0, 0.5, 1.25),
            (0.0, 0.5, 3.0),
            (0.0, 0.5, 1.5),
            ("learned", "aggressive"),
            (False, True),
        ):
            previous_stop = False
            for weight in (0.0, 1.0, 2.0, 3.0, 5.0, 10.0):
                record = {
                    "ex_stop": weight,
                    "ex_last": "stop",
                    "stop": inferred_stop,
                    "keep": contrary_keep,
                    "self_stop": self_stop,
                }
                action = decide_pair(
                    PairEvidence.from_record(record, now),
                    now,
                    authority=authority,
                    allow_self_authority=allow_self,
                )[0]
                is_stop = action == "stop"
                with self.subTest(
                    inferred_stop=inferred_stop,
                    contrary_keep=contrary_keep,
                    self_stop=self_stop,
                    authority=authority,
                    allow_self=allow_self,
                    weight=weight,
                ):
                    self.assertFalse(previous_stop and not is_stop)
                previous_stop = is_stop

    def test_more_keep_evidence_never_creates_stop_authority(self):
        now, silent = self.silent_pair()
        keep_levels = (0.0, 0.25, 1.0, 3.0, 10.0)
        for (
            answer,
            ex_stop,
            inferred_stop,
            self_stop,
            authority,
            allow_self,
            until,
        ) in product(
            (None, "stop", "keep"),
            (0.0, 3.0),
            (0.0, 1.25, 3.0),
            (0.0, 0.5, 1.5),
            ("learned", "aggressive"),
            (False, True),
            (0.0, now + DAY),
        ):
            for field in ("keep", "regret_keep", "ex_keep"):
                seen_non_stop = False
                for weight in keep_levels:
                    record = dict(
                        silent,
                        ex_last=answer,
                        ex_stop=ex_stop,
                        stop=inferred_stop,
                        self_stop=self_stop,
                        suspended_until=until,
                        keep=0.0,
                        regret_keep=0.0,
                        ex_keep=0.0,
                    )
                    record[field] = weight
                    action = decide_pair(
                        PairEvidence.from_record(record, now),
                        now,
                        authority=authority,
                        allow_self_authority=allow_self,
                    )[0]
                    is_stop = action == "stop"
                    with self.subTest(
                        answer=answer,
                        ex_stop=ex_stop,
                        inferred_stop=inferred_stop,
                        self_stop=self_stop,
                        authority=authority,
                        allow_self=allow_self,
                        until=until,
                        field=field,
                        weight=weight,
                    ):
                        self.assertFalse(seen_non_stop and is_stop)
                    seen_non_stop = seen_non_stop or not is_stop

    def test_decision_input_is_frozen_and_slots_based(self):
        evidence = PairEvidence.from_record({"stop": 1.25}, 100 * DAY)

        with self.assertRaises(FrozenInstanceError):
            evidence.stop = 3.0

        self.assertFalse(hasattr(evidence, "__dict__"))


if __name__ == "__main__":
    unittest.main()
