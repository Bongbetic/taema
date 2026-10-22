"""Coverage policy regressions for existing and newly added modules."""

import unittest

from tools.check_coverage import coverage_violations


def module(percent):
    return {"summary": {"percent_covered": percent}}


class CoverageGateTest(unittest.TestCase):
    def test_existing_module_may_remain_at_its_recorded_report_baseline(self):
        self.assertEqual(
            coverage_violations(
                {"files": {"src/taema/legacy.py": module(71.6)}},
                {"src/taema/legacy.py": 72},
                85.0,
            ),
            [],
        )

    def test_existing_module_may_not_fall_below_baseline(self):
        violations = coverage_violations(
            {"files": {"src/taema/legacy.py": module(71.49)}},
            {"src/taema/legacy.py": 72},
            85.0,
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("below recorded 72% baseline", violations[0])

    def test_new_module_must_reach_85_percent(self):
        violations = coverage_violations(
            {"files": {"src/taema/new.py": module(84.99)}}, {}, 85.0
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("new module", violations[0])

    def test_recorded_baseline_module_must_appear_in_report(self):
        violations = coverage_violations({"files": {}}, {"src/taema/old.py": 80}, 85)
        self.assertEqual(len(violations), 1)
        self.assertIn("missing from coverage report", violations[0])


if __name__ == "__main__":
    unittest.main()
