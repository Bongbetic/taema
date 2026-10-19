"""Authorization ladder tests (issue #5).

A table pins the 0.2.1 behaviour of every lifecycle trigger in every mode -- exactly the behaviour
issue #1 describes for today (would-actions in observe/adopt, auto-only containment, enforce stops,
per-pair auto authority, the manual stop acting everywhere). Further tests pin the slot order of
spec #1 Implementation Decisions 2 and prove that every daemon/CLI decision point asks the ladder
instead of checking the mode itself.
"""
import argparse
import io
import os
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema import authorization, cgroup, cli, engine, inspect, knowledge
from tests.test_phase0 import make_cfg, tmp
from tests.test_phase4 import AutoCase

MODES = ("observe", "adopt", "enforce", "auto")

# (trigger, facts, expected) with expected = {mode: (verdict, authority)}.
TRUTH = [
    (authorization.OWNER_EXIT, authorization.Facts(), {
        "observe": ("would", ""), "adopt": ("would", ""),
        "enforce": ("act", "unit"), "auto": ("act", "unit")}),
    (authorization.UNIT_ADOPT, authorization.Facts(), {
        "observe": ("would", ""), "adopt": ("act", "mode"),
        "enforce": ("act", "mode"), "auto": ("act", "mode")}),
    (authorization.AUTO_ADOPT, authorization.Facts(), {
        "observe": ("keep", ""), "adopt": ("keep", ""),
        "enforce": ("keep", ""), "auto": ("act", "mode")}),
    (authorization.GUI_CLOSE, authorization.Facts(), {
        "observe": ("keep", ""), "adopt": ("keep", ""),
        "enforce": ("keep", ""), "auto": ("act", "mode")}),
    (authorization.JOB_SURVIVORS, authorization.Facts(), {
        "observe": ("keep", ""), "adopt": ("keep", ""),
        "enforce": ("keep", ""), "auto": ("act", "mode")}),
    (authorization.LEFTOVER_LEAVES, authorization.Facts(), {
        "observe": ("keep", ""), "adopt": ("keep", ""),
        "enforce": ("keep", ""), "auto": ("act", "mode")}),
    (authorization.GC_STOP, authorization.Facts(), {
        "observe": ("would", ""), "adopt": ("would", ""),
        "enforce": ("act", "unit"), "auto": ("would", "")}),
    (authorization.GC_STOP, authorization.Facts(leftover=True), {
        "observe": ("would", ""), "adopt": ("would", ""),
        "enforce": ("act", "unit"), "auto": ("act", "pair")}),
    (authorization.GC_REMOVE_EMPTY, authorization.Facts(), {
        "observe": ("would", ""), "adopt": ("act", "mode"),
        "enforce": ("act", "mode"), "auto": ("act", "mode")}),
    (authorization.SESSION_END, authorization.Facts(), {
        "observe": ("would", ""), "adopt": ("would", ""),
        "enforce": ("act", "unit"), "auto": ("act", "pair")}),
    (authorization.SESSION_END, authorization.Facts(shared=True), {
        "observe": ("would", ""), "adopt": ("would", ""),
        "enforce": ("act", "unit"), "auto": ("keep", "")}),
    (authorization.SESSION_END, authorization.Facts(unit_survive_logout=True), {
        "observe": ("keep", ""), "adopt": ("keep", ""),
        "enforce": ("keep", ""), "auto": ("keep", "")}),
    (authorization.MANUAL_STOP, authorization.Facts(), {
        "observe": ("act", "manual"), "adopt": ("act", "manual"),
        "enforce": ("act", "manual"), "auto": ("act", "manual")}),
]


class TruthTable(unittest.TestCase):
    """Every trigger x mode, as 0.2.1 behaves, decided by the ladder alone."""

    def test_every_trigger_in_every_mode(self):
        for trigger, facts, want in TRUTH:
            for mode in MODES:
                dec = authorization.authorize(trigger, mode, facts)
                self.assertEqual((dec.verdict, dec.authority), want[mode],
                                 "%s in %s" % (trigger, mode))
                self.assertTrue(dec.reason, "%s in %s: decision needs a reason" % (trigger, mode))
                # Only the unit authority can deny; nothing else contributes a vote in 0.2.1.
                deny = bool(facts.unit_survive_logout)
                self.assertEqual(dec.slot, "authority" if deny else "mode_capability",
                                 "%s in %s" % (trigger, mode))

    def test_slot_order_matches_the_spec(self):
        # spec #1, Implementation Decisions 2: hard safety -> veto -> hold -> capability -> authority
        self.assertEqual(authorization.SLOTS,
                         ("hard_safety", "veto", "hold", "mode_capability", "authority"))

    def test_unknown_trigger_or_mode_fails_closed(self):
        with self.assertRaises(ValueError):
            authorization.authorize("no_such_trigger", "auto")
        with self.assertRaises(ValueError):
            authorization.authorize(authorization.OWNER_EXIT, "yolo")

    def test_survive_logout_reason_names_the_authority(self):
        dec = authorization.authorize(authorization.SESSION_END, "enforce",
                                      authorization.Facts(unit_survive_logout=True))
        self.assertEqual(dec.verdict, "keep")
        self.assertIn("survive_logout", dec.reason)


if __name__ == "__main__":
    unittest.main()
