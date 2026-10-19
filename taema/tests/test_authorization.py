"""Authorization ladder tests (issue #5).

A table pins the M0 behaviour of every lifecycle trigger in every mode. Further tests pin the slot
order of spec #1 Implementation Decisions 2 and prove that every daemon/CLI decision point asks
the ladder instead of checking the mode itself.
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
        "observe": ("would", ""), "adopt": ("act", "mode"),
        "enforce": ("act", "mode"), "auto": ("act", "mode")}),
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
    """Every trigger x mode, as M0 behaves, decided by the ladder alone."""

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


class DaemonRouting(AutoCase):
    """AC 1: every daemon path that moves, stops, or adopts asks the ladder, not the mode."""

    def asked(self):
        p = mock.patch.object(authorization, "authorize", wraps=authorization.authorize)
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def triggers(self, m):
        return [c.args[0] for c in m.call_args_list]

    def test_stop_leaf_asks_owner_exit(self):
        self.cg.leaf("scope-x", [])
        m = self.asked()
        self.d.stop_leaf("scope-x", "owner 5 exited")
        self.assertIn(authorization.OWNER_EXIT, self.triggers(m))
        self.stopm.assert_called_once()                     # auto: acts

    def test_adopt_pass_asks_unit_adopt_and_auto_adopt(self):
        m = self.asked()
        with mock.patch.object(inspect.ProcTable, "scan", return_value=inspect.ProcTable()):
            self.d.adopt_pass()
        got = self.triggers(m)
        self.assertIn(authorization.UNIT_ADOPT, got)
        self.assertIn(authorization.AUTO_ADOPT, got)

    def test_after_observe_asks_gui_close(self):
        up = self.fp.up
        self.fp.add(100, 1, comm="niri", sid=100, born=100.0)
        self.fp.add(200, 100, comm="firefox", born=up - 100)
        self.fp.add(201, 200, comm="helper", born=up - 90)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(200)
        self.d.lineage.observe(self.fp.table())
        m = self.asked()
        self.d.after_observe()
        self.assertIn(authorization.GUI_CLOSE, self.triggers(m))
        self.assertTrue(os.path.isdir("%s/leftover/firefox-200" % self.cg.base))

    def test_decide_job_asks_job_survivors(self):
        env = {"TAEMA_JOB": "20.1"}
        up = self.fp.up
        self.fp.add(21, 20, comm="npm", env=env, born=up - 6.0, pgrp=21)
        self.fp.add(30, 1, comm="vite", env=env, born=up - 5.0, sid=30)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "npm"})
        self.d.deadlines.clear()
        self.idle(30)
        m = self.asked()
        self.d.decide_job("20.1")
        self.assertIn(authorization.JOB_SURVIVORS, self.triggers(m))

    def test_gc_pass_asks_candidate_selection_stop_and_empty_removal(self):
        self.fp.add(301, 1, comm="vite", sid=301, born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        self.d.lineage.entry(301)["root_key"] = "foo"
        self.idle(301)
        self.cg.leaf("leftover/x", [301], cpu=100)
        self.d.idle_since["leftover/x"] = time.time() - 5000   # past the idle grace: a candidate
        self.d.gc_usage["leftover/x"] = 100
        self.cg.leaf("scope-e", [])                          # empty leaf on the second pass
        m = self.asked()
        self.d.gc_pass()
        got = self.triggers(m)
        self.assertIn(authorization.LEFTOVER_LEAVES, got)    # GC candidate selection
        self.assertIn(authorization.GC_STOP, got)
        self.assertIn(authorization.GC_REMOVE_EMPTY, got)

    def test_end_session_asks_leftover_selection_and_session_end(self):
        self.cg.leaf("app-x", [])
        m = self.asked()
        self.d.end_session()
        got = self.triggers(m)
        self.assertIn(authorization.LEFTOVER_LEAVES, got)
        self.assertIn(authorization.SESSION_END, got)
        kept = [e["scope"] for e in self.log() if e["event"] == "session_end_kept"]
        self.assertEqual(kept, ["app-x"])                    # auto: empty scope has no pair


class ManualKillRouting(unittest.TestCase):
    """AC 1: the manual `taema kill` asks the ladder and behaves exactly as before."""

    def test_cmd_kill_asks_manual_stop_and_output_is_unchanged(self):
        cfg = make_cfg(tmp(), mode="observe")
        store = knowledge.Store(tmp(), {})
        rep = {"scope": "scope-x", "decisions": [], "removed": True, "left": []}
        a = argparse.Namespace(name="x", timeout=None, force=False, hard=False,
                               keep=None, dry_run=False)
        with mock.patch.object(cli, "_load", return_value=(cfg, store, [])), \
                mock.patch.object(cgroup, "resolve", return_value="/cg/user/1/scope-x"), \
                mock.patch.object(engine, "stop", return_value=rep), \
                mock.patch.object(authorization, "authorize",
                                  wraps=authorization.authorize) as m:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_kill(a)
        self.assertEqual(rc, 0)
        self.assertEqual([c.args[0] for c in m.call_args_list], [authorization.MANUAL_STOP])
        self.assertEqual(out.getvalue(), "scope scope-x stopped\n")


if __name__ == "__main__":
    unittest.main()
