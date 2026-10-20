"""Authorization ladder tests (issue #5).

A table pins the current mode behavior for every lifecycle trigger, including GUI survivor
containment and adoption in adopt, auto, and enforce. Further tests pin the slot order of spec #1
Implementation Decisions 2 and prove that every daemon/CLI decision point asks the ladder instead
of checking the mode itself.
"""

import argparse
import io
import os
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

import taema.cli.commands as cli
from taema.cli import targets
from taema.model import authorization
from taema.core import cgroup, process as inspect
from taema.governor import engine
from taema.store import knowledge
from tests.test_phase0 import make_cfg, tmp
from tests.test_phase4 import AutoCase

MODES = ("observe", "adopt", "enforce", "auto")
REAL_STOP = engine.stop

# (trigger, facts, expected) with expected = {mode: (verdict, authority)}.
TRUTH = [
    (
        authorization.OWNER_EXIT,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("act", "unit"),
            "enforce": ("act", "unit"),
            "auto": ("act", "unit"),
        },
    ),
    (
        authorization.UNIT_ADOPT,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("act", "mode"),
            "enforce": ("act", "mode"),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.AUTO_ADOPT,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("act", "mode"),
            "enforce": ("act", "mode"),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.GUI_CLOSE,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("act", "mode"),
            "enforce": ("act", "mode"),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.JOB_SURVIVORS,
        authorization.Facts(),
        {
            "observe": ("keep", ""),
            "adopt": ("keep", ""),
            "enforce": ("keep", ""),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.LEFTOVER_LEAVES,
        authorization.Facts(),
        {
            "observe": ("keep", ""),
            "adopt": ("act", "mode"),
            "enforce": ("keep", ""),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.GC_STOP,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("would", ""),
            "enforce": ("act", "unit"),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.GC_STOP,
        authorization.Facts(leftover=True),
        {
            "observe": ("would", ""),
            "adopt": ("would", ""),
            "enforce": ("act", "unit"),
            "auto": ("act", "pair"),
        },
    ),
    (
        authorization.GC_REMOVE_EMPTY,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("act", "mode"),
            "enforce": ("act", "mode"),
            "auto": ("act", "mode"),
        },
    ),
    (
        authorization.SESSION_END,
        authorization.Facts(),
        {
            "observe": ("would", ""),
            "adopt": ("would", ""),
            "enforce": ("act", "unit"),
            "auto": ("act", "pair"),
        },
    ),
    (
        authorization.SESSION_END,
        authorization.Facts(shared=True),
        {
            "observe": ("would", ""),
            "adopt": ("would", ""),
            "enforce": ("act", "unit"),
            "auto": ("keep", ""),
        },
    ),
    (
        authorization.SESSION_END,
        authorization.Facts(unit_survive_logout=True),
        {
            "observe": ("keep", ""),
            "adopt": ("keep", ""),
            "enforce": ("keep", ""),
            "auto": ("keep", ""),
        },
    ),
    (
        authorization.MANUAL_STOP,
        authorization.Facts(),
        {
            "observe": ("act", "manual"),
            "adopt": ("act", "manual"),
            "enforce": ("act", "manual"),
            "auto": ("act", "manual"),
        },
    ),
]


class TruthTable(unittest.TestCase):
    """Every trigger x mode, as the current spec defines, decided by the ladder alone."""

    def test_every_trigger_in_every_mode(self):
        for trigger, facts, want in TRUTH:
            for mode in MODES:
                dec = authorization.authorize(trigger, mode, facts)
                self.assertEqual(
                    (dec.verdict, dec.authority),
                    want[mode],
                    "%s in %s" % (trigger, mode),
                )
                self.assertTrue(
                    dec.reason, "%s in %s: decision needs a reason" % (trigger, mode)
                )
                # Only the unit authority can deny; nothing else contributes a vote in 0.2.1.
                deny = bool(facts.unit_survive_logout)
                self.assertEqual(
                    dec.slot,
                    "authority" if deny else "mode_capability",
                    "%s in %s" % (trigger, mode),
                )

    def test_slot_order_matches_the_spec(self):
        # spec #1, Implementation Decisions 2: hard safety -> veto -> hold -> capability -> authority
        self.assertEqual(
            authorization.SLOTS,
            ("hard_safety", "veto", "hold", "mode_capability", "authority"),
        )

    def test_unknown_trigger_or_mode_fails_closed(self):
        with self.assertRaises(ValueError):
            authorization.authorize("no_such_trigger", "auto")
        with self.assertRaises(ValueError):
            authorization.authorize(authorization.OWNER_EXIT, "yolo")

    def test_survive_logout_reason_names_the_authority(self):
        dec = authorization.authorize(
            authorization.SESSION_END,
            "enforce",
            authorization.Facts(unit_survive_logout=True),
        )
        self.assertEqual(dec.verdict, "keep")
        self.assertIn("survive_logout", dec.reason)

    def test_explanation_facts_show_safety_and_pair_authority_in_the_ladder(self):
        protected = authorization.authorize(
            authorization.GC_STOP,
            "auto",
            authorization.Facts(hard_safety="protected comm systemd"),
        )
        self.assertEqual((protected.verdict, protected.slot), ("keep", "hard_safety"))
        self.assertIn("protected comm", protected.reason)

        unresolved_pair = authorization.authorize(
            authorization.GC_STOP,
            "auto",
            authorization.Facts(
                leftover=True,
                pair_action="ask",
                pair_reason="pair authority: no answer",
            ),
        )
        self.assertEqual(
            (unresolved_pair.verdict, unresolved_pair.slot), ("keep", "authority")
        )
        self.assertEqual(unresolved_pair.reason, "pair authority: no answer")

        answered_pair = authorization.authorize(
            authorization.GC_STOP,
            "auto",
            authorization.Facts(leftover=True, pair_action="stop"),
        )
        self.assertEqual(
            (answered_pair.verdict, answered_pair.authority), ("act", "pair")
        )

    def test_pair_authority_matrix_covers_every_mode_and_setting(self):
        levels = ("answered", "learned", "aggressive")
        pair_triggers = (
            authorization.GC_STOP,
            authorization.JOB_SURVIVORS,
            authorization.SESSION_END,
        )
        for mode in MODES:
            for level in levels:
                for explicit in (False, True):
                    for trigger in pair_triggers:
                        facts = authorization.Facts(
                            leftover=True,
                            pair_action="stop",
                            pair_reason="answered stop"
                            if explicit
                            else "silent evidence",
                            pair_explicit=explicit,
                            learn_authority=level,
                        )
                        with self.subTest(
                            mode=mode,
                            authority=level,
                            explicit=explicit,
                            trigger=trigger,
                        ):
                            result = authorization.authorize(trigger, mode, facts)
                            if mode == "enforce":
                                want = (
                                    ("act", "unit")
                                    if trigger != authorization.JOB_SURVIVORS
                                    else ("keep", "")
                                )
                            elif mode == "observe":
                                want = (
                                    ("would", "")
                                    if trigger
                                    in (
                                        authorization.GC_STOP,
                                        authorization.SESSION_END,
                                    )
                                    else ("keep", "")
                                )
                            elif level == "answered" and not explicit:
                                want = ("keep", "")
                            else:
                                want = ("act", "pair")
                            self.assertEqual((result.verdict, result.authority), want)

    def test_enforce_uses_unit_rules_even_when_pair_authority_is_unavailable(self):
        for level in ("answered", "learned", "aggressive"):
            for trigger in (authorization.GC_STOP, authorization.SESSION_END):
                with self.subTest(authority=level, trigger=trigger):
                    result = authorization.authorize(
                        trigger,
                        "enforce",
                        authorization.Facts(
                            leftover=True,
                            pair_action="invalid",
                            pair_reason="invalid legacy owner",
                            learn_authority=level,
                        ),
                    )
                    self.assertEqual(
                        (result.verdict, result.authority), ("act", "unit")
                    )

    def test_invalid_legacy_pairs_never_authorize_a_stop(self):
        for mode in ("adopt", "auto"):
            for level in ("answered", "learned", "aggressive"):
                for trigger in (
                    authorization.GC_STOP,
                    authorization.JOB_SURVIVORS,
                    authorization.SESSION_END,
                ):
                    with self.subTest(mode=mode, authority=level, trigger=trigger):
                        result = authorization.authorize(
                            trigger,
                            mode,
                            authorization.Facts(
                                leftover=True,
                                pair_action="invalid",
                                pair_reason="invalid legacy owner",
                                learn_authority=level,
                            ),
                        )
                        self.assertNotEqual(result.verdict, "act")
                        self.assertNotEqual(result.authority, "pair")

    def test_configured_leftover_expiry_uses_mode_authority(self):
        for mode in ("adopt", "auto"):
            with self.subTest(mode=mode):
                result = authorization.authorize(
                    authorization.GC_STOP,
                    mode,
                    authorization.Facts(
                        leftover=True,
                        pair_action="expiry",
                        pair_reason="leftover expired after 20 days",
                        learn_authority="answered",
                    ),
                )
                self.assertEqual((result.verdict, result.authority), ("act", "mode"))

    def test_veto_denies_every_stop_trigger_before_mode_authority(self):
        facts = authorization.Facts(scope="leftover/firefox", vetoed="app firefox")
        for mode in authorization.MODES:
            for trigger in (
                authorization.OWNER_EXIT,
                authorization.JOB_SURVIVORS,
                authorization.GC_STOP,
                authorization.SESSION_END,
                authorization.MANUAL_STOP,
            ):
                dec = authorization.authorize(trigger, mode, facts)
                self.assertEqual(
                    (dec.verdict, dec.slot),
                    (authorization.KEEP, authorization.VETO),
                    (mode, trigger),
                )
                self.assertIn("app firefox", dec.reason)


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
        self.stopm.assert_called_once()  # auto: acts

    def test_owner_bound_scope_stops_in_mutating_modes_and_logs_once_in_observe(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                self.d.cfg["mode"] = mode
                self.cg.leaf("scope-" + mode, [])
                self.stopm.reset_mock()

                self.d.stop_leaf("scope-" + mode, "owner 5 exited")

                if mode == "observe":
                    self.stopm.assert_not_called()
                    events = [
                        e
                        for e in self.log()
                        if e.get("event") == "would_stop"
                        and e.get("scope") == "scope-observe"
                    ]
                    self.assertEqual(len(events), 1)
                else:
                    self.stopm.assert_called_once()

    def test_run_bind_and_owner_forms_stop_in_every_mode(self):
        for mode in MODES:
            for source in ("bind", "owner"):
                with self.subTest(mode=mode, source=source):
                    self.d.cfg["mode"] = mode
                    self.stopm.reset_mock()
                    name = "owner-" + mode + "-" + source
                    args = argparse.Namespace(
                        name=name,
                        join=False,
                        bind=source == "bind",
                        owner=os.getpid() if source == "owner" else None,
                        cmd=["true"],
                    )
                    with (
                        mock.patch.object(
                            cli, "_load", return_value=(self.d.cfg, self.d.store, [])
                        ),
                        mock.patch.object(
                            cli, "ask", side_effect=lambda _cfg, msg: self.d.handle(msg)
                        ),
                        mock.patch.object(inspect, "uid_of", return_value=os.getuid()),
                        mock.patch.object(inspect, "starttime", return_value=123),
                        mock.patch.object(cli.engine, "helper_attach"),
                        mock.patch.object(cli.os, "execvp"),
                    ):
                        cli.cmd_run(args)

                    fd = next(
                        fd
                        for fd, (leaf, _pid, _start) in self.d.owners.items()
                        if leaf == "scope-" + name
                    )
                    self.d.on_owner_exit(fd)
                    if mode == "observe":
                        self.stopm.assert_not_called()
                        events = [
                            e
                            for e in self.log()
                            if e.get("event") == "would_stop"
                            and e.get("scope") == "scope-" + name
                        ]
                        self.assertEqual(len(events), 1)
                    else:
                        self.stopm.assert_called_once()

    def test_unit_root_binding_stops_or_logs_in_every_mode(self):
        for i, mode in enumerate(MODES):
            with self.subTest(mode=mode):
                root = 7000 + i
                self.d.cfg["mode"] = mode
                app = "app-" + mode
                self.fp.add(root, 1, comm="qemu", sid=root, born=self.fp.up - 100)
                self.cg.leaf(app, [root])
                self.d.units = [
                    {
                        "unit": {"name": app, "kind": "app"},
                        "children": [
                            {"name": "vm", "ancestor_comm": "qemu", "binds_to": "root"},
                        ],
                    }
                ]
                self.stopm.reset_mock()
                with (
                    mock.patch.object(engine, "auto_adopt_plan", return_value=[]),
                    mock.patch.object(inspect, "uid_of", return_value=os.getuid()),
                    mock.patch.object(inspect, "starttime", return_value=123),
                    mock.patch.object(
                        os,
                        "pidfd_open",
                        side_effect=lambda _pid: os.open(os.devnull, os.O_RDONLY),
                    ),
                    mock.patch.object(self.d.sel, "register"),
                    mock.patch.object(self.d.sel, "unregister"),
                ):
                    self.d.adopt_pass()

                    self.assertEqual(len(self.d.owners), 1)
                    fd = next(iter(self.d.owners))
                    leaf = self.d.owners[fd][0]
                    self.d.on_owner_exit(fd)
                if mode == "observe":
                    self.stopm.assert_not_called()
                    events = [
                        e
                        for e in self.log()
                        if e.get("event") == "would_stop" and e.get("scope") == leaf
                    ]
                    self.assertEqual(len(events), 1)
                else:
                    self.stopm.assert_called_once()

    def test_owner_bound_stop_keeps_shared_and_protected_members_safe(self):
        self.d.cfg["mode"] = "adopt"
        self.fp.add(4001, 1, comm="server")
        self.fp.add(4002, 1, comm="niri")
        self.cg.leaf("scope-bound", [4001, 4002])
        self.edges[4001] = [
            {"kind": "tcp_client", "detail": "127.0.0.1:9", "peers": [90]}
        ]
        with (
            mock.patch.object(inspect, "uid_of", return_value=os.getuid()),
            mock.patch.object(engine, "stop", wraps=REAL_STOP),
            mock.patch.object(engine, "_signal_all") as signal_all,
        ):
            self.d.stop_leaf("scope-bound", "owner 5 exited")

        signal_all.assert_not_called()
        self.assertTrue(os.path.isdir(self.cg.base + "/shared/server-4001"))
        stopped = [e for e in self.log() if e.get("event") == "stop"][-1]
        self.assertEqual(
            {d["pid"]: d["action"] for d in stopped["decisions"]},
            {4001: "share", 4002: "skip"},
        )

    def test_adopt_pass_asks_unit_adopt_and_auto_adopt(self):
        m = self.asked()
        with mock.patch.object(
            inspect.ProcTable, "scan", return_value=inspect.ProcTable()
        ):
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
        self.d.handle(
            {
                "cmd": "job_done",
                "shell_pid": 20,
                "tag": "20.1",
                "status": 0,
                "word": "npm",
            }
        )
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
        self.d.idle_since["leftover/x"] = (
            time.time() - 5000
        )  # past the idle grace: a candidate
        self.d.gc_usage["leftover/x"] = 100
        self.cg.leaf("scope-e", [])  # empty leaf on the second pass
        m = self.asked()
        self.d.gc_pass()
        got = self.triggers(m)
        self.assertIn(authorization.LEFTOVER_LEAVES, got)  # GC candidate selection
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
        self.assertEqual(kept, ["app-x"])  # auto: empty scope has no pair


class ManualKillRouting(unittest.TestCase):
    """AC 1: the manual `taema kill` asks the ladder and behaves exactly as before."""

    def test_cmd_kill_asks_manual_stop_and_output_is_unchanged(self):
        cfg = make_cfg(tmp(), mode="observe")
        store = knowledge.Store(tmp(), {})
        rep = {"scope": "scope-x", "decisions": [], "removed": True, "left": []}
        a = argparse.Namespace(
            name="x", timeout=None, force=False, hard=False, keep=None, dry_run=False
        )
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(
                cli,
                "_target_candidates",
                return_value=[
                    targets.Target("scope", "scope-x", "scope:scope-x", scope="scope-x")
                ],
            ),
            mock.patch.object(cgroup, "resolve", return_value="/cg/user/1/scope-x"),
            mock.patch.object(engine, "stop", return_value=rep),
            mock.patch.object(
                authorization, "authorize", wraps=authorization.authorize
            ) as m,
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_kill(a)
        self.assertEqual(rc, 0)
        self.assertEqual(
            [c.args[0] for c in m.call_args_list], [authorization.MANUAL_STOP]
        )
        self.assertEqual(out.getvalue(), "scope scope-x stopped\n")


if __name__ == "__main__":
    unittest.main()
