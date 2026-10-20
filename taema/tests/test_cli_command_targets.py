"""Target-aware command behavior at the CLI boundary."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from taema.cli import targets, view
import taema.cli.commands as cli
from taema.store import knowledge
from tests.test_phase0 import make_cfg


class TargetCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = knowledge.Store(self.temp.name, {})
        self.cfg = make_cfg(self.temp.name)

    def test_explain_resolves_app_desktop_and_scope_targets(self):
        app = targets.Target("app", "browser", "app:browser", app_key="browser")
        desktop = targets.Target(
            "desktop",
            "org.example.Browser.desktop",
            "desktop:org.example.Browser.desktop",
            app_key="browser",
        )
        scope = targets.Target(
            "scope", "scope-browser", "scope:scope-browser", scope="scope-browser"
        )
        for query, candidate in (
            ("app:browser", app),
            ("desktop:org.example.Browser.desktop", desktop),
        ):
            with (
                self.subTest(query=query),
                mock.patch.object(
                    cli, "_load", return_value=(self.cfg, self.store, [])
                ),
                mock.patch.object(cli, "_target_candidates", return_value=[candidate]),
                mock.patch.object(view, "emit") as emit,
            ):
                self.assertEqual(
                    cli.cmd_explain(SimpleNamespace(target=query, pick=False)), 0
                )
                self.assertEqual(emit.call_args.args[0]["target"], query)

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[scope]),
            mock.patch.object(
                cli, "_target_scope_path", return_value="/cg/scope-browser"
            ),
            mock.patch.object(cli.engine, "unit_for_leaf", return_value=None),
            mock.patch.object(cli.engine, "plan_stop", return_value=[]),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="scope-browser", pick=False)), 0
            )
            self.assertEqual(emit.call_args.args[0]["explanation"], {"plan": []})

    def test_explain_pid_checks_starttime_before_building_report(self):
        pid = targets.Target("pid", "42", "pid:42", scope="scope-x", pid=42, start=100)
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[pid]),
            mock.patch.object(cli.inspect, "starttime", return_value=100),
            mock.patch.object(cli.inspect, "ppid_map", return_value={}),
            mock.patch.object(cli.inspect, "descendants", return_value={42}),
            mock.patch.object(cli.inspect, "edges", return_value={42: []}),
            mock.patch.object(cli.inspect, "comm", return_value="browser"),
            mock.patch.object(cli.cgroup, "proc_cgroup", return_value="scope-x"),
            mock.patch.object(cli.policy, "exe_key", return_value="browser"),
            mock.patch.object(cli.policy, "app_key", return_value="browser"),
            mock.patch.object(cli.policy, "protected_reason", return_value=None),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="pid:42", pick=False)), 0
            )
            self.assertEqual(emit.call_args.args[0]["explanation"]["pid"], 42)

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[pid]),
            mock.patch.object(cli.inspect, "starttime", return_value=101),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="pid:42", pick=False)), 2
            )

    def test_keep_resolves_live_app_and_dry_run_does_not_write(self):
        app = targets.Target("app", "browser", "app:browser", app_key="browser")
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[app]),
            mock.patch.object(cli, "feedback", return_value="queued") as feedback,
            mock.patch.object(self.store, "bump") as bump,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(
                    SimpleNamespace(exe="app:browser", dry_run=False, pick=False)
                ),
                0,
            )
        feedback.assert_called_once_with(self.cfg, self.store, "keep", "browser")
        bump.assert_called_once()

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[app]),
            mock.patch.object(cli, "feedback") as feedback,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(SimpleNamespace(exe="browser", dry_run=True, pick=False)),
                0,
            )
        feedback.assert_not_called()

    def test_unknown_desktop_id_is_rejected_for_mutating_target_commands(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[]),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(
                    SimpleNamespace(
                        exe="desktop:missing.desktop", dry_run=False, pick=False
                    )
                ),
                2,
            )
            self.assertEqual(
                cli.cmd_do_not_kill(
                    SimpleNamespace(
                        target="desktop:missing.desktop", dry_run=False, pick=False
                    )
                ),
                2,
            )

    def test_bulk_confirmation_prints_a_plan_and_honors_yes(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertFalse(
                cli._confirm_bulk(
                    "adopt", ["scope-a", "scope-b"], SimpleNamespace(yes=False)
                )
            )
        self.assertIn("plan: adopt affects 2 targets", output.getvalue())
        self.assertIn("--yes", errors.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertTrue(
                cli._confirm_bulk("adopt", ["scope-a"], SimpleNamespace(yes=True))
            )

    def test_explicit_app_query_is_a_completion_candidate_even_when_not_live(self):
        with mock.patch.object(targets, "live_targets", return_value=[]):
            found = cli._target_candidates("app:learned", self.store)
        self.assertEqual(
            [(item.kind, item.value) for item in found], [("app", "learned")]
        )


if __name__ == "__main__":
    unittest.main()
