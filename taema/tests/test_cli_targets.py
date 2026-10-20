"""Target matching, live cgroup discovery, picker, and completion contracts."""

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from taema.cli import commands, targets
from taema.core import cgroup, process
from taema.config import policy
from taema.store import knowledge
from tests.test_phase0 import FakeCg


class TargetResolution(unittest.TestCase):
    def candidates(self):
        return [
            targets.Target(
                "scope", "scope-browser", "scope:scope-browser", scope="scope-browser"
            ),
            targets.Target(
                "app",
                "firefox",
                "app:firefox",
                scope="scope-browser",
                app_key="firefox",
            ),
            targets.Target(
                "app",
                "firefox-nightly",
                "app:firefox-nightly",
                scope="scope-nightly",
                app_key="firefox-nightly",
            ),
            targets.Target(
                "pid", "42", "pid:42", scope="scope-browser", pid=42, start=123
            ),
            targets.Target(
                "desktop",
                "org.example.Browser.desktop",
                "desktop:org.example.Browser.desktop",
                scope="scope-browser",
                desktop_id="org.example.Browser.desktop",
                app_key="firefox",
            ),
        ]

    def test_explicit_kinds_and_scope_aliases_resolve_exactly(self):
        candidates = self.candidates()
        self.assertEqual(
            targets.resolve_target("scope:browser", candidates).value, "scope-browser"
        )
        self.assertEqual(
            targets.resolve_target("app:firefox", candidates).value, "firefox"
        )
        self.assertEqual(targets.resolve_target("pid:42", candidates).start, 123)
        self.assertEqual(
            targets.resolve_target("desktop:org.example.Browser", candidates).value,
            "org.example.Browser.desktop",
        )

    def test_numeric_pid_targets_never_use_substring_matching(self):
        candidate = targets.Target("pid", "8942", "pid:8942", pid=8942, start=123)
        self.assertEqual(targets.matching_targets("42", [candidate]), [])
        self.assertEqual(targets.matching_targets("pid:42", [candidate]), [])
        self.assertEqual(targets.matching_targets("8942", [candidate]), [candidate])

    def test_unique_substring_matches_and_ambiguity_is_reported(self):
        candidates = self.candidates()
        self.assertEqual(
            targets.resolve_target("nightly", candidates).value, "firefox-nightly"
        )
        with self.assertRaises(targets.TargetAmbiguous) as raised:
            targets.resolve_target("fire", candidates)
        self.assertEqual(len(raised.exception.candidates), 2)
        with self.assertRaises(targets.TargetNotFound):
            targets.resolve_target("app:missing", candidates)

    def test_ambiguous_terminal_target_uses_numbered_picker(self):
        candidates = [
            targets.Target("app", "firefox", "app:firefox"),
            targets.Target("app", "firefox-nightly", "app:firefox-nightly"),
        ]
        output = io.StringIO()
        selected = targets.select_target(
            "fire",
            candidates,
            interactive=True,
            input_fn=lambda: "2",
            output=output,
        )
        self.assertEqual(selected.value, "firefox-nightly")
        self.assertIn("1) app:firefox", output.getvalue())
        with self.assertRaises(targets.TargetAmbiguous):
            targets.select_target("fire", candidates, interactive=False)

    def test_fzf_selection_and_cancellation(self):
        candidates = [
            targets.Target("app", "firefox", "app:firefox"),
            targets.Target("app", "firefox-nightly", "app:firefox-nightly"),
        ]
        with mock.patch.object(
            targets.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout="app:firefox-nightly\n"),
        ) as run:
            selected = targets.select_target(
                "fire", candidates, pick=True, interactive=False
            )
        self.assertEqual(selected.value, "firefox-nightly")
        self.assertIn("app:firefox", run.call_args.kwargs["input"])
        with mock.patch.object(
            targets.subprocess,
            "run",
            return_value=mock.Mock(returncode=1, stdout=""),
        ):
            self.assertIsNone(
                targets.select_target("fire", candidates, pick=True, interactive=False)
            )

    def test_live_targets_discover_scopes_apps_pids_and_desktop_ids(self):
        with FakeCg() as cg:
            cg.leaf("scope-browser", pids=[42])
            cg.leaf("leftover/owner-1", pids=[43])
            starts = {42: 100, 43: 200}
            keys = {42: "firefox", 43: "python:helper.py"}
            environments = {
                42: {"GIO_LAUNCHED_DESKTOP_FILE": "/apps/org.example.Browser.desktop"},
                43: {},
            }
            with (
                mock.patch.object(process, "starttime", side_effect=starts.get),
                mock.patch.object(process, "uid_of", return_value=os.getuid()),
                mock.patch.object(
                    policy, "app_key", side_effect=lambda pid, **_kwargs: keys.get(pid)
                ),
                mock.patch.object(process, "comm", side_effect=lambda pid: keys[pid]),
                mock.patch.object(process, "environ", side_effect=environments.get),
            ):
                found = targets.live_targets()
        self.assertIn(
            ("scope", "scope-browser"), {(item.kind, item.value) for item in found}
        )
        self.assertIn(("app", "firefox"), {(item.kind, item.value) for item in found})
        self.assertIn(("pid", "42"), {(item.kind, item.value) for item in found})
        self.assertIn(
            ("desktop", "org.example.Browser.desktop"),
            {(item.kind, item.value) for item in found},
        )
        self.assertEqual(
            [item.value for item in targets.leftover_targets(found)],
            ["leftover/owner-1"],
        )

    def test_pid_target_carries_managed_scope_and_start_time(self):
        with FakeCg() as cg:
            cg.leaf("scope-browser", pids=[42])
            base_rel = cg.base[len(cgroup.CG) :]
            with (
                mock.patch.object(process, "starttime", return_value=100),
                mock.patch.object(process, "uid_of", return_value=os.getuid()),
                mock.patch.object(process, "comm", return_value="firefox"),
                mock.patch.object(
                    cgroup,
                    "proc_cgroup",
                    return_value=base_rel + "/scope-browser",
                ),
            ):
                target = targets.process_target(42)
        self.assertEqual(target.scope, "scope-browser")
        self.assertEqual(target.start, 100)
        with mock.patch.object(process, "starttime", return_value=None):
            with self.assertRaises(targets.TargetNotFound):
                targets.process_target(42)

    def test_completion_values_include_target_kinds_and_review_ids(self):
        candidates = self.candidates()
        values = targets.completion_values(candidates, [4, 9])
        self.assertIn("scope:scope-browser", values)
        self.assertIn("app:firefox", values)
        self.assertIn("desktop:org.example.Browser.desktop", values)
        self.assertIn("review:4", values)
        self.assertEqual(values, sorted(values, key=str.casefold))

    def test_cli_completions_read_registry_and_live_names(self):
        with tempfile.TemporaryDirectory() as state_dir:
            store = knowledge.Store(state_dir, {})
            candidates = self.candidates()
            args = type(
                "Args",
                (),
                {
                    "shell": "bash",
                    "word": "app:",
                    "line": "taema kill app:",
                    "cursor": None,
                },
            )()
            output = io.StringIO()
            with (
                mock.patch.object(commands, "_load", return_value=({}, store, [])),
                mock.patch.object(targets, "live_targets", return_value=candidates),
                mock.patch.object(store, "open_reviews", return_value=[{"id": 7}]),
                mock.patch("sys.stdout", output),
            ):
                self.assertEqual(commands.cmd_complete(args), 0)
            self.assertIn("app:firefox", output.getvalue().splitlines())
            self.assertIn("app:firefox-nightly", output.getvalue().splitlines())

    def test_completion_scripts_are_installed_for_all_three_shells(self):
        root = Path(__file__).resolve().parents[1]
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        self.assertIn("shell/completion.bash $(BASHCOMP)/taema", makefile)
        self.assertIn("shell/_taema $(ZSHCOMP)/_taema", makefile)
        self.assertIn("shell/completion.fish $(FISHCOMP)/taema.fish", makefile)


if __name__ == "__main__":
    unittest.main()
