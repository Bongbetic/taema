"""CLI registry, shared view output, and fast parser contract tests."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

import taema.cli.commands as commands
import taema.cli as cli_package
from taema.cli import fast, framework, view
from taema.core import process
from taema.store import knowledge
from tests.test_ipc_v2 import matches
from tests.test_phase0 import FakeCg, make_cfg


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "cli" / "read-v1.json").read_text())


class CliRegistry(unittest.TestCase):
    def test_legacy_commands_and_requested_aliases_are_registered(self):
        parser = framework._parser()
        aliases = {
            "stop": ["scope-x"],
            "kill": ["scope-x"],
            "ps": [],
            "ls": [],
            "why": ["app:firefox"],
            "explain": ["app:firefox"],
            "allow": ["firefox"],
            "keep": ["firefox"],
            "dnk": ["firefox"],
            "never": ["firefox"],
            "undo": [],
            "review": [],
            "doctor": [],
            "hold": [],
            "resume": [],
            "snooze": ["2h"],
            "status": [],
            "watch": [],
            "events": ["--since", "12", "--event", "review_created", "--follow"],
            "prompt": [],
            "gc": [],
            "adopt": [],
            "daemon": [],
            "learn": ["export", "--format", "v2"],
            "run": ["scope-x", "true"],
            "forget": ["firefox"],
        }
        for alias, arguments in aliases.items():
            with self.subTest(alias=alias):
                parsed = parser.parse_args([alias, *arguments])
                self.assertEqual(
                    parsed._command,
                    {
                        "stop": "kill",
                        "ps": "ls",
                        "why": "explain",
                        "allow": "keep",
                        "dnk": "do-not-kill",
                        "never": "do-not-kill",
                    }.get(alias, alias if alias != "learn" else "learn export"),
                )
                self.assertTrue(parsed._handler)

    def test_global_flags_parse_before_and_after_commands(self):
        parser = framework._parser()
        before = parser.parse_args(
            [
                "--plain",
                "--wide",
                "--no-color",
                "--quiet",
                "--yes",
                "--socket",
                "/tmp/taema.sock",
                "--config",
                "/tmp/taema.toml",
                "--verbose",
                "status",
            ]
        )
        after = parser.parse_args(
            ["status", "--plain", "--wide", "--socket", "/tmp/other.sock", "--json"]
        )
        self.assertTrue(before.plain and before.wide and before.no_color)
        self.assertTrue(before.quiet and before.yes and before.verbose)
        self.assertEqual(before.socket, "/tmp/taema.sock")
        self.assertEqual(before.config, "/tmp/taema.toml")
        self.assertEqual(after.socket, "/tmp/other.sock")
        self.assertTrue(after.plain and after.wide and after.json)

    def test_fast_status_parser_accepts_values_and_rejects_other_commands(self):
        args = framework._fast_status_args(
            ["--socket=/tmp/taema.sock", "status", "--config", "/tmp/config.toml"]
        )
        self.assertEqual(args.socket, "/tmp/taema.sock")
        self.assertEqual(args.config, "/tmp/config.toml")
        self.assertFalse(args._summary)
        self.assertIsNone(framework._fast_status_args(["status", "--help"]))
        self.assertIsNone(framework._fast_status_args(["ls"]))
        self.assertIsNone(framework._fast_status_args(["--config"]))
        self.assertIsNone(framework._fast_status_args(["--json", "--jsonl"]))

    def test_selected_command_skips_global_options_and_legacy_veto(self):
        self.assertEqual(
            framework._selected_command(
                ["--socket", "/tmp/a.sock", "--config=/tmp/cfg", "status"]
            ),
            "status",
        )
        self.assertEqual(
            framework._selected_command(["--do-not-kill", "firefox"]), None
        )
        self.assertEqual(framework._selected_command(["--mystery", "ls"]), "ls")

    def test_status_fast_parser_accepts_common_options_without_argparse(self):
        args = framework._fast_status_args(
            ["--plain", "--config", "/tmp/taema.toml", "status", "--json"]
        )
        self.assertEqual(args.command, "status")
        self.assertTrue(args.plain and args.json)
        self.assertEqual(args.config, "/tmp/taema.toml")
        self.assertIsNone(framework._fast_status_args(["status", "--help"]))

    def test_unknown_command_suggests_close_match_and_a_fix(self):
        error = io.StringIO()
        with redirect_stderr(error):
            result = framework.main(["statuz"])
        self.assertEqual(result, 1)
        self.assertIn("hint:", error.getvalue())
        self.assertIn("Did you mean `taema status`?", error.getvalue())

    def test_invalid_read_mode_and_empty_run_have_hints(self):
        for argv in (["kill", "--json", "scope-x"], ["run", "scope-x"]):
            error = io.StringIO()
            with self.subTest(argv=argv), redirect_stderr(error):
                result = framework.main(argv)
            self.assertEqual(result, 1)
            self.assertIn("hint:", error.getvalue())
            self.assertIn("suggestion:", error.getvalue())

    def test_pager_is_used_only_for_a_terminal_and_bad_pager_is_ignored(self):
        with mock.patch.dict(os.environ, {"PAGER": "cat"}, clear=True):
            with mock.patch.object(framework.sys, "stdout", io.StringIO()):
                self.assertFalse(framework._page("text"))
            tty = SimpleNamespace(isatty=lambda: True)
            with (
                mock.patch.object(framework.sys, "stdout", tty),
                mock.patch(
                    "subprocess.run", return_value=SimpleNamespace(returncode=0)
                ) as run,
            ):
                self.assertTrue(framework._page("page me"))
            self.assertEqual(run.call_args.kwargs["input"], "page me")
        with mock.patch.dict(os.environ, {"PAGER": "'"}, clear=True):
            with mock.patch.object(
                framework.sys, "stdout", SimpleNamespace(isatty=lambda: True)
            ):
                self.assertFalse(framework._page("text"))

    def test_fast_help_uses_registered_commands_and_options(self):
        help_output = fast.help_text()
        self.assertIn("kill, stop", help_output)
        self.assertIn("--config", help_output)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(fast.main(), 0)
        self.assertEqual(output.getvalue(), help_output)

    def test_lazy_package_keeps_legacy_stdlib_exports(self):
        for name in ("socket", "tempfile", "time", "uuid"):
            with self.subTest(name=name):
                self.assertEqual(getattr(cli_package, name).__name__, name)
        self.assertIs(cli_package.commands, commands)

    def test_lazy_module_forwards_mock_assignment_and_deletion(self):
        proxy = commands._LazyModule("_test_process_proxy", "taema.core.process")
        proxy._temporary = True
        del proxy._temporary
        original = process.starttime
        try:
            proxy.starttime = lambda _pid: 456
            self.assertEqual(process.starttime(42), 456)
            del proxy.starttime
            proxy.starttime = original

            fresh = commands._LazyModule(
                "_test_process_proxy_fresh", "taema.core.process"
            )
            del fresh.starttime
            fresh.starttime = original
        finally:
            process.starttime = original
            commands.__dict__.pop("_test_process_proxy", None)
            commands.__dict__.pop("_test_process_proxy_fresh", None)

    def test_help_and_version_do_not_import_command_implementation(self):
        source = str(ROOT / "src")
        script = (
            "import sys; sys.path.insert(0, %r); "
            "from taema.cli import framework; "
            "forbidden = 'taema.cli.commands'; "
            "\ntry: framework.main(['--version'])\nexcept SystemExit: pass\n"
            "assert forbidden not in sys.modules\n"
            "try: framework.main(['--help'])\nexcept SystemExit: pass\n"
            "assert forbidden not in sys.modules\n"
        ) % source
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class CliViews(unittest.TestCase):
    def test_status_loader_skips_fast_store_until_needed(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = os.path.join(temporary, "state")
            config_path = os.path.join(temporary, "taema.toml")
            Path(config_path).write_text(
                "[paths]\nstate_dir = %s\n" % json.dumps(state_dir),
                encoding="utf-8",
            )
            missing, missing_store = commands._load_status(
                SimpleNamespace(config=config_path)
            )
            self.assertIsNone(missing_store)

            os.makedirs(state_dir)
            knowledge.Store(state_dir, {})
            fast_cfg, fast_store = commands._load_status(
                SimpleNamespace(config=config_path, socket="~/taema.sock", _fast=True)
            )
            self.assertIsNone(fast_store)
            self.assertEqual(
                fast_cfg["paths"]["socket"], os.path.expanduser("~/taema.sock")
            )

            loaded_cfg, loaded_store = commands._load_status(
                SimpleNamespace(config=config_path)
            )
            self.assertIsInstance(loaded_store, knowledge.Store)
            self.assertEqual(loaded_cfg["paths"]["state_dir"], state_dir)
            self.assertIsNone(
                commands._status_store(make_cfg(os.path.join(temporary, "empty")))
            )
            self.assertIsNone(commands._status_store(fast_cfg, pending_only=True))
            Path(state_dir, "feedback.jsonl.replay").write_text("", encoding="utf-8")
            self.assertIsInstance(
                commands._status_store(fast_cfg, pending_only=True), knowledge.Store
            )

    def test_status_and_ls_emit_schema_valid_shared_snapshots(self):
        with tempfile.TemporaryDirectory() as state_dir:
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir)
            output = io.StringIO()
            args = SimpleNamespace(json=True, jsonl=False, quiet=False)
            with (
                mock.patch.object(commands, "_load_status", return_value=(cfg, store)),
                mock.patch.object(commands, "ask", return_value=None),
                mock.patch.object(
                    commands.cgroup, "base", return_value="/missing/cgroup"
                ),
                redirect_stdout(output),
            ):
                result = commands.main(["status", "--json"])
            status = json.loads(output.getvalue())
            self.assertEqual(result, 3)
            self.assertTrue(matches(status, SCHEMA, SCHEMA))
            self.assertEqual(status["schema"], "taema.view.v1")
            self.assertEqual(status["status"]["daemon"], "unavailable")

        with FakeCg() as cg:
            cg.leaf("scope-json")
            output = io.StringIO()
            args = SimpleNamespace(json=True, jsonl=False, quiet=False, wide=False)
            with redirect_stdout(output):
                result = commands.cmd_ls(args)
            scopes = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertTrue(matches(scopes, SCHEMA, SCHEMA))
            self.assertEqual(scopes["kind"], "ls")
            self.assertEqual(scopes["scopes"][0]["name"], "scope-json")

    def test_jsonl_uses_one_schema_tagged_record_per_scope(self):
        with FakeCg() as cg:
            cg.leaf("scope-a")
            cg.leaf("scope-b")
            output = io.StringIO()
            args = SimpleNamespace(json=False, jsonl=True, quiet=False, wide=False)
            with redirect_stdout(output):
                commands.cmd_ls(args)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(matches(record, SCHEMA, SCHEMA) for record in records))
        self.assertEqual({record["schema"] for record in records}, {"taema.scope.v1"})

    def test_no_arguments_prints_compact_status_summary(self):
        with tempfile.TemporaryDirectory() as state_dir:
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir)
            output = io.StringIO()
            with (
                mock.patch.object(commands, "_load_status", return_value=(cfg, store)),
                mock.patch.object(commands, "ask", return_value=None),
                mock.patch.object(
                    commands.cgroup, "base", return_value="/missing/cgroup"
                ),
                redirect_stdout(output),
            ):
                result = commands.main([])
        self.assertEqual(result, 3)
        self.assertEqual(
            output.getvalue(),
            "tæma status\n"
            "daemon: unavailable\n"
            "mode: observe\n"
            "profile: auto (automatic profile selection)\n"
            "scopes: 0\n"
            "reviews: 0\n"
            "feedback_invalid: 0\n",
        )

    def test_color_environment_and_plain_flags_are_respected(self):
        tty = SimpleNamespace(isatty=lambda: True)
        args = SimpleNamespace(plain=False, no_color=False)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(view.color_enabled(args, tty))
            with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True):
                self.assertFalse(view.color_enabled(args, tty))
            with mock.patch.dict(os.environ, {"CLICOLOR_FORCE": "1"}, clear=True):
                self.assertTrue(view.color_enabled(args, io.StringIO()))
        args.plain = True
        with mock.patch.dict(os.environ, {"CLICOLOR_FORCE": "1"}, clear=True):
            self.assertFalse(view.color_enabled(args, tty))

    def test_config_and_socket_overrides_reach_store_and_daemon_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = os.path.join(temporary, "state")
            config_path = os.path.join(temporary, "taema.toml")
            Path(config_path).write_text(
                '[paths]\nstate_dir = "%s"\n' % state_dir,
                encoding="utf-8",
            )
            args = SimpleNamespace(config=config_path, socket="~/taema-test.sock")
            cfg, _store, _units = commands._load(args)
        self.assertEqual(cfg["_sources"], [config_path])
        self.assertEqual(
            cfg["paths"]["socket"], os.path.expanduser("~/taema-test.sock")
        )
        self.assertEqual(cfg["paths"]["socket_fallback"], cfg["paths"]["socket"])


if __name__ == "__main__":
    unittest.main()
