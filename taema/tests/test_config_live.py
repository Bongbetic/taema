"""Live configuration layering, editing, and daemon reload contract."""

import builtins
import datetime
import io
import os
from pathlib import Path
import signal
import tempfile
import time
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema.cli import commands, framework
from taema.config import policy
from taema.config import management
from taema.daemon import service
from taema import doctor


class ConfigLayering(unittest.TestCase):
    def write(self, path, text):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
        return str(path)

    def test_ordered_dropins_and_protected_union_have_sources(self):
        with tempfile.TemporaryDirectory() as root:
            system = self.write(
                Path(root) / "etc/taema.toml",
                'mode = "observe"\n[protected]\ncomm = ["system"]\n[timers]\nidle_grace = 1\n',
            )
            self.write(
                Path(root) / "etc/taema.d/10-first.toml",
                '[timers]\nidle_grace = 10\n[protected]\ncomm = ["first"]\n',
            )
            self.write(
                Path(root) / "etc/taema.d/20-last.toml",
                '[timers]\nidle_grace = 20\n[protected]\ncomm = ["last"]\n',
            )
            config_home = Path(root) / "home/.config"
            user = self.write(
                config_home / "taema/taema.toml",
                'mode = "adopt"\n[timers]\nidle_grace = 30\n[protected]\ncomm = ["user"]\n',
            )
            self.write(
                config_home / "taema/taema.d/10-local.toml",
                '[timers]\nidle_grace = 40\n[protected]\ncomm = ["local"]\n',
            )
            self.write(
                config_home / "taema/taema.d/50-cli.toml",
                '[timers]\nidle_grace = 50\n[protected]\ncomm = ["cli"]\n',
            )
            with (
                mock.patch.object(policy, "SYSTEM_CONFIG", system),
                mock.patch.dict(
                    os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False
                ),
            ):
                os.environ.pop("TAEMA_CONFIG", None)
                cfg = policy.load_config()

        self.assertEqual(cfg["mode"], "adopt")
        self.assertEqual(cfg["timers"]["idle_grace"], 50)
        self.assertEqual(
            cfg["protected"]["comm"],
            ["system", "first", "last", "user", "local", "cli"],
        )
        self.assertEqual(
            cfg["_sources"],
            [
                system,
                str(Path(root) / "etc/taema.d/10-first.toml"),
                str(Path(root) / "etc/taema.d/20-last.toml"),
                user,
                str(Path(root) / "home/.config/taema/taema.d/10-local.toml"),
                str(Path(root) / "home/.config/taema/taema.d/50-cli.toml"),
            ],
        )
        self.assertEqual(
            cfg["_source_map"]["timers.idle_grace"],
            str(Path(root) / "home/.config/taema/taema.d/50-cli.toml"),
        )

    def test_taema_config_replaces_all_file_layers(self):
        with tempfile.TemporaryDirectory() as root:
            system = self.write(
                Path(root) / "etc/taema.toml",
                'mode = "enforce"\n[protected]\ncomm = ["system"]\n',
            )
            isolated = self.write(
                Path(root) / "isolated.toml",
                'mode = "adopt"\n[timers]\ngc_interval = 17\n[protected]\ncomm = ["isolated"]\n',
            )
            with (
                mock.patch.object(policy, "SYSTEM_CONFIG", system),
                mock.patch.dict(
                    os.environ,
                    {
                        "XDG_CONFIG_HOME": str(Path(root) / "config"),
                        "TAEMA_CONFIG": isolated,
                    },
                ),
            ):
                cfg = policy.load_config()
        self.assertEqual(cfg["mode"], "adopt")
        self.assertEqual(cfg["timers"]["gc_interval"], 17)
        self.assertEqual(cfg["protected"]["comm"], ["isolated"])
        self.assertEqual(cfg["_sources"], [isolated])
        self.assertEqual(cfg["_source_map"]["mode"], isolated)

    def test_new_sections_have_spec_defaults_and_writer_round_trips_tables(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "taema.toml"
            source.write_text('mode = "observe"\n', encoding="utf-8")
            cfg = policy.load_config(str(source))
        self.assertIsNone(cfg["learn"].get("authority"))
        self.assertEqual(
            policy.effective_authority(cfg),
            {"value": "learned", "source": "mode default for observe"},
        )
        self.assertEqual(cfg["learn"]["remember_argv"], False)
        self.assertFalse(cfg["learn"]["allow_self_authority"])
        self.assertEqual(cfg["mem"]["manage"], "soft")
        self.assertEqual(cfg["agent"]["window_backend"], "auto")
        self.assertEqual(cfg["profile"]["game"]["freeze"]["after"], 30)
        self.assertEqual(doctor._unknown_config(cfg), [])
        values = {
            "enabled": True,
            "labels": ["one", "two"],
            "profile": {"active": "game", "auto": {"on_battery": "battery"}},
            "limits": [{"name": "cpu", "weight": 50}],
        }
        self.assertEqual(tomllib.loads(management.dump_toml(values)), values)

    def test_learn_authority_defaults_by_mode_and_reports_its_source(self):
        with tempfile.TemporaryDirectory() as root:
            adopt = Path(root) / "adopt.toml"
            adopt.write_text('mode = "adopt"\n', encoding="utf-8")
            auto = Path(root) / "auto.toml"
            auto.write_text('mode = "auto"\n', encoding="utf-8")
            explicit = Path(root) / "explicit.toml"
            explicit.write_text(
                'mode = "adopt"\n[learn]\nauthority = "aggressive"\n',
                encoding="utf-8",
            )
            enforce = Path(root) / "enforce.toml"
            enforce.write_text(
                'mode = "enforce"\n[learn]\nauthority = "answered"\n',
                encoding="utf-8",
            )

            adopt_cfg = policy.load_config(str(adopt))
            auto_cfg = policy.load_config(str(auto))
            explicit_cfg = policy.load_config(str(explicit))
            enforce_cfg = policy.load_config(str(enforce))

        self.assertEqual(
            policy.effective_authority(adopt_cfg),
            {"value": "answered", "source": "mode default for adopt"},
        )
        self.assertEqual(
            policy.effective_authority(auto_cfg),
            {"value": "learned", "source": "mode default for auto"},
        )
        self.assertEqual(
            policy.effective_authority(explicit_cfg),
            {"value": "aggressive", "source": str(explicit)},
        )
        self.assertEqual(doctor._unknown_config(explicit_cfg), [])
        self.assertEqual(
            policy.effective_authority(enforce_cfg),
            {"value": "unit", "source": "enforce mode unit rules"},
        )

    def test_invalid_learn_authority_and_self_authority_types_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "taema.toml"
            for setting, message in (
                ('authority = "guess"', "learn.authority"),
                ('allow_self_authority = "false"', "allow_self_authority"),
            ):
                source.write_text("[learn]\n%s\n" % setting, encoding="utf-8")
                with self.subTest(setting=setting):
                    with self.assertRaisesRegex(ValueError, message):
                        policy.load_config(str(source))

    def test_malformed_unit_is_skipped_without_dropping_valid_units(self):
        with tempfile.TemporaryDirectory() as root:
            units_dir = Path(root, "units")
            units_dir.mkdir()
            Path(units_dir, "broken.toml").write_text("[unit\n", encoding="utf-8")
            Path(units_dir, "valid.toml").write_text(
                '[unit]\nname = "scope-valid"\n', encoding="utf-8"
            )
            config_file = Path(root, "config.toml")
            config_file.write_text(
                "[paths]\nunits_dir = %r\n" % str(units_dir), encoding="utf-8"
            )
            cfg = policy.load_config(str(config_file))
            units = policy.load_units(cfg)
        self.assertEqual([unit["unit"]["name"] for unit in units], ["scope-valid"])
        self.assertEqual(len(cfg["_unit_errors"]), 1)
        self.assertRegex(cfg["_unit_errors"][0], r"broken\.toml:\d+:\d+:")
        report = doctor.diagnose(cfg, units=units, system_root="/nonexistent")
        unit_check = next(
            item for item in report["checks"] if item["name"] == "unit files"
        )
        self.assertEqual(unit_check["status"], "warn")

    def test_unknown_config_keys_are_retained_for_doctor_warning(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "taema.toml"
            source.write_text(
                "[learn]\nmisspelled_option = true\n"
                "[profile.auto]\nunknown_switch = true\n"
                "[profile.focus.notify]\nmisspelled_setting = true\n",
                encoding="utf-8",
            )
            cfg = policy.load_config(str(source))
        unknown = doctor._unknown_config(cfg)
        self.assertIn("learn.misspelled_option", unknown)
        self.assertIn("profile.auto.unknown_switch", unknown)
        self.assertIn("profile.focus.notify.misspelled_setting", unknown)

    def test_malformed_config_types_have_locations_and_missing_override_fails(self):
        self.assertEqual(
            policy._toml_location(ValueError("Invalid value (at line 4, column 2)")),
            (4, 2),
        )
        self.assertEqual(
            policy._toml_location(ValueError("end of document"), "x = ["), (2, 1)
        )
        with tempfile.TemporaryDirectory() as root:
            cases = (
                ('protected = "bad"\n', "protected must be a table"),
                ('[protected]\ncomm = "bad"\n', "protected.comm must be an array"),
                (
                    "[protected]\nenv_prefix = []\n",
                    "protected.env_prefix must be a table",
                ),
            )
            for index, (content, message) in enumerate(cases):
                source = Path(root, "%d.toml" % index)
                source.write_text(content, encoding="utf-8")
                with (
                    self.subTest(content=content),
                    self.assertRaisesRegex(
                        ValueError, str(source) + r":1:1:.*" + message
                    ),
                ):
                    policy.load_config(str(source))
            missing = str(Path(root, "missing.toml"))
            with self.assertRaises(FileNotFoundError):
                policy.load_config(missing)
            self.assertEqual(policy._read(missing), {})

    def test_merge_keeps_unknown_protected_keys_and_legacy_learner_keys(self):
        merged = policy.merge(
            {"protected": {"comm": ["system"], "env_prefix": {"HOME": ["/a"]}}},
            {
                "protected": {
                    "comm": ["user"],
                    "env_prefix": {"HOME": ["/b"]},
                    "custom": True,
                },
                "learner": {"extra": "kept"},
            },
        )
        self.assertEqual(merged["protected"]["comm"], ["system", "user"])
        self.assertEqual(merged["protected"]["env_prefix"]["HOME"], ["/a", "/b"])
        self.assertTrue(merged["protected"]["custom"])
        self.assertEqual(merged["learner"]["extra"], "kept")

        malformed = policy.merge(
            {"protected": {"comm": ["system"], "env_prefix": {}}},
            {"protected": {"comm": "bad", "env_prefix": []}},
        )
        self.assertEqual(malformed["protected"]["comm"], "bad")
        self.assertEqual(malformed["protected"]["env_prefix"], [])

    def test_config_watch_fingerprint_and_unit_lookup_cover_missing_paths(self):
        with tempfile.TemporaryDirectory() as root:
            missing = str(Path(root, "missing-units"))
            cfg = {"paths": {"units_dir": missing}}
            self.assertEqual(policy.load_units(cfg), [])
            self.assertIn(missing, policy.config_watch_paths(cfg))
            fingerprint = policy.file_fingerprint([missing])
        self.assertEqual(fingerprint[0][1:], (None, None, None))
        units = [{"unit": {"name": "scope-a"}}]
        self.assertIs(policy.unit_for_scope(units, "scope-a"), units[0])
        self.assertIsNone(policy.unit_for_scope(units, "scope-b"))

    def test_unreadable_unit_is_skipped_with_a_reported_path(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "private.toml")
            source.write_text('[unit]\nname = "scope-private"\n', encoding="utf-8")
            cfg = {"paths": {"units_dir": root}}
            real_open = builtins.open

            def deny_unit(path, *args, **kwargs):
                if os.fspath(path) == str(source):
                    raise PermissionError("permission denied")
                return real_open(path, *args, **kwargs)

            with mock.patch("builtins.open", side_effect=deny_unit):
                units = policy.load_units(cfg)
        self.assertEqual(units, [])
        self.assertIn("private.toml: permission denied", cfg["_unit_errors"][0])

    def test_protected_process_rules_still_stop_at_kernel_threads(self):
        with (
            mock.patch.object(policy.inspect, "uid_of", return_value=os.getuid()),
            mock.patch.object(policy.inspect, "is_kernel_thread", return_value=True),
        ):
            self.assertEqual(
                policy.protected_reason(43210, {"protected": {}}), "kernel thread"
            )


class ManagedConfigCli(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_home = self.root / "config"
        self.system = self.root / "etc/taema.toml"
        self.system.parent.mkdir(parents=True)
        self.system.write_text(
            'mode = "observe"\n[timers]\nidle_grace = 10\n', encoding="utf-8"
        )
        self.user_dir = self.config_home / "taema"
        self.user_dir.mkdir(parents=True)
        self.hand_main = self.user_dir / "taema.toml"
        self.hand_main.write_text("[timers]\ngc_interval = 91\n", encoding="utf-8")
        self.hand_dropin = self.user_dir / "taema.d/20-hand.toml"
        self.hand_dropin.parent.mkdir()
        self.hand_dropin.write_text("[timers]\nadopt_interval = 92\n", encoding="utf-8")
        self.managed = self.user_dir / "taema.d/50-cli.toml"
        self.base_env = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.config_home)},
            clear=False,
        )
        self.base_env.start()
        self.system_patch = mock.patch.object(policy, "SYSTEM_CONFIG", str(self.system))
        self.system_patch.start()
        os.environ.pop("TAEMA_CONFIG", None)
        self.addCleanup(self.base_env.stop)
        self.addCleanup(self.system_patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def run_cli(self, *argv):
        output = io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(output),
            mock.patch.object(commands, "ask", return_value=None),
        ):
            result = commands.main(list(argv))
        return result, output.getvalue()

    def test_set_unset_show_and_diff_only_touch_managed_dropin(self):
        main_before = self.hand_main.read_bytes()
        hand_before = self.hand_dropin.read_bytes()
        result, _ = self.run_cli("config", "set", "timers.idle_grace", "45")
        self.assertEqual(result, 0)
        self.assertIn(
            "managed by taema", self.managed.read_text(encoding="utf-8").lower()
        )
        self.assertEqual(self.hand_main.read_bytes(), main_before)
        self.assertEqual(self.hand_dropin.read_bytes(), hand_before)
        self.assertEqual(policy.load_config()["timers"]["idle_grace"], 45)

        result, value = self.run_cli("config", "get", "timers.idle_grace")
        self.assertEqual(result, 0)
        self.assertEqual(value.strip(), "45")
        result, shown = self.run_cli("config", "show", "--sources")
        self.assertEqual(result, 0)
        self.assertIn(str(self.managed), shown)
        result, diff = self.run_cli("config", "diff")
        self.assertEqual(result, 0)
        self.assertIn("idle_grace", diff)

        result, _ = self.run_cli("config", "unset", "timers.idle_grace")
        self.assertEqual(result, 0)
        self.assertEqual(policy.load_config()["timers"]["idle_grace"], 10)
        self.assertEqual(self.hand_main.read_bytes(), main_before)
        self.assertEqual(self.hand_dropin.read_bytes(), hand_before)

    def test_invalid_editor_save_restores_previous_managed_file(self):
        self.managed.write_text(
            "# managed by taema\n[timers]\nidle_grace = 45\n", encoding="utf-8"
        )
        before = self.managed.read_bytes()
        editor = self.root / "bad-editor"
        editor.write_text(
            "#!/usr/bin/env python3\nimport pathlib, sys\npathlib.Path(sys.argv[1]).write_text('mode = [\\n')\n",
            encoding="utf-8",
        )
        editor.chmod(0o755)
        with mock.patch.dict(os.environ, {"EDITOR": str(editor)}):
            result, output = self.run_cli("config", "edit")
        self.assertNotEqual(result, 0)
        self.assertIn(str(self.managed) + ":2:1:", output)
        self.assertEqual(self.managed.read_bytes(), before)

    def test_config_and_reload_commands_are_registered(self):
        parser = framework._parser()
        self.assertEqual(
            parser.parse_args(["config", "show", "--sources"])._command, "config show"
        )
        self.assertEqual(parser.parse_args(["reload"])._command, "reload")
        output = io.StringIO()
        with (
            redirect_stdout(output),
            mock.patch.object(commands, "ask", return_value={"reloaded": True}) as ask,
        ):
            self.assertEqual(commands.main(["reload"]), 0)
        self.assertEqual(
            ask.call_args.args[1],
            {"cmd": "reload", "reason": "taema reload command"},
        )
        self.assertIn("reloaded", output.getvalue())

    def test_invalid_cli_value_restores_previous_dropin(self):
        self.managed.write_text(
            '# managed by taema\nmode = "observe"\n', encoding="utf-8"
        )
        before = self.managed.read_bytes()
        result, error = self.run_cli("config", "set", "mode", '"invalid"')
        self.assertNotEqual(result, 0)
        self.assertIn(str(self.managed) + ":1:1:", error)
        self.assertEqual(self.managed.read_bytes(), before)

    def test_status_displays_daemon_configuration_error(self):
        config_file = self.root / "status.toml"
        config_file.write_text(
            "[paths]\nstate_dir = %r\n" % str(self.root / "state"),
            encoding="utf-8",
        )
        cfg = policy.load_config(str(config_file))
        reply = {
            "mode": "observe",
            "feedback_invalid": 0,
            "hold": "",
            "hold_state": {
                "global": False,
                "scopes": [],
                "snooze_until": None,
                "snooze_remaining_s": 0,
                "reason": "",
            },
            "config_error": "/tmp/taema.toml:3:4: invalid value",
            "config": [str(config_file)],
        }
        output = io.StringIO()
        args = type("Args", (), {"json": False, "jsonl": False, "quiet": False})()
        with (
            redirect_stdout(output),
            mock.patch.object(commands, "_load_status", return_value=(cfg, None)),
            mock.patch.object(commands, "_status_store", return_value=None),
            mock.patch.object(commands, "ask", return_value=reply),
            mock.patch.object(commands.cgroup, "base", return_value="/missing/cgroup"),
        ):
            result = commands.cmd_status(args)
        self.assertEqual(result, 0)
        self.assertIn(
            "config error: /tmp/taema.toml:3:4: invalid value", output.getvalue()
        )


class DaemonConfigReload(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_file = self.root / "taema.toml"
        self.config_file.write_text(
            'mode = "observe"\n[paths]\nstate_dir = %r\nunits_dir = %r\n'
            % (str(self.root / "state"), str(self.root / "units")),
            encoding="utf-8",
        )
        self.units = self.root / "units"
        self.units.mkdir()
        self.env = mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(self.config_file)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.temporary.cleanup)
        self.daemon = service.Daemon(policy.load_config())
        self.daemon.last = {"adopt": time.time(), "gc": time.time()}

    def change(self, content):
        self.config_file.write_text(content, encoding="utf-8")
        future = time.time() + 2
        os.utime(self.config_file, (future, future))

    def test_reload_command_sighup_and_mtime_apply_valid_config(self):
        self.change(
            'mode = "adopt"\n[paths]\nstate_dir = %r\nunits_dir = %r\n'
            % (str(self.root / "state"), str(self.units))
        )
        result = self.daemon.handle({"cmd": "reload"})
        self.assertTrue(result["reloaded"])
        self.assertEqual(self.daemon.mode, "adopt")

        self.change(
            'mode = "enforce"\n[paths]\nstate_dir = %r\nunits_dir = %r\n'
            % (str(self.root / "state"), str(self.units))
        )
        self.daemon._on_signal(signal.SIGHUP, None)
        self.assertTrue(self.daemon.reload_requested)
        with (
            mock.patch.object(self.daemon, "check_socket"),
            mock.patch.object(self.daemon, "thaw_held_scopes"),
            mock.patch.object(self.daemon, "adopt_pass"),
            mock.patch.object(self.daemon, "gc_pass"),
        ):
            self.daemon.tick()
        self.assertEqual(self.daemon.mode, "enforce")

        self.change(
            'mode = "auto"\n[paths]\nstate_dir = %r\nunits_dir = %r\n'
            % (str(self.root / "state"), str(self.units))
        )
        with (
            mock.patch.object(self.daemon, "check_socket"),
            mock.patch.object(self.daemon, "thaw_held_scopes"),
            mock.patch.object(self.daemon, "adopt_pass"),
            mock.patch.object(self.daemon, "gc_pass"),
        ):
            self.daemon.tick()
        self.assertEqual(self.daemon.mode, "auto")

        unit = self.units / "managed.toml"
        unit.write_text('[unit]\nname = "scope-loaded"\n', encoding="utf-8")
        os.utime(unit, (time.time() + 2, time.time() + 2))
        self.daemon.poll_config_reload()
        self.assertEqual(self.daemon.units[0]["unit"]["name"], "scope-loaded")

    def test_invalid_change_keeps_last_good_and_reports_file_location(self):
        self.change("mode = [")
        self.daemon.handle({"cmd": "reload"})
        self.assertEqual(self.daemon.mode, "observe")
        status = self.daemon.handle({"cmd": "status"})
        # TOML reports this unterminated array at EOF, on line 2 after the final newline.
        self.assertIn(str(self.config_file) + ":2:1:", status["config_error"])
        report = self.daemon.handle({"cmd": "doctor"})
        config = next(
            item for item in report["checks"] if item["name"] == "configuration"
        )
        self.assertIn(str(self.config_file) + ":2:1:", config["message"])

    def test_state_directory_change_switches_the_live_store(self):
        old_store = self.daemon.store
        old_store.data["held"] = True
        old_store.data["held_scopes"] = ["scope-browser"]
        old_store.data["snooze_until"] = time.time() + 60
        old_store.dirty = True
        old_store.save()
        new_state = self.root / "new-state"
        self.change(
            'mode = "adopt"\n[paths]\nstate_dir = %r\nunits_dir = %r\n'
            % (str(new_state), str(self.units))
        )
        with mock.patch.object(self.daemon, "restore_runtime_hold") as restore_hold:
            result = self.daemon.handle({"cmd": "reload"})
        self.assertTrue(result["reloaded"])
        self.assertIsNot(self.daemon.store, old_store)
        self.assertEqual(self.daemon.store.dir, str(new_state))
        self.assertEqual(self.daemon.mode, "adopt")
        holds = self.daemon.store.hold_status(
            include_pending=False, include_runtime=False
        )
        self.assertTrue(holds["global"])
        self.assertEqual(holds["scopes"], ["scope-browser"])
        self.assertIsNotNone(holds["snooze_until"])
        restore_hold.assert_called_once_with()


class ConfigManagementEdges(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_home = self.root / "config"
        self.config_home.mkdir()
        self.system = self.root / "system.toml"
        self.system.write_text('mode = "observe"\n', encoding="utf-8")
        self.env = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.config_home)},
            clear=False,
        )
        self.env.start()
        os.environ.pop("TAEMA_CONFIG", None)
        self.system_patch = mock.patch.object(policy, "SYSTEM_CONFIG", str(self.system))
        self.system_patch.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.system_patch.stop)

    def editor(self, content, status=0):
        path = self.root / "editor.py"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\nimport sys\n"
            "Path(sys.argv[1]).write_text(%r, encoding='utf-8')\n"
            "sys.exit(%d)\n" % (content, status),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return str(path)

    def test_invalid_inputs_missing_get_and_unset_are_reported(self):
        with self.assertRaises(ValueError):
            management.parse_key("bad key")
        with self.assertRaises(ValueError):
            management.parse_value("not valid TOML")
        with self.assertRaises(ValueError):
            management.parse_value(None)
        with self.assertRaises(KeyError):
            management.get_value("missing.value")
        with self.assertRaises(ValueError):
            management._set({"a": 1}, ["a", "child"], 2)
        data = {"timers": {"idle_grace": 5}}
        management._unset(data, ["absent", "value"])
        management._unset(data, ["timers", "absent"])
        self.assertEqual(data, {"timers": {"idle_grace": 5}})

    def test_writer_rejects_values_it_cannot_represent(self):
        for value in (float("nan"), object(), {"bad key": 1}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                management.format_value(value)
        with self.assertRaises(ValueError):
            management.dump_toml({"bad key": 1})
        self.assertEqual(
            tomllib.loads(
                "value = " + management.format_value(datetime.date(2026, 10, 20))
            )["value"].isoformat(),
            "2026-10-20",
        )

    def test_edit_without_editor_and_nonzero_editor_restore_or_remove_file(self):
        with mock.patch.dict(os.environ, {"EDITOR": "", "VISUAL": ""}):
            with self.assertRaisesRegex(ValueError, "set EDITOR"):
                management.edit_managed()

        with mock.patch.dict(
            os.environ, {"EDITOR": self.editor("mode = ["), "VISUAL": ""}
        ):
            with self.assertRaises(ValueError):
                management.edit_managed()
        self.assertFalse(Path(management.managed_path()).exists())

        management.write_managed({"mode": "observe"})
        before = Path(management.managed_path()).read_bytes()
        with mock.patch.dict(
            os.environ, {"EDITOR": self.editor("", status=2), "VISUAL": ""}
        ):
            with self.assertRaisesRegex(ValueError, "editor exited"):
                management.edit_managed()
        self.assertEqual(Path(management.managed_path()).read_bytes(), before)

    def test_successful_edit_adds_header_and_atomic_write_cleans_temporary(self):
        with mock.patch.dict(
            os.environ,
            {"EDITOR": self.editor('mode = "adopt"\n'), "VISUAL": ""},
        ):
            management.edit_managed()
        path = Path(management.managed_path())
        self.assertTrue(
            path.read_text(encoding="utf-8").startswith("# managed by taema")
        )
        self.assertEqual(policy.load_config()["mode"], "adopt")
        with mock.patch.object(
            management.os, "replace", side_effect=OSError("rename failed")
        ):
            with self.assertRaisesRegex(OSError, "rename failed"):
                management._write_bytes(str(path), b"broken")
        self.assertEqual(list(path.parent.glob(".50-cli.*")), [])

    def test_set_on_new_managed_file_rolls_back_invalid_value_and_unset_creates_clean_file(
        self,
    ):
        with self.assertRaises(ValueError):
            management.set_value("mode", '"invalid"')
        self.assertFalse(Path(management.managed_path()).exists())
        management.unset_value("timers.no_such_key")
        self.assertEqual(management.read_managed(), {})


if __name__ == "__main__":
    unittest.main()
