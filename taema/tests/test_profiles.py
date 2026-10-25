"""Mode switches and configuration profile behavior."""

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema import doctor
from taema.cli import commands, framework
from taema.config import policy
from taema.daemon import service
from taema.model import authorization


class ProfileConfigurationTests(unittest.TestCase):
    def load_profile(self, root, name, extra=""):
        source = Path(root, "taema.toml")
        source.write_text(
            '[profile]\nactive = "%s"\n%s' % (name, extra), encoding="utf-8"
        )
        return policy.load_config(str(source))

    def test_builtin_profile_overlays_match_documented_effects(self):
        with tempfile.TemporaryDirectory() as root:
            focus = self.load_profile(root, "focus")
            self.assertTrue(focus["qos"]["focus_boost"])

            battery = self.load_profile(root, "battery")
            self.assertEqual(battery["timers"]["adopt_interval"], 60)
            self.assertEqual(battery["timers"]["gc_interval"], 300)
            self.assertEqual(battery["freeze"]["after"], 30)

            game = self.load_profile(root, "game")
            self.assertIn("gamescope", game["protected"]["comm"])
            self.assertIn("steam", game["protected"]["comm"])
            self.assertFalse(game["notify"]["enabled"])
            self.assertEqual(game["timers"]["adopt_interval"], 5)

            quiet = self.load_profile(root, "quiet")
            self.assertTrue(quiet["_profile_suppress_stops"])
            self.assertFalse(quiet["notify"]["enabled"])
            self.assertEqual(quiet["_source_map"]["notify.enabled"], "profile quiet")

            server = self.load_profile(root, "server")
            self.assertFalse(server["agent"]["enabled"])
            self.assertFalse(server["notify"]["enabled"])
            self.assertFalse(server["experimental"]["window_close"])
            self.assertFalse(server["experimental"]["launch_wrap"])

            default = self.load_profile(root, "default")
            self.assertFalse(default["_profile_suppress_stops"])
            for cfg in (focus, battery, game, quiet, server, default):
                self.assertEqual(doctor._unknown_config(cfg), [])

    def test_user_defined_profile_is_validated_and_applied_after_base_config(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            source.write_text(
                'mode = "adopt"\n'
                '[profile]\nactive = "work"\n'
                "[profile.work.notify]\nenabled = false\n"
                '[profile.work.mem]\nbudget = "3G"\n',
                encoding="utf-8",
            )
            cfg = policy.load_config(str(source))
        self.assertEqual(cfg["mode"], "adopt")
        self.assertEqual(cfg["mem"]["budget"], "3G")
        self.assertFalse(cfg["notify"]["enabled"])
        self.assertEqual(cfg["_profile_name"], "work")
        self.assertEqual(doctor._unknown_config(cfg), [])

    def test_runtime_mode_override_has_precedence_over_profile_overlay(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            source.write_text(
                '[profile]\nactive = "work"\nruntime_mode = "auto"\n'
                '[profile.work]\nmode = "observe"\n',
                encoding="utf-8",
            )
            cfg = policy.load_config(str(source))
        self.assertEqual(cfg["mode"], "auto")
        self.assertEqual(cfg["_profile_name"], "work")

    def test_unknown_active_profile_has_source_location(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            source.write_text('[profile]\nactive = "missing"\n', encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, str(source) + r":1:1: profile.active names no profile"
            ):
                policy.load_config(str(source))


class ModeProfileCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_home = self.root / "config"
        self.user_dir = self.config_home / "taema"
        self.user_dir.mkdir(parents=True)
        self.handwritten = self.user_dir / "taema.toml"
        self.handwritten.write_text('mode = "observe"\n', encoding="utf-8")
        self.system = self.root / "etc/taema.toml"
        self.system.parent.mkdir(parents=True)
        self.system.write_text('mode = "observe"\n', encoding="utf-8")
        self.environment = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.config_home)},
            clear=False,
        )
        self.environment.start()
        os.environ.pop("TAEMA_CONFIG", None)
        self.system_patch = mock.patch.object(policy, "SYSTEM_CONFIG", str(self.system))
        self.system_patch.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.system_patch.stop)

    def run_cli(self, *argv):
        output = io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(output),
            mock.patch.object(commands, "ask", return_value=None) as ask_mock,
        ):
            result = commands.main(list(argv))
        return result, output.getvalue(), ask_mock

    def test_mode_and_profile_commands_write_managed_layer_and_reload(self):
        before = self.handwritten.read_bytes()
        result, output, asked = self.run_cli("mode", "auto")
        self.assertEqual(result, 0)
        self.assertIn("mode: observe -> auto", output)
        self.assertIn("capability matrix changes", output)
        self.assertEqual(self.handwritten.read_bytes(), before)
        managed = self.user_dir / "taema.d/50-cli.toml"
        self.assertEqual(policy.load_config()["mode"], "auto")
        self.assertEqual(asked.call_args.args[1]["cmd"], "reload")
        self.assertEqual(asked.call_args.args[1]["reason"], "taema mode command")

        result, output, asked = self.run_cli("profile", "quiet")
        self.assertEqual(result, 0)
        self.assertIn("quiet suppresses automatic stops and notifications", output)
        cfg = policy.load_config()
        self.assertEqual(cfg["_profile_name"], "quiet")
        self.assertTrue(cfg["_profile_suppress_stops"])
        self.assertFalse(cfg["notify"]["enabled"])
        self.assertEqual(asked.call_args.args[1]["cmd"], "reload")
        self.assertEqual(
            asked.call_args.args[1]["reason"], "selected manually with taema profile"
        )
        self.assertIn("managed by taema", managed.read_text(encoding="utf-8"))
        self.assertEqual(self.handwritten.read_bytes(), before)

        result, output, _asked = self.run_cli("profile", "auto")
        self.assertEqual(result, 0)
        self.assertIn("automatic profile selection requested", output)
        self.assertEqual(policy.load_config()["_profile_name"], "auto")

    def test_profile_command_accepts_user_profiles_and_reports_unknown_names(self):
        self.handwritten.write_text(
            "[profile.work.notify]\nenabled = false\n", encoding="utf-8"
        )
        result, output, _asked = self.run_cli("profile", "work")
        self.assertEqual(result, 0)
        self.assertEqual(policy.load_config()["_profile_name"], "work")
        result, output, _asked = self.run_cli("profile", "missing")
        self.assertEqual(result, 1)
        self.assertIn("unknown profile", output)

    def test_mode_and_profile_commands_are_registered(self):
        parser = framework._parser()
        self.assertEqual(parser.parse_args(["mode", "adopt"])._command, "mode")
        self.assertEqual(parser.parse_args(["profile", "quiet"])._command, "profile")


class AutoProfileSelectionTests(unittest.TestCase):
    def config(self, auto, active="auto"):
        cfg = {"profile": {"active": active, "auto": auto}}
        for name in ("default", "battery", "game", "quiet"):
            cfg["profile"][name] = {}
        return cfg

    def test_manual_active_disables_selection(self):
        cfg = self.config({"on_battery": "battery"}, active="quiet")
        self.assertIsNone(
            policy.select_auto_profile(cfg, on_battery=True, comms=set(), now=0)
        )

    def test_battery_selects_profile(self):
        cfg = self.config({"on_battery": "battery"})
        name, reason = policy.select_auto_profile(
            cfg, on_battery=True, comms=set(), now=0
        )
        self.assertEqual(name, "battery")
        self.assertIn("battery", reason)

    def test_running_match_wins_over_battery(self):
        cfg = self.config(
            {"on_battery": "battery", "when_running": {"gamescope": "game"}}
        )
        name, reason = policy.select_auto_profile(
            cfg, on_battery=True, comms={"gamescope"}, now=0
        )
        self.assertEqual(name, "game")
        self.assertIn("gamescope", reason)

    def test_time_window_matches_overnight(self):
        cfg = self.config(
            {
                "time": [
                    {"profile": "quiet", "start": "22:00", "end": "07:00"},
                ]
            }
        )
        import time as _time

        night = _time.mktime((2026, 9, 15, 23, 30, 0, 0, 0, -1))
        name, _reason = policy.select_auto_profile(
            cfg, on_battery=False, comms=set(), now=night
        )
        self.assertEqual(name, "quiet")
        noon = _time.mktime((2026, 9, 15, 12, 0, 0, 0, 0, -1))
        name, _reason = policy.select_auto_profile(
            cfg, on_battery=False, comms=set(), now=noon
        )
        self.assertEqual(name, "default")

    def test_time_window_respects_days(self):
        cfg = self.config(
            {
                "time": [
                    {
                        "profile": "quiet",
                        "start": "00:00",
                        "end": "23:59",
                        "days": ["sat", "sun"],
                    },
                ]
            }
        )
        import time as _time

        saturday = _time.mktime((2026, 9, 19, 12, 0, 0, 0, 0, -1))
        name, _reason = policy.select_auto_profile(
            cfg, on_battery=False, comms=set(), now=saturday
        )
        self.assertEqual(name, "quiet")
        monday = _time.mktime((2026, 9, 21, 12, 0, 0, 0, 0, -1))
        name, _reason = policy.select_auto_profile(
            cfg, on_battery=False, comms=set(), now=monday
        )
        self.assertEqual(name, "default")

    def test_no_match_falls_back_to_default(self):
        cfg = self.config({})
        name, _reason = policy.select_auto_profile(
            cfg, on_battery=False, comms=set(), now=0
        )
        self.assertEqual(name, "default")

    def test_power_supply_tree(self):
        with tempfile.TemporaryDirectory() as root:
            ac = Path(root, "AC0")
            ac.mkdir()
            (ac / "type").write_text("Mains\n")
            (ac / "online").write_text("1\n")
            self.assertFalse(policy.read_power_supply(root))
            (ac / "online").write_text("0\n")
            self.assertTrue(policy.read_power_supply(root))
        with tempfile.TemporaryDirectory() as root:
            bat = Path(root, "BAT0")
            bat.mkdir()
            (bat / "type").write_text("Battery\n")
            (bat / "status").write_text("Discharging\n")
            self.assertTrue(policy.read_power_supply(root))
            (bat / "status").write_text("Charging\n")
            self.assertFalse(policy.read_power_supply(root))
        self.assertFalse(policy.read_power_supply("/nonexistent-power-tree"))


class AutoProfileConfigTests(unittest.TestCase):
    def test_with_profile_applies_overlay_and_reason(self):
        cfg = policy.load_config()
        overlaid = policy.with_profile(cfg, "quiet", "automatic test")
        self.assertEqual(overlaid["_profile_name"], "quiet")
        self.assertEqual(overlaid["_profile_reason"], "automatic test")
        self.assertTrue(overlaid["_profile_suppress_stops"])
        self.assertFalse(overlaid["notify"]["enabled"])
        self.assertEqual(cfg["_profile_name"], "auto")

    def test_rejects_unknown_auto_profile_names(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            source.write_text('[profile.auto]\non_battery = "nope"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                with self.assertRaises(ValueError):
                    policy.load_config()

    def test_rejects_bad_time_window(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            source.write_text(
                '[[profile.auto.time]]\nprofile = "quiet"\nstart = "25:00"\nend = "07:00"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                with self.assertRaises(ValueError):
                    policy.load_config()

    def test_power_supply_path_defaults(self):
        cfg = policy.load_config()
        self.assertEqual(cfg["paths"]["power_supply"], "/sys/class/power_supply")


class ProfileDaemonTests(unittest.TestCase):
    def test_reload_logs_changes_and_status_reports_active_profile_reason(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "taema.toml")
            state = Path(root, "state")
            units = Path(root, "units")
            units.mkdir()
            source.write_text(
                "[paths]\nstate_dir = %s\nunits_dir = %s\n"
                % (json.dumps(str(state)), json.dumps(str(units))),
                encoding="utf-8",
            )
            env = mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)})
            with env:
                daemon = service.Daemon(policy.load_config())
                source.write_text(
                    'mode = "adopt"\n'
                    "[paths]\nstate_dir = %s\nunits_dir = %s\n"
                    '[profile]\nactive = "quiet"\n'
                    % (json.dumps(str(state)), json.dumps(str(units))),
                    encoding="utf-8",
                )
                result = daemon.handle(
                    {"cmd": "reload", "reason": "selected manually with taema profile"}
                )
                self.assertTrue(result["reloaded"])

                status = daemon.handle({"cmd": "status"})
                self.assertEqual(status["mode"], "adopt")
                self.assertEqual(status["profile"], "quiet")
                self.assertEqual(
                    status["profile_reason"], "selected manually with taema profile"
                )
                automatic_stop = daemon.authorize(authorization.GC_STOP)
                manual_stop = daemon.authorize(authorization.MANUAL_STOP)
                self.assertEqual(automatic_stop.verdict, authorization.KEEP)
                self.assertIn("quiet profile", automatic_stop.reason)
                self.assertEqual(manual_stop.verdict, authorization.ACT)
                self.assertEqual(
                    daemon.handle({"cmd": "reload", "reason": "x" * 257}),
                    {"error": "bad request"},
                )

                with daemon.store.db.connection() as connection:
                    rows = connection.execute(
                        "SELECT event, data FROM events WHERE event IN (?, ?)",
                        ("mode_changed", "profile_changed"),
                    ).fetchall()
                logged = {row["event"]: json.loads(row["data"]) for row in rows}
                self.assertEqual(logged["mode_changed"]["old"], "observe")
                self.assertEqual(logged["mode_changed"]["new"], "adopt")
                self.assertEqual(
                    logged["mode_changed"]["reason"],
                    "selected manually with taema profile",
                )
                self.assertEqual(logged["profile_changed"]["old"], "auto")
                self.assertEqual(logged["profile_changed"]["new"], "quiet")
            daemon.sel.close()

    def make_daemon(self, root, extra=""):
        source = Path(root, "taema.toml")
        state = Path(root, "state")
        units = Path(root, "units")
        power = Path(root, "power")
        units.mkdir()
        power.mkdir()
        source.write_text(
            "[paths]\nstate_dir = %s\nunits_dir = %s\npower_supply = %s\n%s"
            % (
                json.dumps(str(state)),
                json.dumps(str(units)),
                json.dumps(str(power)),
                extra,
            ),
            encoding="utf-8",
        )
        return source, power

    def test_auto_pass_switches_on_battery(self):
        with tempfile.TemporaryDirectory() as root:
            source, power = self.make_daemon(root)
            ac = power / "AC0"
            ac.mkdir()
            (ac / "type").write_text("Mains\n")
            (ac / "online").write_text("0\n")
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                daemon = service.Daemon(policy.load_config())
                try:
                    with mock.patch.object(
                        service.Daemon, "_running_comms", return_value=set()
                    ):
                        self.assertEqual(daemon.auto_profile_pass(), "battery")
                    status = daemon.handle({"cmd": "status"})
                    self.assertEqual(status["profile"], "battery")
                    self.assertIn("battery", status["profile_reason"])
                    daemon.store.save()
                    with daemon.store.db.connection() as connection:
                        rows = connection.execute(
                            "SELECT data FROM events WHERE event = 'profile_changed'"
                        ).fetchall()
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(json.loads(rows[0][0])["new"], "battery")
                finally:
                    daemon.sel.close()

    def test_auto_pass_matches_running_process(self):
        with tempfile.TemporaryDirectory() as root:
            source, _power = self.make_daemon(root)
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                daemon = service.Daemon(policy.load_config())
                try:
                    with mock.patch.object(
                        service.Daemon,
                        "_running_comms",
                        return_value={"gamescope"},
                    ):
                        self.assertEqual(daemon.auto_profile_pass(), "game")
                    self.assertEqual(
                        daemon.handle({"cmd": "status"})["profile"], "game"
                    )
                finally:
                    daemon.sel.close()

    def test_manual_profile_blocks_auto_pass(self):
        with tempfile.TemporaryDirectory() as root:
            source, power = self.make_daemon(root, '[profile]\nactive = "quiet"\n')
            ac = power / "AC0"
            ac.mkdir()
            (ac / "type").write_text("Mains\n")
            (ac / "online").write_text("0\n")
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                daemon = service.Daemon(policy.load_config())
                try:
                    self.assertIsNone(daemon.auto_profile_pass())
                    self.assertEqual(
                        daemon.handle({"cmd": "status"})["profile"], "quiet"
                    )
                finally:
                    daemon.sel.close()

    def test_auto_pass_does_not_reload_when_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            source, _power = self.make_daemon(root)
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(source)}):
                daemon = service.Daemon(policy.load_config())
                try:
                    with mock.patch.object(
                        service.Daemon, "_running_comms", return_value=set()
                    ):
                        first = daemon.auto_profile_pass()
                        daemon.store.save()
                        with daemon.store.db.connection() as connection:
                            before = connection.execute(
                                "SELECT COUNT(*) FROM events WHERE event = ?",
                                ("profile_changed",),
                            ).fetchone()[0]
                        second = daemon.auto_profile_pass()
                    self.assertEqual((first, second), ("default", "default"))
                    with daemon.store.db.connection() as connection:
                        after = connection.execute(
                            "SELECT COUNT(*) FROM events WHERE event = ?",
                            ("profile_changed",),
                        ).fetchone()[0]
                    self.assertEqual(before, after)
                finally:
                    daemon.sel.close()


if __name__ == "__main__":
    unittest.main()
