"""Desktop entry wrapping tests (issue #63).

`taema desktop wrap` writes a user-level override whose Exec runs the
original command under `taema launch`; the override marker records the
source hash so doctor can warn when a package update drifts behind it.
"""

import hashlib
import os
import unittest
from unittest import mock

ENTRY = """[Desktop Entry]
Name=Example
Exec=example --foo %U
Terminal=false
Type=Application
"""


class DesktopWrapTest(unittest.TestCase):
    def _dirs(self):
        import tempfile

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        data = os.path.join(temp.name, "data")
        system = os.path.join(temp.name, "sys")
        os.makedirs(os.path.join(data, "applications"))
        os.makedirs(os.path.join(system, "applications"))
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY)
        env = mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": data, "XDG_DATA_DIRS": system},
        )
        env.start()
        self.addCleanup(env.stop)
        return data, system

    def test_wrap_writes_override_with_launch_exec(self):
        from taema import desktop

        data, system = self._dirs()
        record = desktop.wrap("example.desktop")
        override = os.path.join(data, "applications", "example.desktop")
        self.assertEqual(record["file"], override)
        self.assertEqual(
            record["source"],
            os.path.join(system, "applications", "example.desktop"),
        )
        with open(override) as fh:
            body = fh.read()
        self.assertIn("Exec=taema launch --app example -- example --foo %U", body)
        self.assertIn("# taema-wrap source=", body)
        self.assertIn("sha256=", body)
        self.assertEqual(record["app"], "example")
        self.assertEqual(record["sha256"], hashlib.sha256(ENTRY.encode()).hexdigest())
        # the system entry is untouched
        with open(os.path.join(system, "applications", "example.desktop")) as fh:
            self.assertEqual(fh.read(), ENTRY)

    def test_wrap_is_idempotent(self):
        from taema import desktop

        self._dirs()
        first = desktop.wrap("example.desktop")
        second = desktop.wrap("example.desktop")
        self.assertFalse(first["updated"])
        self.assertFalse(second["updated"])

    def test_wrap_rewraps_after_source_change(self):
        from taema import desktop

        _data, system = self._dirs()
        desktop.wrap("example.desktop")
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY.replace("example --foo", "example --bar"))
        record = desktop.wrap("example.desktop")
        self.assertTrue(record["updated"])
        self.assertEqual(desktop.drifted(), [])

    def test_wrap_refuses_foreign_override(self):
        from taema import desktop

        data, _system = self._dirs()
        with open(os.path.join(data, "applications", "example.desktop"), "w") as fh:
            fh.write("[Desktop Entry]\nName=Mine\nExec=mine\n")
        with self.assertRaises(desktop.DesktopError):
            desktop.wrap("example.desktop")

    def test_wrap_rejects_bad_names_and_dbus_entries(self):
        from taema import desktop

        _data, system = self._dirs()
        for bad in ("../evil.desktop", "nope.desktop", "", "a/b.desktop"):
            with self.assertRaises(desktop.DesktopError, msg=bad):
                desktop.wrap(bad)
        with open(os.path.join(system, "applications", "dbus.desktop"), "w") as fh:
            fh.write(
                "[Desktop Entry]\nName=D\nExec=d\nDBusActivatable=true\n"
                "Type=Application\n"
            )
        with self.assertRaises(desktop.DesktopError):
            desktop.wrap("dbus.desktop")

    def test_app_name_is_sanitized_for_launch(self):
        from taema import desktop

        _data, system = self._dirs()
        with open(os.path.join(system, "applications", "Cool App.desktop"), "w") as fh:
            fh.write(ENTRY)
        record = desktop.wrap("Cool App.desktop")
        self.assertEqual(record["app"], "cool-app")

    def test_unwrap_removes_only_ours(self):
        from taema import desktop

        data, _system = self._dirs()
        desktop.wrap("example.desktop")
        record = desktop.unwrap("example")
        self.assertTrue(record["removed"])
        self.assertFalse(
            os.path.exists(os.path.join(data, "applications", "example.desktop"))
        )
        with open(os.path.join(data, "applications", "other.desktop"), "w") as fh:
            fh.write("[Desktop Entry]\nName=O\nExec=o\n")
        with self.assertRaises(desktop.DesktopError):
            desktop.unwrap("other.desktop")
        self.assertTrue(
            os.path.exists(os.path.join(data, "applications", "other.desktop"))
        )

    def test_unwrap_all_and_list(self):
        from taema import desktop

        _data, system = self._dirs()
        with open(os.path.join(system, "applications", "two.desktop"), "w") as fh:
            fh.write(ENTRY)
        desktop.wrap("example.desktop")
        desktop.wrap("two.desktop")
        listed = desktop.list_wraps()
        self.assertEqual(sorted(item["app"] for item in listed), ["example", "two"])
        removed = desktop.unwrap_all()
        self.assertEqual(len(removed), 2)
        self.assertEqual(desktop.list_wraps(), [])

    def test_drift_detects_changed_source(self):
        from taema import desktop

        _data, system = self._dirs()
        desktop.wrap("example.desktop")
        self.assertEqual(desktop.drifted(), [])
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY.replace("Terminal=false", "Terminal=true"))
        drifted = desktop.drifted()
        self.assertEqual(len(drifted), 1)
        self.assertEqual(drifted[0]["app"], "example")


class DesktopCommandTest(unittest.TestCase):
    def _dirs(self, launch_wrap=True):
        import tempfile

        from tests.test_phase0 import make_cfg

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        data = os.path.join(temp.name, "data")
        system = os.path.join(temp.name, "sys")
        os.makedirs(os.path.join(data, "applications"))
        os.makedirs(os.path.join(system, "applications"))
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY)
        env = mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": data, "XDG_DATA_DIRS": system},
        )
        env.start()
        self.addCleanup(env.stop)
        cfg = make_cfg(temp.name)
        cfg["experimental"] = {"launch_wrap": launch_wrap}
        return data, system, cfg

    def test_registry_names_desktop_children(self):
        import taema.cli.commands as cli
        from taema.cli import registry

        entries = [entry for entry in registry.COMMANDS if entry["name"] == "desktop"]
        self.assertEqual(len(entries), 1)
        children = {child["name"]: child for child in entries[0]["children"]}
        self.assertEqual(
            {name: child["handler"] for name, child in children.items()},
            {
                "wrap": "cmd_desktop_wrap",
                "unwrap": "cmd_desktop_unwrap",
                "list": "cmd_desktop_list",
            },
        )
        for handler in (
            "cmd_desktop",
            "cmd_desktop_wrap",
            "cmd_desktop_unwrap",
            "cmd_desktop_list",
        ):
            self.assertTrue(callable(getattr(cli, handler, None)), handler)

    def test_wrap_round_trip(self):
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace

        import taema.cli.commands as cli

        data, _system, cfg = self._dirs()
        override = os.path.join(data, "applications", "example.desktop")
        with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_desktop_wrap(SimpleNamespace(name="example.desktop"))
            self.assertEqual(rc, 0)
            self.assertIn("wrapped", out.getvalue())
            with open(override) as fh:
                self.assertIn("taema launch --app example --", fh.read())
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_desktop_list(SimpleNamespace())
            self.assertEqual(rc, 0)
            self.assertIn("example", out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_desktop_unwrap(
                    SimpleNamespace(name="example.desktop", all=False)
                )
            self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(override))

    def test_wrap_gated_behind_launch_wrap(self):
        from types import SimpleNamespace

        import taema.cli.commands as cli

        data, _system, cfg = self._dirs(launch_wrap=False)
        with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
            rc = cli.cmd_desktop_wrap(SimpleNamespace(name="example.desktop"))
        self.assertNotEqual(rc, 0)
        self.assertFalse(
            os.path.exists(os.path.join(data, "applications", "example.desktop"))
        )

    def test_unwrap_all(self):
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace

        import taema.cli.commands as cli
        from taema import desktop

        data, system, cfg = self._dirs()
        with open(os.path.join(system, "applications", "two.desktop"), "w") as fh:
            fh.write(ENTRY)
        desktop.wrap("example.desktop")
        desktop.wrap("two.desktop")
        with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_desktop_unwrap(SimpleNamespace(name=None, all=True))
            self.assertEqual(rc, 0)
            self.assertIn("2", out.getvalue())
        self.assertEqual(os.listdir(os.path.join(data, "applications")), [])

    def test_unwrap_needs_name_or_all(self):
        from types import SimpleNamespace

        import taema.cli.commands as cli

        _data, _system, cfg = self._dirs()
        with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
            rc = cli.cmd_desktop_unwrap(SimpleNamespace(name=None, all=False))
        self.assertEqual(rc, 2)


class DesktopDoctorTest(unittest.TestCase):
    def _dirs(self):
        import tempfile

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        data = os.path.join(temp.name, "data")
        system = os.path.join(temp.name, "sys")
        os.makedirs(os.path.join(data, "applications"))
        os.makedirs(os.path.join(system, "applications"))
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY)
        env = mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": data, "XDG_DATA_DIRS": system},
        )
        env.start()
        self.addCleanup(env.stop)
        return data, system

    def test_no_wraps_is_ok(self):
        from taema import doctor

        self._dirs()
        check = doctor._desktop_check({})
        self.assertEqual(check["status"], "ok")
        self.assertEqual(check["name"], "desktop entries")

    def test_healthy_wrap_is_ok(self):
        from taema import desktop, doctor

        self._dirs()
        desktop.wrap("example.desktop")
        check = doctor._desktop_check({})
        self.assertEqual(check["status"], "ok")
        self.assertIn("1", check["message"])

    def test_drifted_wrap_warns(self):
        from taema import desktop, doctor

        _data, system = self._dirs()
        desktop.wrap("example.desktop")
        with open(os.path.join(system, "applications", "example.desktop"), "w") as fh:
            fh.write(ENTRY.replace("Terminal=false", "Terminal=true"))
        check = doctor._desktop_check({})
        self.assertEqual(check["status"], "warn")
        self.assertIn("example", check["message"])
        self.assertIn("wrap", check["fix"])

    def test_diagnose_includes_desktop_entries(self):
        from taema import desktop, doctor
        from tests.test_phase0 import make_cfg, tmp

        with (
            mock.patch.object(desktop, "list_wraps", return_value=[]),
            mock.patch.object(desktop, "drifted", return_value=[]),
        ):
            report = doctor.diagnose(make_cfg(tmp()), None, [])
        names = [item["name"] for item in report["checks"]]
        self.assertIn("desktop entries", names)


class LaunchDashDashTest(unittest.TestCase):
    def _ask(self, seen):
        def ask(_cfg, msg):
            seen.append(msg)
            if msg["cmd"] == "launch_prepare":
                return {"ok": True, "scope": "app-true", "via": "helper"}
            return {"ok": True}

        return ask

    def test_launch_strips_dash_dash(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import FakeCg, make_cfg, tmp

        seen = []
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(cli, "ask", side_effect=self._ask(seen)),
                mock.patch.object(cli.engine, "helper_move"),
                mock.patch.object(cli.os, "execvp") as ex,
            ):
                import types

                cli.cmd_launch(
                    types.SimpleNamespace(
                        app=None,
                        unit=None,
                        bind=False,
                        dry_run=False,
                        cmd=["--", "true"],
                    )
                )
        ex.assert_called_once_with("true", ["true"])
        self.assertEqual(seen[0]["app"], "true")


if __name__ == "__main__":
    unittest.main()
