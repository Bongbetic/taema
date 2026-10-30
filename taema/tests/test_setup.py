"""First-run wizard: `taema setup` (issue #81)."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from tests.test_phase0 import make_cfg
from taema.notify import NullNotifier


def run_cli(root, *argv):
    override = os.path.join(root, "taema.toml")
    with open(override, "w", encoding="utf-8") as stream:
        stream.write('[paths]\nstate_dir = "%s"\n' % os.path.join(root, "state"))
    dead_socket = os.path.join(root, "dead.sock")
    output = io.StringIO()
    with redirect_stdout(output):
        from taema.cli import commands

        code = commands.main(["--config", override, "--socket", dead_socket, *argv])
    return code, output.getvalue()


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = os.path.join(self.temp.name, "home")
        os.makedirs(self.home)
        self._xdg = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": os.path.join(self.home, ".config"), "HOME": self.home},
        )
        self._xdg.start()
        self.addCleanup(self._xdg.stop)
        self.system_root = os.path.join(self.temp.name, "sysroot")
        os.makedirs(self.system_root)
        self.cfg = make_cfg(os.path.join(self.temp.name, "state"))

    def test_yes_writes_dropin_and_second_run_noop(self):
        from taema import setup as setup_mod

        first = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=NullNotifier(),
        )
        dropin = os.path.join(self.home, ".config", "taema", "taema.d", "40-setup.toml")
        self.assertTrue(os.path.isfile(dropin))
        with open(dropin) as stream:
            self.assertIn('mode = "adopt"', stream.read())
        mode = next(item for item in first["steps"] if item["name"] == "mode")
        self.assertEqual(mode["status"], "fixed")
        self.assertIn(dropin, first["wrote"])

        second = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=NullNotifier(),
        )
        mode = next(item for item in second["steps"] if item["name"] == "mode")
        self.assertEqual(mode["status"], "skipped")
        self.assertEqual(second["wrote"], [])

    def test_runtimes_install_detected_packs(self):
        from taema import setup as setup_mod

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=NullNotifier(),
            which=lambda name: "/usr/bin/" + name if name == "podman" else None,
        )
        target = os.path.join(self.home, ".config", "taema", "units", "podman.toml")
        self.assertTrue(os.path.isfile(target))
        step = next(item for item in report["steps"] if item["name"] == "runtimes")
        self.assertEqual(step["status"], "fixed")
        self.assertIn(target, report["wrote"])

        again = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            which=lambda name: "/usr/bin/" + name if name == "podman" else None,
            backend=NullNotifier(),
        )
        step = next(item for item in again["steps"] if item["name"] == "runtimes")
        self.assertEqual(step["status"], "skipped")

    def test_runtimes_decline_installs_nothing(self):
        from taema import setup as setup_mod

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            which=lambda name: "/usr/bin/podman" if name == "podman" else None,
            input_fn=lambda prompt: "n",
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "runtimes")
        self.assertEqual(step["status"], "skipped")
        self.assertFalse(
            os.path.isfile(
                os.path.join(self.home, ".config", "taema", "units", "podman.toml")
            )
        )

    def test_choice_prompt_selects_auto(self):
        from taema import setup as setup_mod

        setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            input_fn=lambda prompt: "auto",
            backend=NullNotifier(),
        )
        dropin = os.path.join(self.home, ".config", "taema", "taema.d", "40-setup.toml")
        with open(dropin) as stream:
            self.assertIn('mode = "auto"', stream.read())

    def test_desktop_installs_autostart_widget_and_wraps(self):
        from unittest import mock

        from taema import desktop as desktop_mod
        from taema import setup as setup_mod
        from taema.store.knowledge import Store

        store = Store(os.path.join(self.temp.name, "dstate"), {})
        with store.db.connection() as connection:
            connection.execute(
                "INSERT INTO apps(key, kind, instances) VALUES ('code', 'app', 7)"
            )
            connection.commit()
        applications = os.path.join(self.temp.name, "applications")
        user_apps = os.path.join(self.temp.name, "user-apps")
        os.makedirs(applications)
        os.makedirs(user_apps)
        with open(os.path.join(applications, "code.desktop"), "w") as stream:
            stream.write("[Desktop Entry]\nName=Code\nExec=/usr/bin/code\n")
        which = lambda name: "/usr/bin/" + name if name == "quickshell" else None
        with (
            mock.patch.object(desktop_mod, "system_dirs", return_value=[applications]),
            mock.patch.object(desktop_mod, "user_dir", return_value=user_apps),
            mock.patch.object(desktop_mod, "list_wraps", return_value=[]),
            mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "niri"}),
        ):
            report = setup_mod.run_setup(
                self.cfg,
                store,
                system_root=self.system_root,
                yes=True,
                which=which,
                backend=NullNotifier(),
            )
        self.assertTrue(
            os.path.isfile(
                os.path.join(self.home, ".config", "autostart", "taema-agent.desktop")
            )
        )
        self.assertFalse(
            os.path.exists(os.path.join(self.home, ".config", "quickshell"))
        )
        self.assertTrue(os.path.isfile(os.path.join(user_apps, "code.desktop")))
        names = [item for item in report["steps"]]
        self.assertIn("autostart", [item["name"] for item in names])
        self.assertIn("widget", [item["name"] for item in names])
        self.assertIn("wrap", [item["name"] for item in names])
        widget = next(item for item in names if item["name"] == "widget")
        self.assertIn("cp ", widget["message"])

        with (
            mock.patch.object(desktop_mod, "system_dirs", return_value=[applications]),
            mock.patch.object(desktop_mod, "user_dir", return_value=user_apps),
            mock.patch.object(
                desktop_mod,
                "list_wraps",
                return_value=[{"file": os.path.join(user_apps, "code.desktop")}],
            ),
            mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "niri"}),
        ):
            again = setup_mod.run_setup(
                self.cfg,
                store,
                system_root=self.system_root,
                yes=True,
                which=which,
                backend=NullNotifier(),
            )
        self.assertEqual(again["wrote"], [])

    def test_memory_reports_ram_swap_zswap_advice(self):
        from taema import setup as setup_mod

        proc = os.path.join(self.temp.name, "proc")
        os.makedirs(proc)
        with open(os.path.join(proc, "meminfo"), "w") as stream:
            stream.write("MemTotal:        8000000 kB\nMemAvailable:    4000000 kB\n")
        os.makedirs(os.path.join(self.system_root, "proc"))
        with open(os.path.join(self.system_root, "proc/swaps"), "w") as stream:
            stream.write(
                "Filename\tType\tSize\tUsed\tPriority\n/swap\tfile\t1\t0\t-2\n"
            )
        os.makedirs(os.path.join(self.system_root, "sys/module/zswap/parameters"))
        with open(
            os.path.join(self.system_root, "sys/module/zswap/parameters/enabled"), "w"
        ) as stream:
            stream.write("N\n")
        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            proc_root=proc,
            yes=True,
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "memory")
        self.assertIn("RAM total 7 GiB", step["message"])
        self.assertIn("swap: /swap", step["message"])
        self.assertIn("zswap: off", step["message"])
        self.assertIn(
            "sudo sh -c 'echo Y > /sys/module/zswap/parameters/enabled'",
            report["root_commands"],
        )

    def test_oom_explains_earlyoom_coordination(self):
        from taema import setup as setup_mod

        proc = os.path.join(self.temp.name, "procoom")
        pid = os.path.join(proc, "4242")
        os.makedirs(pid)
        with open(os.path.join(pid, "comm"), "w") as stream:
            stream.write("earlyoom\n")
        with open(os.path.join(pid, "cmdline"), "wb") as stream:
            stream.write(b"earlyoom\x00-m\x0010\x00")
        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            proc_root=proc,
            yes=True,
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "oom")
        self.assertIn("kills below 10", step["message"])
        self.assertIn("--prefer", step["message"])

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            proc_root="/nonexistent-proc",
            yes=True,
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "oom")
        self.assertIn("no earlyoom process running", step["message"])

    def test_hooks_report_missing_files_as_root_commands(self):
        from taema import setup as setup_mod

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "hooks")
        self.assertEqual(step["status"], "warn")
        self.assertIn("bash hook", step["message"])
        self.assertIn("sudo xbps-install -f taema", report["root_commands"])

        for path in (
            "etc/bash/bashrc.d/taema.sh",
            "usr/share/fish/vendor_conf.d/taema.fish",
            "usr/libexec/taema/taema-hook",
        ):
            full = os.path.join(self.system_root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as stream:
                stream.write("x")
        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=NullNotifier(),
        )
        step = next(item for item in report["steps"] if item["name"] == "hooks")
        self.assertEqual(step["status"], "ok")
        self.assertEqual(report["root_commands"], [])

    def test_notify_confirms_reply(self):
        from taema import setup as setup_mod

        calls = {}

        class FakeBackend:
            name = "fake"

            def send(self, summary, body, actions=(), wait=False, **kwargs):
                calls["wait"] = wait
                calls["actions"] = actions
                return {"id": 7}

            def wait_for_action(self, receipt, timeout):
                calls["timeout"] = timeout
                return ("action", "stop")

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            backend=FakeBackend(),
            input_fn=lambda prompt: "",
        )
        step = next(item for item in report["steps"] if item["name"] == "notify")
        self.assertEqual(step["status"], "fixed")
        self.assertTrue(calls["wait"])
        self.assertIn("Stop", [label for _key, label in calls["actions"]])

    def test_notify_yes_sends_without_wait(self):
        from taema import setup as setup_mod

        calls = {}

        class FakeBackend:
            name = "fake"

            def send(self, summary, body, actions=(), wait=False, **kwargs):
                calls["wait"] = wait
                return {"id": 7}

            def wait_for_action(self, receipt, timeout):
                raise AssertionError("must not wait with --yes")

        report = setup_mod.run_setup(
            self.cfg,
            None,
            system_root=self.system_root,
            yes=True,
            backend=FakeBackend(),
        )
        step = next(item for item in report["steps"] if item["name"] == "notify")
        self.assertEqual(step["status"], "fixed")
        self.assertFalse(calls["wait"])

    def test_cli_setup_yes_reports_steps(self):
        from taema.notify import NullNotifier

        with mock.patch("taema.notify.select_backend", return_value=NullNotifier()):
            code, output = run_cli(self.temp.name, "setup", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("doctor", output)
        self.assertIn("mode", output)


if __name__ == "__main__":
    unittest.main()
