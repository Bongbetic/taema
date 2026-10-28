"""Unit authoring: matching, lint, draft, dry-run, and testing."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from taema.cli import commands
from taema.config import policy
from taema.governor import engine
from taema.store import knowledge


def _self_comm():
    from taema.core import process as inspect

    return inspect.comm(os.getpid())


def _self_exe():
    from taema.core import process as inspect

    return inspect.exe(os.getpid())


def run_cli(root, *argv):
    override = Path(root) / "taema.toml"
    override.write_text(
        '[paths]\nstate_dir = "%s"\n' % (Path(root) / "state"), encoding="utf-8"
    )
    dead_socket = str(Path(root) / "dead.sock")
    output = io.StringIO()
    with redirect_stdout(output):
        code = commands.main(
            ["--config", str(override), "--socket", dead_socket, *argv]
        )
    return code, output.getvalue()


def good_unit():
    return {
        "unit": {"name": "app-demo", "kind": "app"},
        "match": {"comm": "demo"},
        "mem": {"class": "app"},
        "kill": {"graceful": 10},
    }


class UnitMatchTests(unittest.TestCase):
    def test_exe_must_equal(self):
        self.assertTrue(engine.unit_matches({"exe": "/usr/bin/x"}, 1, exe="/usr/bin/x"))
        self.assertFalse(
            engine.unit_matches({"exe": "/usr/bin/x"}, 1, exe="/usr/bin/y")
        )

    def test_comm_supports_globs(self):
        self.assertTrue(engine.unit_matches({"comm": "work-*"}, 1, comm="work-1"))
        self.assertFalse(engine.unit_matches({"comm": "work-*"}, 1, comm="play-1"))

    def test_cmdline_contains(self):
        self.assertTrue(
            engine.unit_matches(
                {"cmdline_contains": "server"}, 1, cmdline="app server --x"
            )
        )
        self.assertFalse(
            engine.unit_matches({"cmdline_contains": "server"}, 1, cmdline="app")
        )

    def test_empty_match_matches_nothing(self):
        self.assertFalse(engine.unit_matches({}, 1, comm="x"))
        self.assertFalse(engine.unit_matches({"bogus": 1}, 1, comm="x"))


class UnitLintTests(unittest.TestCase):
    def test_good_unit_is_clean(self):
        self.assertEqual(policy.validate_unit(good_unit()), [])

    def test_unknown_keys_flagged(self):
        unit = good_unit()
        unit["kill"]["frobnicate"] = True
        unit["nope"] = {}
        errors = policy.validate_unit(unit)
        self.assertTrue(any("frobnicate" in error for error in errors))
        self.assertTrue(any("nope" in error for error in errors))

    def test_missing_name_kind_and_match(self):
        self.assertTrue(policy.validate_unit({"unit": {"kind": "app"}}))
        self.assertTrue(policy.validate_unit({"unit": {"name": "x", "kind": "bogus"}}))
        unit = good_unit()
        del unit["match"]
        errors = policy.validate_unit(unit)
        self.assertTrue(any("match" in error for error in errors))

    def test_bad_durations_rejected(self):
        unit = good_unit()
        unit["kill"]["graceful"] = -5
        self.assertTrue(
            any("graceful" in error for error in policy.validate_unit(unit))
        )
        unit = good_unit()
        unit["gc"] = {"no_attach_grace": "soon"}
        self.assertTrue(
            any("no_attach_grace" in error for error in policy.validate_unit(unit))
        )

    def test_survive_logout_needs_a_need(self):
        unit = good_unit()
        unit["kill"]["survive_logout"] = True
        errors = policy.validate_unit(unit)
        self.assertTrue(any("survive_logout" in error for error in errors))
        unit["unit"]["stop_when_unneeded"] = True
        self.assertEqual(policy.validate_unit(unit), [])

    def test_misplaced_survive_logout_flagged(self):
        unit = good_unit()
        unit["unit"]["survive_logout"] = True
        errors = policy.validate_unit(unit)
        self.assertTrue(any("survive_logout" in error for error in errors))

    def test_children_shape(self):
        unit = good_unit()
        unit["children"] = [{"comm": "x"}]
        self.assertTrue(any("name" in error for error in policy.validate_unit(unit)))
        unit["children"] = [{"name": "kid"}]
        self.assertTrue(any("comm" in error for error in policy.validate_unit(unit)))

    def test_shipped_examples_are_clean(self):
        examples = Path(engine.__file__).resolve().parents[3] / "examples" / "units"
        import tomllib

        for path in sorted(examples.glob("*.toml")):
            with self.subTest(unit=path.name):
                with open(path, "rb") as stream:
                    self.assertEqual(policy.validate_unit(tomllib.load(stream)), [])

    def test_generic_comm_alone_is_overbroad(self):
        unit = good_unit()
        unit["match"] = {"comm": "node"}
        errors = policy.validate_unit(unit)
        self.assertTrue(any("over-broad" in error for error in errors))
        unit["match"] = {"comm": "node", "cmdline_contains": "server.js"}
        self.assertEqual(policy.validate_unit(unit), [])
        unit["match"] = {"comm": "demo"}
        self.assertEqual(policy.validate_unit(unit), [])

    def test_never_stop_with_stop_when_unneeded_is_flagged(self):
        unit = good_unit()
        unit["kill"]["never_stop"] = True
        unit["unit"]["stop_when_unneeded"] = True
        errors = policy.validate_unit(unit)
        self.assertTrue(any("never_stop" in error for error in errors))

    def test_hook_must_be_executable_when_a_path(self):
        with tempfile.TemporaryDirectory() as root:
            hook = Path(root) / "hook.sh"
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            unit = good_unit()
            unit["kill"]["hook"] = str(hook)
            errors = policy.validate_unit(unit)
            self.assertTrue(any("executable" in error for error in errors))
            hook.chmod(0o755)
            self.assertEqual(policy.validate_unit(unit), [])

    def test_mem_max_below_observed_peak_is_flagged(self):
        unit = good_unit()
        unit["mem"]["max"] = 1000
        self.assertEqual(policy.validate_unit(unit), [])
        errors = policy.validate_unit(unit, peaks={"app-demo": 2000})
        self.assertTrue(any("peak" in error for error in errors))
        self.assertEqual(policy.validate_unit(unit, peaks={"app-demo": 500}), [])


class UnitCliTests(unittest.TestCase):
    def isolated(self, root):
        config_home = Path(root) / "config"
        config_home.mkdir(parents=True, exist_ok=True)
        return mock.patch.dict(
            os.environ, {"XDG_CONFIG_HOME": str(config_home)}, clear=False
        )

    def test_draft_from_pid(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            code, output = run_cli(
                root, "unit", "draft", "self-test", "--from", str(os.getpid())
            )
            self.assertEqual(code, 0, output)
            path = Path(root) / "config" / "taema" / "units" / "self-test.toml"
            text = path.read_text(encoding="utf-8")
            self.assertIn('name = "self-test"', text)
            self.assertIn("[match]", text)
            import tomllib

            with open(path, "rb") as stream:
                self.assertEqual(policy.validate_unit(tomllib.load(stream)), [])

    def test_draft_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            target = Path(root) / "config" / "taema" / "units"
            target.mkdir(parents=True)
            (target / "taken.toml").write_text("x = 1\n", encoding="utf-8")
            code, _output = run_cli(
                root, "unit", "draft", "taken", "--from", str(os.getpid())
            )
            self.assertEqual(code, 1)
            code, _output = run_cli(
                root, "unit", "draft", "taken", "--from", str(os.getpid()), "--force"
            )
            self.assertEqual(code, 0)

    def test_draft_bad_pid(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            code, _output = run_cli(root, "unit", "draft", "nope", "--from", "99999999")
            self.assertEqual(code, 2)

    def test_new_from_pid_names_and_suggests_sections(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            code, output = run_cli(
                root,
                "unit",
                "new",
                "--from",
                str(os.getpid()),
                "--name",
                "self-new",
            )
            self.assertEqual(code, 0, output)
            path = Path(root) / "config" / "taema" / "units" / "self-new.toml"
            text = path.read_text(encoding="utf-8")
            self.assertIn('name = "self-new"', text)
            for section in (
                "[match]",
                "[children]",
                "[gc]",
                "[mem]",
                "[qos]",
                "[kill]",
            ):
                self.assertIn(section, text)
            import tomllib

            with open(path, "rb") as stream:
                self.assertEqual(policy.validate_unit(tomllib.load(stream)), [])

    def test_new_from_app_comm(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            import taema.core.process as inspect

            code, output = run_cli(
                root, "unit", "new", "--from", inspect.comm(os.getpid())
            )
            self.assertEqual(code, 0, output)
            units = list((Path(root) / "config" / "taema" / "units").glob("*.toml"))
            self.assertEqual(len(units), 1)

    def test_new_bad_target_dies(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            code, _output = run_cli(
                root, "unit", "new", "--from", "zzz-no-such-app-name"
            )
            self.assertEqual(code, 2)

    def test_new_validates_after_editor_save(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            editor = Path(root) / "editor.sh"
            editor.write_text(
                "#!/bin/sh\nprintf '\\n[nope]\\nx = 1\\n' >> \"$1\"\n",
                encoding="utf-8",
            )
            editor.chmod(0o755)
            env = {"EDITOR": str(editor)}
            with (
                mock.patch.dict(os.environ, env, clear=False),
                mock.patch.object(commands, "_stdin_is_tty", return_value=True),
            ):
                code, output = run_cli(
                    root, "unit", "new", "--from", str(os.getpid()), "--name", "edited"
                )
            self.assertEqual(code, 2, output)
            self.assertIn("nope", output)

    def test_unit_test_by_file_and_name_shows_scope_and_ladder(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            path = Path(root) / "unit.toml"
            path.write_text(
                '[unit]\nname = "app-selftest"\nkind = "app"\n'
                '[match]\ncomm = "%s"\nexe = "%s"\n' % (_self_comm(), _self_exe()),
                encoding="utf-8",
            )
            code, output = run_cli(root, "unit", "test", str(path))
            self.assertEqual(code, 0, output)
            self.assertIn("scope app-", output)
            self.assertIn("gc:", output)
            self.assertIn("mem:", output)
            self.assertIn("qos:", output)
            units_dir = Path(root) / "config" / "taema" / "units"
            units_dir.mkdir(parents=True)
            (units_dir / "app-selftest.toml").write_text(
                path.read_text(encoding="utf-8"), encoding="utf-8"
            )
            code, output = run_cli(root, "unit", "test", "app-selftest")
            self.assertEqual(code, 0, output)
            self.assertIn("scope app-", output)

    def test_lint_clean_and_bad(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            good = Path(root) / "good.toml"
            good.write_text(
                '[unit]\nname = "app-x"\nkind = "app"\n[match]\ncomm = "x"\n',
                encoding="utf-8",
            )
            code, _output = run_cli(root, "unit", "lint", str(good))
            self.assertEqual(code, 0)
            bad = Path(root) / "bad.toml"
            bad.write_text('[unit]\nname = "x"\nkind = "bogus"\n', encoding="utf-8")
            code, output = run_cli(root, "unit", "lint", str(bad))
            self.assertEqual(code, 2)
            self.assertIn("kind", output)
            broken = Path(root) / "broken.toml"
            broken.write_text("[unit\n", encoding="utf-8")
            code, output = run_cli(root, "unit", "lint", str(broken))
            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", output)

    def test_dry_run_matches_nothing_by_default(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            path = Path(root) / "unit.toml"
            path.write_text(
                '[unit]\nname = "app-zzz-nope"\nkind = "app"\n'
                '[match]\ncomm = "zzz-no-such-process-name"\n',
                encoding="utf-8",
            )
            code, output = run_cli(root, "unit", "dry-run", str(path))
            self.assertEqual(code, 0, output)
            self.assertIn("0 processes", output)

    def test_dry_run_rejects_bad_unit(self):
        with tempfile.TemporaryDirectory() as root, self.isolated(root):
            path = Path(root) / "unit.toml"
            path.write_text('[unit]\nkind = "app"\n', encoding="utf-8")
            code, output = run_cli(root, "unit", "dry-run", str(path))
            self.assertEqual(code, 2)
            self.assertIn("name", output)


class UnitTestOpTests(unittest.TestCase):
    def test_unit_test_fuzz_rejected_without_state_change(self):
        from taema import protocol

        bad = [
            {"v": 2, "id": "f1", "op": "unit_test", "unit": "nope", "pids": [1]},
            {"v": 2, "id": "f2", "op": "unit_test", "unit": {}, "pids": "x"},
            {"v": 2, "id": "f3", "op": "unit_test", "unit": {}, "pids": [0]},
            {"v": 2, "id": "f4", "op": "unit_test", "unit": {}, "pids": [True]},
            {
                "v": 2,
                "id": "f5",
                "op": "unit_test",
                "unit": {},
                "pids": list(range(5000)),
            },
            {"v": 2, "id": "f6", "op": "unit_test", "unit": [], "pids": [1]},
        ]
        for message in bad:
            with self.subTest(message=message["id"]):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_feedback(message)
        with tempfile.TemporaryDirectory() as root:
            store = knowledge.Store(str(Path(root) / "state"))
            before = store.export_legacy()
            reply = store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "f7",
                    "op": "unit_test",
                    "unit": {"unit": {"name": "x", "kind": "bogus"}},
                    "pids": [99999999],
                }
            )
            self.assertTrue(reply["ok"])
            self.assertEqual(reply["matched"], [])
            after = store.export_legacy()
            # Applying a command records its id for dedup; nothing else moves.
            after.pop("feedback_ids", None)
            before.pop("feedback_ids", None)
            self.assertEqual(after, before)

    def test_op_matches_live_pid(self):
        from taema.core import process as inspect

        with tempfile.TemporaryDirectory() as root:
            store = knowledge.Store(str(Path(root) / "state"))
            own = os.getpid()
            reply = store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "unit-test-1",
                    "op": "unit_test",
                    "unit": {
                        "unit": {"name": "app-self", "kind": "app"},
                        "match": {
                            "comm": inspect.comm(own),
                            "exe": inspect.exe(own),
                        },
                    },
                    "pids": [own, 99999999],
                }
            )
            self.assertTrue(reply["ok"])
            self.assertEqual(reply["lint"], [])
            self.assertEqual([hit["pid"] for hit in reply["matched"]], [own])

    def test_op_reports_lint_without_matching(self):
        with tempfile.TemporaryDirectory() as root:
            store = knowledge.Store(str(Path(root) / "state"))
            reply = store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "unit-test-2",
                    "op": "unit_test",
                    "unit": {"unit": {"name": "x", "kind": "bogus"}},
                    "pids": [1],
                }
            )
            self.assertTrue(reply["ok"])
            self.assertEqual(reply["matched"], [])
            self.assertTrue(reply["lint"])

    def test_changed_unit_file_reloads(self):
        import time as _time

        from taema.daemon import service

        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            units.mkdir()
            override = Path(root) / "taema.toml"
            override.write_text(
                "[paths]\nstate_dir = %s\nunits_dir = %s\n"
                % (json.dumps(str(Path(root) / "state")), json.dumps(str(units))),
                encoding="utf-8",
            )
            unit = units / "live.toml"
            unit.write_text(
                '[unit]\nname = "app-v1"\nkind = "app"\n[match]\ncomm = "v1"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"TAEMA_CONFIG": str(override)}):
                daemon = service.Daemon(policy.load_config())
                try:
                    names = [u["unit"]["name"] for u in daemon.units]
                    self.assertIn("app-v1", names)
                    unit.write_text(
                        '[unit]\nname = "app-v2"\nkind = "app"\n[match]\ncomm = "v2"\n',
                        encoding="utf-8",
                    )
                    stamp = _time.time() + 2
                    os.utime(unit, (stamp, stamp))
                    daemon.poll_config_reload()
                    names = [u["unit"]["name"] for u in daemon.units]
                    self.assertIn("app-v2", names)
                    self.assertNotIn("app-v1", names)
                finally:
                    daemon.sel.close()

    def test_op_rejects_malformed_messages(self):
        from taema import protocol

        cases = [
            {"v": 2, "id": "x", "op": "unit_test", "pids": [1]},
            {"v": 2, "id": "x", "op": "unit_test", "unit": {}, "pids": "1"},
            {"v": 2, "id": "x", "op": "unit_test", "unit": {}, "pids": [0]},
            {"v": 2, "id": "x", "op": "unit_test", "unit": {}, "pids": [-3]},
            {"v": 2, "id": "x", "op": "unit_test", "unit": [], "pids": [1]},
            {
                "v": 2,
                "id": "x",
                "op": "unit_test",
                "unit": {},
                "pids": list(range(5000)),
            },
            {
                "v": 2,
                "id": "x",
                "op": "unit_test",
                "unit": {},
                "pids": [1],
                "bogus": True,
            },
        ]
        with tempfile.TemporaryDirectory() as root:
            store = knowledge.Store(str(Path(root) / "state"))
            for index, message in enumerate(cases):
                with self.subTest(case=index):
                    with self.assertRaises(ValueError):
                        protocol.validate_feedback(dict(message))
                    self.assertIsNone(store.apply_feedback_command(dict(message)))


PACK_NAMES = (
    "vscode",
    "jetbrains",
    "android-emulator",
    "podman",
    "libvirt-qemu",
    "docker-rootless",
    "incus",
    "virtualbox",
    "steam",
    "discord",
    "electron",
)


def _pack_dir():
    return Path(__file__).resolve().parents[1] / "examples" / "packs"


class UnitManageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system = os.path.join(self.temp.name, "system")
        self.userbase = os.path.join(self.temp.name, "user")
        self.user = os.path.join(self.userbase, "units")
        os.makedirs(self.system)
        os.makedirs(self.user)
        self._system = mock.patch.object(policy, "SYSTEM_UNITS", self.system)
        self._system.start()
        self.addCleanup(self._system.stop)
        self._home = mock.patch.object(
            policy, "user_config_dir", return_value=self.userbase
        )
        self._home.start()
        self.addCleanup(self._home.stop)
        self.root = os.path.join(self.temp.name, "root")
        os.makedirs(self.root)

    def write(self, directory, name, body):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(body)
        return path

    def test_list_shows_source_and_active(self):
        self.write(
            self.system,
            "a.toml",
            '[unit]\nname = "app-a"\nkind = "app"\n[match]\ncomm = "a"\n',
        )
        self.write(
            self.user,
            "b.toml",
            '[unit]\nname = "app-b"\nkind = "app"\n[match]\ncomm = "b"\n'
            "[source]\nlearned = true\n",
        )
        self.write(
            self.system,
            "c.toml",
            '[unit]\nname = "app-c"\nkind = "app"\n[match]\ncomm = "c"\n',
        )
        self.write(self.user, "c.toml.disabled", "")
        code, output = run_cli(self.root, "unit", "list")
        self.assertEqual(code, 0)
        lines = {
            parts[0]: parts[1:3]
            for parts in (line.split() for line in output.strip().splitlines())
            if parts
        }
        self.assertEqual(lines["app-a"], ["system", "yes"])
        self.assertEqual(lines["app-b"], ["learned", "yes"])
        self.assertEqual(lines["app-c"], ["system", "no"])

    def test_disable_enable_roundtrip(self):
        self.write(
            self.system,
            "a.toml",
            '[unit]\nname = "app-a"\nkind = "app"\n[match]\ncomm = "a"\n',
        )
        code, _output = run_cli(self.root, "unit", "disable", "app-a")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(self.user, "a.toml.disabled")))
        code, output = run_cli(self.root, "unit", "list")
        self.assertEqual(code, 0)
        self.assertIn("app-a system no", output)
        code, _output = run_cli(self.root, "unit", "enable", "app-a")
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(os.path.join(self.user, "a.toml.disabled")))
        code, output = run_cli(self.root, "unit", "list")
        self.assertIn("app-a system yes", output)

    def test_disable_unknown_unit_fails(self):
        from contextlib import redirect_stderr

        error = io.StringIO()
        with redirect_stderr(error):
            code, _output = run_cli(self.root, "unit", "disable", "nope")
        self.assertEqual(code, 1)
        self.assertIn("no such unit", error.getvalue())

    def test_enable_unknown_and_idempotent(self):
        from contextlib import redirect_stderr

        self.write(
            self.system,
            "a.toml",
            '[unit]\nname = "app-a"\nkind = "app"\n[match]\ncomm = "a"\n',
        )
        error = io.StringIO()
        with redirect_stderr(error):
            code, _output = run_cli(self.root, "unit", "enable", "nope")
        self.assertEqual(code, 1)
        self.assertIn("no such unit", error.getvalue())
        code, output = run_cli(self.root, "unit", "enable", "app-a")
        self.assertEqual(code, 0)
        self.assertIn("already enabled", output)
        self.write(self.user, "ghost.toml.disabled", "")
        code, _output = run_cli(self.root, "unit", "enable", "ghost")
        self.assertEqual(code, 0)
        self.assertFalse(
            os.path.exists(os.path.join(self.user, "ghost.toml.disabled"))
        )

    def test_install_from_pack(self):
        code, _output = run_cli(self.root, "unit", "install", "vscode")
        self.assertEqual(code, 0)
        installed = os.path.join(self.user, "vscode.toml")
        self.assertTrue(os.path.isfile(installed))
        unit, error = policy.read_unit_file(installed)
        self.assertIsNone(error)
        self.assertEqual(policy.validate_unit(unit), [])
        code, _output = run_cli(self.root, "unit", "install", "vscode")
        self.assertEqual(code, 1)
        code, _output = run_cli(self.root, "unit", "install", "vscode", "--force")
        self.assertEqual(code, 0)
        from contextlib import redirect_stderr

        error = io.StringIO()
        with redirect_stderr(error):
            code, _output = run_cli(self.root, "unit", "install", "nope")
        self.assertEqual(code, 2)
        self.assertIn("vscode", error.getvalue())

    def test_all_packs_lint_clean(self):
        packs = sorted(_pack_dir().glob("*.toml"))
        self.assertEqual({path.stem for path in packs}, set(PACK_NAMES))
        for path in packs:
            with self.subTest(pack=path.stem):
                unit, error = policy.read_unit_file(str(path))
                self.assertIsNone(error)
                self.assertEqual(policy.validate_unit(unit), [])


if __name__ == "__main__":
    unittest.main()
