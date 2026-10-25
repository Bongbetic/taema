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
                        "match": {"comm": inspect.comm(own)},
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


if __name__ == "__main__":
    unittest.main()
