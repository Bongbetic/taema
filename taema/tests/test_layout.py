"""Package boundaries, compatibility imports, and installed layout."""

import ast
import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1]


class PackageLayoutTests(unittest.TestCase):
    OLD_MODULE_PATHS = (
        "taema.authorization",
        "taema.cgroup",
        "taema.engine",
        "taema.inspect",
        "taema.knowledge",
        "taema.lineage",
        "taema.policy",
    )

    def test_old_module_paths_are_removed(self):
        for old_name in self.OLD_MODULE_PATHS:
            with self.subTest(module=old_name):
                leaf = old_name.split(".")[-1]
                self.assertFalse((PACKAGE / "src" / "taema" / (leaf + ".py")).exists())
                with self.assertRaises(ImportError):
                    importlib.import_module(old_name)

    def test_cli_and_daemon_packages_export_no_legacy_names(self):
        cli_package = importlib.import_module("taema.cli")
        daemon_package = importlib.import_module("taema.daemon")
        for name in ("cmd_ls", "cmd_kill", "main", "ask", "die", "socket"):
            with self.subTest(package="taema.cli", name=name):
                self.assertFalse(hasattr(cli_package, name))
        for name in ("Daemon", "main"):
            with self.subTest(package="taema.daemon", name=name):
                self.assertFalse(hasattr(daemon_package, name))

    def test_authorization_model_has_no_io_dependencies_or_calls(self):
        source = PACKAGE / "src" / "taema" / "model" / "authorization.py"
        tree = ast.parse(source.read_text())
        allowed_imports = {"__future__", "dataclasses", "typing"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".", 1)[0])
        self.assertLessEqual(imports, allowed_imports)

        forbidden_calls = {"open", "input", "print", "exec", "eval", "__import__"}
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(forbidden_calls.isdisjoint(calls))

    def test_install_keeps_nested_packages_importable(self):
        wrapper = subprocess.run(
            [str(PACKAGE / "bin" / "taema"), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(wrapper.returncode, 0, wrapper.stderr)
        self.assertIn("usage: taema", wrapper.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            subprocess.run(
                ["make", "install", f"DESTDIR={stage}"],
                cwd=PACKAGE,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            wrapper_path = stage / "usr" / "bin" / "taema"
            self.assertTrue(wrapper_path.is_file())
            self.assertTrue(os.access(wrapper_path, os.X_OK))
            package_root = stage / "usr" / "lib" / "taema"
            installed = package_root / "taema"
            for relative in (
                "model/authorization.py",
                "core/cgroup.py",
                "core/process.py",
                "core/lineage.py",
                "store/knowledge.py",
                "governor/engine.py",
                "daemon/service.py",
                "cli/commands.py",
                "config/policy.py",
            ):
                with self.subTest(module=relative):
                    self.assertTrue((installed / relative).is_file())
            for leaf in (
                "authorization.py",
                "cgroup.py",
                "engine.py",
                "inspect.py",
                "knowledge.py",
                "lineage.py",
                "policy.py",
            ):
                with self.subTest(removed=leaf):
                    self.assertFalse((installed / leaf).exists())

            env = os.environ.copy()
            env["PYTHONPATH"] = str(package_root)
            result = subprocess.run(
                [sys.executable, "-m", "taema", "--help"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage: taema", result.stdout)


if __name__ == "__main__":
    unittest.main()
