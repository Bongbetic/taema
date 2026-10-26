"""Rare standard-library helpers stay out of the daemon startup import path."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LazyStdlibImports(unittest.TestCase):
    def test_service_import_defers_rare_stdlib_helpers(self):
        source = str(ROOT / "src")
        script = (
            "import sys; sys.path.insert(0, %r); "
            "from taema.daemon import service; "
            "loaded = {name for name in ('hmac', 'secrets', 'struct', 'uuid', "
            "'subprocess') "
            "if name in sys.modules}; "
            "assert not loaded, loaded"
        ) % source
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_registry_defers_typing(self):
        source = str(ROOT / "src")
        script = (
            "import sys; sys.path.insert(0, %r); "
            "import taema.cli.registry; "
            "assert 'typing' not in sys.modules, 'typing loaded'"
        ) % source
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
