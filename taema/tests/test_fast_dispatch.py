"""Dispatch tests: the shell hooks prefer taema-fast, fall back to taema-hook.

Runs the exact selection lines from each shell file in a fake libexec dir.
zsh and fish are not installed here, so their line shapes are asserted
literally while the bash logic also runs for real.
"""

import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path):
    with open(os.path.join(ROOT, path)) as f:
        return f.read()


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.lib = tempfile.mkdtemp()
        self.addCleanup(
            lambda: subprocess.run(["rm", "-rf", self.lib], check=False)
        )

    def select_bash(self, lib, hook=None):
        script = "TAEMA_HOOK=%s\n_taema_hook=${TAEMA_HOOK:-}\n" % (
            hook if hook is not None else ""
        )
        script += (
            "if [[ -z $_taema_hook ]]; then\n"
            "    _taema_hook=%s/taema-fast\n"
            "    [[ -x $_taema_hook ]] || _taema_hook=%s/taema-hook\n"
            "fi\n"
            "printf '%%s' \"$_taema_hook\"\n" % (lib, lib)
        )
        if hook is None:
            script = script.replace("TAEMA_HOOK=\n", "unset TAEMA_HOOK\n", 1)
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True
        ).stdout

    def touch(self, name):
        path = os.path.join(self.lib, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(path, 0o755)

    def test_bash_prefers_fast(self):
        self.touch("taema-fast")
        self.touch("taema-hook")
        self.assertEqual(
            self.select_bash(self.lib), os.path.join(self.lib, "taema-fast")
        )

    def test_bash_falls_back_to_hook(self):
        self.touch("taema-hook")
        self.assertEqual(
            self.select_bash(self.lib), os.path.join(self.lib, "taema-hook")
        )

    def test_bash_explicit_hook_wins(self):
        self.touch("taema-fast")
        self.touch("taema-hook")
        custom = os.path.join(self.lib, "custom")
        self.touch("custom")
        self.assertEqual(self.select_bash(self.lib, hook=custom), custom)

    def test_bash_matches_the_shipped_file(self):
        body = read("shell/taema.bash")
        self.assertIn("_taema_hook=${TAEMA_HOOK:-}", body)
        self.assertIn("_taema_hook=/usr/libexec/taema/taema-fast", body)
        self.assertIn(
            "[[ -x $_taema_hook ]] || _taema_hook=/usr/libexec/taema/taema-hook",
            body,
        )

    def test_zsh_matches_the_shipped_file(self):
        body = read("shell/taema.zsh")
        self.assertIn("typeset -g _taema_hook=${TAEMA_HOOK:-}", body)
        self.assertIn("_taema_hook=/usr/libexec/taema/taema-fast", body)
        self.assertIn(
            "[[ -x $_taema_hook ]] || _taema_hook=/usr/libexec/taema/taema-hook",
            body,
        )

    def test_fish_matches_the_shipped_file(self):
        body = read("shell/taema.fish")
        self.assertIn(
            "set -g __taema_hook /usr/libexec/taema/taema-fast", body
        )
        self.assertIn("set __taema_hook /usr/libexec/taema/taema-hook", body)
        self.assertIn(
            "set -q TAEMA_HOOK; and set __taema_hook $TAEMA_HOOK", body
        )
        # the explicit override stays last so it always wins
        self.assertGreater(
            body.index("set -q TAEMA_HOOK"),
            body.index("set __taema_hook /usr/libexec/taema/taema-hook"),
        )

    def test_makefile_installs_fast(self):
        body = read("Makefile")
        self.assertIn(
            "install -m755 $(RUST_OUT)/taema-fast $(LIBEXEC)/taema-fast",
            body,
        )

    def test_make_dry_run_installs_fast(self):
        dest = tempfile.mkdtemp()
        self.addCleanup(
            lambda: subprocess.run(["rm", "-rf", dest], check=False)
        )
        r = subprocess.run(
            ["make", "-n", "install", "DESTDIR=" + dest],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("rust/target/release/taema-fast", r.stdout)


if __name__ == "__main__":
    unittest.main()
