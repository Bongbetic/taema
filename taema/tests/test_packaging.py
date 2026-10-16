"""Packaging scripts: syntax of every shell script, and INSTALL/REMOVE run in a temp root."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "srcpkgs", "taema", "INSTALL")
REMOVE = os.path.join(ROOT, "srcpkgs", "taema", "REMOVE")
ZSH_LINE = "[ -r /usr/share/taema/shell/taema.zsh ] && . /usr/share/taema/shell/taema.zsh # taema"
PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/:/usr/bin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/usr/bin/zsh
carol:x:1002:1002::/home/carol:/usr/bin/nologin
dave:x:1003:1003::/home/dave:/bin/false
erin:x:1004:1004::/home/erin:
svc:x:999:999::/var/lib/svc:/bin/bash
nobody:x:65534:65534::/:/bin/bash
"""


class SyntaxTest(unittest.TestCase):
    def test_sh_n(self):
        for rel in ("srcpkgs/taema/INSTALL", "srcpkgs/taema/REMOVE", "sv/taema/run",
                    "sv/taema/finish", "tools/build-xbps.sh"):
            with self.subTest(script=rel):
                r = subprocess.run(["sh", "-n", os.path.join(ROOT, rel)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


class ScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "root")
        self.stubs = os.path.join(self.tmp, "stubs")
        self.log = os.path.join(self.tmp, "calls.log")
        os.makedirs(os.path.join(self.root, "etc"))
        os.makedirs(os.path.join(self.root, "var", "service"))
        os.makedirs(self.stubs)
        self.write(os.path.join(self.root, "etc", "passwd"), PASSWD)
        self.write(os.path.join(self.root, "etc", "group"), "root:x:0:\ntaema:x:990:\n")
        for name in ("usermod", "sv", "groupadd"):
            self.stub(name, 'echo "%s $*" >> "$STUBLOG"\n' % name)
        # The name service is the host's: a script given another root must not ask it.
        self.stub("getent", 'echo "getent $*" >> "$STUBLOG"\nexit 2\n')

    def write(self, path, text):
        with open(path, "w") as f:
            f.write(text)

    def stub(self, name, body):
        path = os.path.join(self.stubs, name)
        self.write(path, "#!/bin/sh\n" + body)
        os.chmod(path, 0o755)

    def run_script(self, script, action, update):
        env = {"PATH": self.stubs + ":/usr/bin:/bin", "ROOTDIR": self.root, "STUBLOG": self.log, "LC_ALL": "C"}
        r = subprocess.run(["sh", script, action, "taema", "0.1.0_1", update, "", "noarch"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def calls(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    @property
    def link(self):
        return os.path.join(self.root, "var", "service", "taema")

    @property
    def zshrc(self):
        return os.path.join(self.root, "etc", "zsh", "zshrc")


class InstallTest(ScriptTest):
    def test_first_install(self):
        self.run_script(INSTALL, "post", "no")
        usermods = [c for c in self.calls() if c.startswith("usermod")]
        self.assertEqual(sorted(u.split()[-1] for u in usermods), ["alice", "bob"])
        for u in usermods:
            self.assertIn("-aG taema", u)
            self.assertIn("-R " + self.root, u)
        self.assertFalse([c for c in self.calls() if c.startswith("getent")])
        self.assertEqual(os.readlink(self.link), "/etc/sv/taema")

    def test_no_zsh_no_zshrc(self):
        self.run_script(INSTALL, "post", "no")
        self.assertFalse(os.path.exists(self.zshrc))

    def test_zsh_line_once(self):
        os.makedirs(os.path.join(self.root, "etc", "zsh"))
        self.write(self.zshrc, "# mine\n")
        self.run_script(INSTALL, "post", "no")
        self.run_script(INSTALL, "post", "no")
        with open(self.zshrc) as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, ["# mine", ZSH_LINE])

    def test_zshrc_created_when_zsh_binary_exists(self):
        os.makedirs(os.path.join(self.root, "usr", "bin"))
        self.write(os.path.join(self.root, "usr", "bin", "zsh"), "#!/bin/sh\n")
        os.chmod(os.path.join(self.root, "usr", "bin", "zsh"), 0o755)
        self.run_script(INSTALL, "post", "no")
        with open(self.zshrc) as f:
            self.assertEqual(f.read(), ZSH_LINE + "\n")

    def test_existing_link_kept(self):
        os.symlink("/elsewhere", self.link)
        self.run_script(INSTALL, "post", "no")
        self.assertEqual(os.readlink(self.link), "/elsewhere")

    def test_missing_group_adds_nobody(self):
        self.write(os.path.join(self.root, "etc", "group"), "root:x:0:\n")
        self.run_script(INSTALL, "post", "no")
        self.assertEqual([c for c in self.calls() if c.startswith("usermod")], [])

    def test_update_does_nothing(self):
        os.makedirs(os.path.join(self.root, "etc", "zsh"))
        self.run_script(INSTALL, "post", "yes")
        self.run_script(INSTALL, "pre", "no")
        self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.lexists(self.link))
        self.assertFalse(os.path.exists(self.zshrc))


class RemoveTest(ScriptTest):
    def setUp(self):
        super().setUp()
        os.symlink("/etc/sv/taema", self.link)
        os.makedirs(os.path.join(self.root, "etc", "zsh"))
        self.write(self.zshrc, "# mine\n" + ZSH_LINE + "\nexport X=1\n")

    def test_remove(self):
        self.run_script(REMOVE, "pre", "no")
        self.assertFalse(os.path.lexists(self.link))
        with open(self.zshrc) as f:
            self.assertEqual(f.read(), "# mine\nexport X=1\n")

    def test_update_does_nothing(self):
        self.run_script(REMOVE, "pre", "yes")
        self.run_script(REMOVE, "post", "no")
        self.assertTrue(os.path.islink(self.link))
        with open(self.zshrc) as f:
            self.assertIn(ZSH_LINE, f.read())
        self.assertEqual(self.calls(), [])

    def test_remove_without_files(self):
        os.unlink(self.link)
        os.unlink(self.zshrc)
        self.run_script(REMOVE, "pre", "no")


if __name__ == "__main__":
    unittest.main()
