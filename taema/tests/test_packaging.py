"""Packaging scripts: syntax of every shell script, and INSTALL/REMOVE run in a temp root."""

import os
import shutil
import subprocess
import sys
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
        for rel in (
            "srcpkgs/taema/INSTALL",
            "srcpkgs/taema/REMOVE",
            "sv/taema/run",
            "sv/taema/finish",
            "libexec/taemad-user",
            "bin/taemad",
            "tools/build-xbps.sh",
        ):
            with self.subTest(script=rel):
                r = subprocess.run(
                    ["sh", "-n", os.path.join(ROOT, rel)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_hold_service_setting_reaches_the_user_daemon(self):
        with open(os.path.join(ROOT, "sv/taema/run"), encoding="utf-8") as stream:
            service_run = stream.read()
        with open(
            os.path.join(ROOT, "libexec/taemad-user"), encoding="utf-8"
        ) as stream:
            user_run = stream.read()
        self.assertIn("export TAEMA_HOLD", service_run)
        self.assertIn('TAEMA_HOLD="${TAEMA_HOLD:-0}"', user_run)


class InstalledDocumentationTest(unittest.TestCase):
    def test_install_publishes_learning_manual_and_state_docs(self):
        with tempfile.TemporaryDirectory() as staged:
            result = subprocess.run(
                ["make", "DESTDIR=" + staged, "install"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in (
                "usr/share/man/man7/taema-learning.7",
                "usr/share/doc/taema/state-schema.md",
                "usr/share/doc/taema/legacy-state-migration.md",
                "usr/bin/taemad",
                "usr/libexec/taema/taemad-user",
            ):
                with self.subTest(path=path):
                    self.assertTrue(os.path.isfile(os.path.join(staged, path)), path)
            self.assertTrue(
                os.access(os.path.join(staged, "usr/bin/taemad"), os.X_OK)
            )


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

    def run_script(self, script, action, update, root=None):
        env = {
            "PATH": self.stubs + ":/usr/bin:/bin",
            "ROOTDIR": self.root if root is None else root,
            "STUBLOG": self.log,
            "LC_ALL": "C",
        }
        r = subprocess.run(
            ["sh", script, action, "taema", "0.1.0_1", update, "", "noarch"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
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


class ServiceDelegationTest(unittest.TestCase):
    def test_user_service_uses_installed_daemon_only_entrypoint(self):
        with open(os.path.join(ROOT, "libexec/taemad-user"), encoding="utf-8") as source:
            user_run = source.read()
        with open(os.path.join(ROOT, "bin/taemad"), encoding="utf-8") as source:
            daemon_wrapper = source.read()
        with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as source:
            makefile = source.read()
        self.assertIn("/usr/bin/taemad", user_run)
        self.assertNotIn("/usr/bin/taema daemon", user_run)
        self.assertIn("-m taema.daemon_entrypoint", daemon_wrapper)
        self.assertNotIn("PYTHONMALLOC=malloc", daemon_wrapper)
        self.assertIn("bin/taemad", makefile)

    def test_root_service_primes_readable_bytecode_before_privilege_drop(self):
        with open(os.path.join(ROOT, "bin/taemad"), encoding="utf-8") as source:
            daemon_wrapper = source.read()
        with open(os.path.join(ROOT, "libexec/taemad-user"), encoding="utf-8") as source:
            user_run = source.read()
        reset_python_env = user_run.index(
            "unset PYTHONDONTWRITEBYTECODE PYTHONPYCACHEPREFIX"
        )
        precompile = user_run.index("-m compileall")
        chmod_dirs = user_run.index("-exec chmod 755")
        chmod_bytecode = user_run.index("-exec chmod 644")
        user_umask = user_run.index("umask 022")
        restore_umask = user_run.rindex("umask 077")
        privilege_drop = user_run.index("exec setpriv")
        self.assertLess(reset_python_env, precompile)
        self.assertLess(user_umask, precompile)
        self.assertLess(precompile, chmod_dirs)
        self.assertLess(chmod_dirs, chmod_bytecode)
        self.assertLess(chmod_bytecode, restore_umask)
        self.assertLess(restore_umask, privilege_drop)
        self.assertIn("/usr/lib/taema/taema", user_run)
        precompile_block = user_run[precompile:privilege_drop]
        self.assertIn("continuing with source imports", precompile_block)
        self.assertNotIn("exit 1", precompile_block)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", daemon_wrapper)
        self.assertIn("unset PYTHONPYCACHEPREFIX", daemon_wrapper)
        self.assertIn("lib=/usr/lib/taema", daemon_wrapper)
        self.assertIn(
            '[ -d "$here/../src/taema" ] && lib=$here/../src', daemon_wrapper
        )

    def test_root_compileall_creates_readable_adjacent_bytecode(self):
        with tempfile.TemporaryDirectory(prefix="taema-pycache-test-") as temporary:
            package = os.path.join(temporary, "package", "samplepkg")
            os.makedirs(package)
            with open(os.path.join(package, "__init__.py"), "w") as target:
                target.write("value = 1\n")
            with open(os.path.join(package, "module.py"), "w") as target:
                target.write("other = 2\n")
            env = dict(os.environ)
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            env.pop("PYTHONPYCACHEPREFIX", None)
            original_umask = os.umask(0o022)
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "compileall", "-q", package],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            finally:
                os.umask(original_umask)
            self.assertEqual(result.returncode, 0, result.stderr)
            cache = os.path.join(package, "__pycache__")
            cached = [
                os.path.join(cache, name)
                for name in os.listdir(cache)
                if name.endswith(".pyc")
            ]
            self.assertTrue(cached)
            self.assertTrue(
                all(os.stat(path).st_mode & 0o044 == 0o044 for path in cached)
            )

    def test_precompile_failure_warns_and_falls_through_to_daemon_start(self):
        with open(os.path.join(ROOT, "libexec/taemad-user"), encoding="utf-8") as source:
            user_run = source.read()
        start = user_run.index("if ! /usr/bin/python3 -P -m compileall")
        end = user_run.index("\nfi", start) + len("\nfi")
        block = user_run[start:end].replace(
            "/usr/bin/python3 -P -m compileall -q /usr/lib/taema/taema",
            "/bin/false",
        )
        result = subprocess.run(
            ["sh", "-c", block + '\nprintf "%s\\n" daemon-start-continues\n'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bytecode precompile failed", result.stderr)
        self.assertIn("daemon-start-continues", result.stdout)

    def test_existing_service_skip_follows_cgroup_repair(self):
        service_path = os.path.join(ROOT, "sv", "taema", "run")
        with open(service_path, encoding="utf-8") as source:
            service = source.read()
        start = service.index("sync_members() {")
        end = service.index("\n}\n\nif [ ! -f", start)
        sync_members = service[start:end]
        repair = sync_members.index('chown_member_cgroup "$uid:$ugid" "$d"')
        existing_service_skip = sync_members.index(
            '[ ! -e "$SVDIR/$user" ] || continue'
        )
        self.assertLess(repair, existing_service_skip)

    def test_member_cgroup_chown_includes_memory_pressure_when_present(self):
        service_path = os.path.join(ROOT, "sv", "taema", "run")
        with open(service_path, encoding="utf-8") as source:
            service = source.read()
        start = service.index("chown_member_cgroup() {")
        end = service.index("\n}\n", start) + 2
        helper = service[start:end]

        with tempfile.TemporaryDirectory() as tmp:
            for present in (True, False):
                with self.subTest(memory_pressure=present):
                    cgroup = os.path.join(tmp, "cgroup-" + str(present))
                    os.makedirs(cgroup)
                    for name in (
                        "cgroup.procs",
                        "cgroup.threads",
                        "cgroup.subtree_control",
                    ):
                        open(os.path.join(cgroup, name), "w").close()
                    pressure = os.path.join(cgroup, "memory.pressure")
                    if present:
                        open(pressure, "w").close()
                    calls = os.path.join(tmp, "chown-calls")
                    open(calls, "w").close()
                    runner = os.path.join(tmp, "run-helper.sh")
                    with open(runner, "w") as target:
                        target.write(
                            "#!/bin/sh\n"
                            'chown() { printf \'%s\\n\' "$*" >> "$CHOWN_LOG"; }\n'
                            + helper
                            + '\nchown_member_cgroup 1000:1000 "$CGROUP_PATH"\n'
                        )
                    result = subprocess.run(
                        ["sh", runner],
                        env={
                            "PATH": "/usr/bin:/bin",
                            "CHOWN_LOG": calls,
                            "CGROUP_PATH": cgroup,
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    with open(calls) as source:
                        chown_calls = source.read().splitlines()
                    self.assertEqual(len(chown_calls), 2 if present else 1)
                    self.assertIn("1000:1000 " + cgroup, chown_calls[0])
                    if present:
                        self.assertEqual(chown_calls[1], "1000:1000 " + pressure)


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

    def test_live_update_restarts_daemon_after_install(self):
        self.run_script(INSTALL, "post", "yes", root="/")
        self.assertEqual(self.calls(), ["sv restart taema"])


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
        cache = os.path.join(
            self.root, "usr", "lib", "taema", "taema", "__pycache__"
        )
        os.makedirs(cache)
        generated = os.path.join(cache, "service.cpython-314.pyc")
        self.write(generated, "generated bytecode")
        self.run_script(REMOVE, "pre", "yes")
        self.run_script(REMOVE, "post", "no")
        self.assertTrue(os.path.islink(self.link))
        with open(self.zshrc) as f:
            self.assertIn(ZSH_LINE, f.read())
        self.assertTrue(os.path.isfile(generated))
        self.assertEqual(self.calls(), [])

    def test_remove_without_files(self):
        os.unlink(self.link)
        os.unlink(self.zshrc)
        self.run_script(REMOVE, "pre", "no")

    def test_remove_cleans_only_generated_bytecode(self):
        package = os.path.join(self.root, "usr", "lib", "taema", "taema")
        cache = os.path.join(package, "__pycache__")
        os.makedirs(cache)
        self.write(os.path.join(cache, "service.cpython-314.pyc"), "generated")
        source = os.path.join(package, "service.py")
        self.write(source, "source remains")

        self.run_script(REMOVE, "pre", "no")

        self.assertFalse(os.path.exists(cache))
        self.assertTrue(os.path.isfile(source))

if __name__ == "__main__":
    unittest.main()
