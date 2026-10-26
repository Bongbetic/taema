"""Differential parity: the same requests to the Python and Rust helpers.

Each case runs both helpers in identical fresh trees (separate temp dirs,
same pids) and compares exit code, stdout, stderr, and produced files.
Log timestamps and temp paths are normalized before comparison.

Cases marked code-only cover inputs where the Python helper crashes with a
traceback (non-ASCII digits, out-of-range pids): the Rust helper refuses
cleanly with the same exit code instead.
"""

import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_BIN = os.path.join(ROOT, "rust", "target", "debug", "taema-attach")


def load_helper():
    path = os.path.join(ROOT, "libexec", "taema-attach.py")
    loader = importlib.machinery.SourceFileLoader("taema_attach_p", path)
    spec = importlib.util.spec_from_loader("taema_attach_p", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def starttime_of(pid):
    with open("/proc/%d/stat" % pid) as f:
        raw = f.read()
    return int(raw[raw.rindex(")") + 2 :].split()[19])


def oom_of(pid):
    with open("/proc/%d/oom_score_adj" % pid) as f:
        return int(f.read().strip())


def cgroup_of(pid):
    with open("/proc/%d/cgroup" % pid) as f:
        for line in f:
            if line.startswith("0::"):
                return line[3:].strip()
    return ""


class Sides:
    """Fresh identical trees for the Python and Rust runs of one case."""

    def __init__(self, test):
        self.test = test
        self.stack = ExitStack()
        self.roots = {}
        for side in ("py", "rs"):
            tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
            self.roots[side] = tmp

    def close(self):
        self.stack.close()

    def paths(self, side):
        root = self.roots[side]
        uid = os.getuid()
        return {
            "root": root,
            "cg": os.path.join(root, "cg"),
            "config": os.path.join(root, "taema.toml"),
            "log": os.path.join(root, "log", "attach.log"),
            "oom": os.path.join(root, "oom"),
            "scope": os.path.join(root, "cg", "user", str(uid)),
        }

    def setup(self, build):
        for side in ("py", "rs"):
            build(self.paths(side))


class LoadRulesTests(unittest.TestCase):
    """The Python helper refuses mistyped [protected] rules like the Rust one."""

    def load(self, helper, text):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "taema.toml")
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o644)
        real_stat = os.stat

        def fake_stat(target, *args, **kwargs):
            info = real_stat(target, *args, **kwargs)
            if target == path:
                return SimpleNamespace(
                    st_uid=0, st_mode=info.st_mode, st_size=info.st_size
                )
            return info

        with mock.patch.object(os, "stat", side_effect=fake_stat):
            return helper.load_rules(path)

    def test_mistyped_protected_refuses(self):
        helper = load_helper()
        with self.assertRaises(helper.Refused) as caught:
            self.load(helper, "protected = 1\n")
        self.assertIn("invalid protected rules", str(caught.exception))

    def test_mistyped_rule_value_refuses(self):
        helper = load_helper()
        with self.assertRaises(helper.Refused):
            self.load(helper, "[protected]\ncomm = 1\n")

    def test_valid_rules_load(self):
        rules = self.load(load_helper(), '[protected]\ncomm = ["x"]\n')
        self.assertEqual(rules, {"comm": ["x"]})

    def test_bare_string_rule_loads(self):
        rules = self.load(load_helper(), '[protected]\ncomm = "x"\n')
        self.assertEqual(rules, {"comm": "x"})


class ParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()
        if os.environ.get("WITHOUT_RUST"):
            raise unittest.SkipTest("WITHOUT_RUST=1 skips the parity corpus")
        cargo = shutil.which("cargo")
        if cargo is None:
            raise unittest.SkipTest("cargo not available")
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = os.path.join(ROOT, "rust", "target")
        built = subprocess.run(
            [
                cargo,
                "build",
                "--locked",
                "--offline",
                "--manifest-path",
                os.path.join(ROOT, "rust", "Cargo.toml"),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        if built.returncode != 0:
            raise AssertionError("cargo build failed:\n" + built.stderr)
        cls.seen_messages = set()

    def run_python(self, argv, paths, sudo_uid):
        helper = self.helper
        root = paths["root"]
        # Root ownership is faked only where the helper requires it (config
        # and OOM state); scopes stay caller-owned and /proc stays real.
        oom = paths["oom"]
        trusted = (paths["config"], oom, root)
        real_stat, real_lstat, real_fstat = os.stat, os.lstat, os.fstat

        def needs_root(path):
            return isinstance(path, str) and (
                path in trusted or path.startswith(oom + os.sep)
            )

        def fake_namespace(info):
            return SimpleNamespace(
                st_uid=0,
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_nlink=info.st_nlink,
            )

        def fake_stat(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            return fake_namespace(info) if needs_root(path) else info

        def fake_lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            return fake_namespace(info) if needs_root(path) else info

        def fake_fstat(fd, *args, **kwargs):
            info = real_fstat(fd, *args, **kwargs)
            try:
                target = os.readlink("/proc/self/fd/%d" % fd)
            except OSError:
                return info
            return fake_namespace(info) if needs_root(target) else info

        out, err = io.StringIO(), io.StringIO()
        crashed = False
        with (
            mock.patch.object(helper, "CG", paths["cg"]),
            mock.patch.object(helper, "CONFIG", paths["config"]),
            mock.patch.object(helper, "LOG", paths["log"]),
            mock.patch.object(helper, "OOM_STATE_DIR", paths["oom"]),
            mock.patch.object(helper.os, "geteuid", return_value=0),
            mock.patch.object(helper.os, "stat", side_effect=fake_stat),
            mock.patch.object(helper.os, "lstat", side_effect=fake_lstat),
            mock.patch.object(helper.os, "fstat", side_effect=fake_fstat),
            mock.patch.dict(os.environ, {"SUDO_UID": sudo_uid}),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            try:
                code = helper.main(list(argv))
            except helper.Refused as error:
                print("taema-attach: %s" % error, file=sys.stderr)
                code = 1
            except Exception as error:
                # An uncaught traceback exits 1; the Rust side must refuse
                # with the same code. May depend on the machine (live pids).
                print("taema-attach: CRASH %s" % type(error).__name__, file=sys.stderr)
                code = 1
                crashed = True
        return code, out.getvalue(), err.getvalue(), crashed

    def run_rust(self, argv, paths, sudo_uid):
        env = dict(os.environ)
        env["TAEMA_ATTACH_TEST"] = "1"
        env["TAEMA_ATTACH_CG"] = paths["cg"]
        env["TAEMA_ATTACH_CONFIG"] = paths["config"]
        env["TAEMA_ATTACH_LOG"] = paths["log"]
        env["TAEMA_ATTACH_OOM_DIR"] = paths["oom"]
        if sudo_uid is None:
            env.pop("SUDO_UID", None)
        else:
            env["SUDO_UID"] = sudo_uid
        proc = subprocess.run(
            [RUST_BIN, *argv], capture_output=True, text=True, env=env, timeout=30
        )
        return proc.returncode, proc.stdout, proc.stderr

    def normalize(self, text, root):
        text = text.replace(root, "{T}")
        text = re.sub(r"(?m)^\d+(?= )", "T", text)
        # TOML diagnostics differ per parser; only the prefix is compared.
        text = re.sub(r"unreadable: .*", "unreadable: ...", text, flags=re.DOTALL)
        return text

    def snapshot(self, paths):
        """Log, rotated log, records, and moved-procs files, normalized."""
        found = {}
        root = paths["root"]
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if name == "taema.toml":
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                try:
                    with open(full, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                try:
                    text = data.decode("ascii")
                except UnicodeDecodeError:
                    text = repr(data)
                if rel.endswith(".log") or rel.endswith(".log.1"):
                    text = self.normalize(text, root)
                found[rel] = text
        return found

    def check(
        self,
        name,
        argv,
        build=None,
        sudo_uid=None,
        code_only=False,
        rust_sudo_uid="same",
    ):
        """Run one argv against both helpers and compare everything."""
        if sudo_uid is None:
            sudo_uid = str(os.getuid())
        if rust_sudo_uid == "same":
            rust_sudo_uid = sudo_uid
        sides = Sides(self)
        self.addCleanup(sides.close)
        if build is not None:
            sides.setup(build)
        py_paths, rs_paths = sides.paths("py"), sides.paths("rs")
        py_code, py_out, py_err, py_crashed = self.run_python(argv, py_paths, sudo_uid)
        rs_code, rs_out, rs_err = self.run_rust(argv, rs_paths, rust_sudo_uid)
        with self.subTest(case=name):
            self.assertEqual(rs_code, py_code)
            if code_only or py_crashed:
                return
            self.assertEqual(rs_out, py_out)
            self.assertEqual(
                self.normalize(rs_err, rs_paths["root"]),
                self.normalize(py_err, py_paths["root"]),
            )
            self.assertEqual(self.snapshot(rs_paths), self.snapshot(py_paths))
        self.record(py_err, py_paths["root"])

    def record(self, py_err, root):
        for line in py_err.splitlines():
            if line.startswith("taema-attach: "):
                self.seen_messages.add(self.normalize(line.split(": ", 1)[1], root))

    # -- builders ----------------------------------------------------------

    @staticmethod
    def write_config(paths, text="[protected]\n", mode=0o644):
        with open(paths["config"], "w") as f:
            f.write(text)
        os.chmod(paths["config"], mode)

    @staticmethod
    def make_scope(paths, rel):
        os.makedirs(os.path.join(paths["scope"], rel), exist_ok=True)

    @staticmethod
    def make_oom(paths, mode=0o700):
        os.makedirs(paths["oom"], mode=mode, exist_ok=True)
        os.chmod(paths["oom"], mode)

    def build_minimal(self, paths):
        self.write_config(paths)

    def build_scope(self, paths):
        self.write_config(paths)
        self.make_scope(paths, "scope-x")

    def build_oom(self, paths):
        self.write_config(paths)
        self.make_oom(paths)

    def write_record(self, paths, pid, start, original, applied, state=0, mode=0o600):
        self.make_oom(paths)
        record = {
            "uid": os.getuid(),
            "pid": pid,
            "start": start,
            "original": original,
            "applied": applied,
            "state": state,
        }
        path = os.path.join(paths["oom"], "%d-%d-%d.json" % (os.getuid(), pid, start))
        with open(path, "w") as f:
            f.write(json.dumps(record, separators=(",", ":")))
        os.chmod(path, mode)
        return path

    @staticmethod
    def gone_pid():
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        _, _status = os.waitpid(pid, 0)
        assert not os.path.exists("/proc/%d" % pid)
        return pid

    # -- argv validation ----------------------------------------------------

    def test_usage(self):
        for argv in (
            [],
            ["move"],
            ["attach"],
            ["bogus", "x"],
            ["attach", "1"],
            ["move", "rel"],
            ["oom-restore", "1", "2", "3"],
            ["attach", "1", "x", "extra"],
        ):
            self.check("usage %r" % (argv,), argv, self.build_minimal)

    def test_bad_name(self):
        for name in ("Bad-Name", "", "x" * 33, "a/b", "a.b", "-x", "UP"):
            self.check("bad name %r" % name, ["attach", "99", name], self.build_minimal)

    def test_bad_path(self):
        for rel in (
            "../x",
            "",
            "UPPER",
            "a//b",
            "/a",
            "a/",
            "a/./b",
            "x" * 98,
            "-a",
            "a b",
        ):
            self.check("bad path %r" % rel, ["move", rel, "99"], self.build_minimal)

    def test_oom_argv_shapes(self):
        cases = [
            (["oom-restore", "x", "1", "0", "0"], "bad target"),
            (["oom-restore", "42", "x", "0", "0"], "bad target"),
            (["oom-restore", "42", "1", "x", "0"], "bad value"),
            (["oom-restore", "42", "1", "0", "x"], "bad applied"),
            (["oom-restore", "1", "1", "0", "0"], "bad pid range"),
            (["oom-restore", "42", "0", "0", "0"], "bad start range"),
            (["oom-restore", "42", "1", "1001", "1001"], "bad value range"),
            (["oom-restore", "42", "1", "-1001", "0"], "bad value range"),
            (["oom-restore", "42", "1", "5", "4"], "bad applied range"),
            (["oom-restore", "42", "1", "0", "1001"], "bad applied range"),
            (["oom-record", "x", "1", "0", "1"], "bad target"),
            (["oom-record", "42", "1", "x", "1"], "bad value"),
            (["oom-record", "42", "1", "0", "x"], "bad value"),
            (["oom-record", "1", "1", "0", "1"], "bad pid range"),
            (["oom-record", "42", "1", "5", "5"], "bad equal values"),
            (["oom-record", "42", "1", "5", "4"], "bad equal values"),
            (["oom-record", "42", "1", "0", "1001"], "bad applied range"),
        ]
        for argv, label in cases:
            self.check("oom shape %s %r" % (label, argv), argv, self.build_oom)

    def test_crash_class_codes_match(self):
        pid = os.getpid()
        start = starttime_of(pid)
        cases = [
            ["move", "scope-x", "²"],
            ["move", "scope-x", "9" * 30],
            ["oom-restore", "9" * 30, str(start), "0", "0"],
        ]
        for argv in cases:
            self.check("crash %r" % (argv,), argv, self.build_scope, code_only=True)
        self.check(
            "unicode sudo",
            ["move", "scope-x", str(pid)],
            self.build_scope,
            sudo_uid="²",
            code_only=True,
        )

    # -- scope and config ---------------------------------------------------

    def test_missing_scope(self):
        self.check("missing scope", ["move", "scope-x", "99"], self.build_minimal)

    def test_scope_boundaries(self):
        self.check("97 rel ok", ["move", "a" * 97, "99"], self.build_minimal)
        self.check("32 name ok", ["attach", "99", "n" * 32], self.build_minimal)

    def test_scope_not_owned(self):
        def build(paths):
            self.write_config(paths)
            self.make_scope(paths, "scope-x")

        self.check("owned scope proceeds", ["move", "scope-x", "99"], build)
        # Owned by the real uid, but the caller claims another one.
        self.check(
            "foreign caller", ["move", "scope-x", "99"], build, sudo_uid="424242"
        )

    def test_symlink_scope(self):
        def build(paths):
            self.write_config(paths)
            target = os.path.join(paths["scope"], "real")
            os.makedirs(target, exist_ok=True)
            os.symlink(target, os.path.join(paths["scope"], "scope-x"))

        self.check("symlink scope", ["move", "scope-x", "99"], build)

    def test_missing_config(self):
        def build(paths):
            self.make_scope(paths, "scope-x")

        self.check("missing config", ["move", "scope-x", "99"], build)

    def test_bad_config(self):
        def writable(paths):
            self.write_config(paths, mode=0o664)
            self.make_scope(paths, "scope-x")

        def directory(paths):
            os.makedirs(paths["config"], exist_ok=True)
            self.make_scope(paths, "scope-x")

        def broken_toml(paths):
            self.write_config(paths, text="[protected\ncomm = [")
            self.make_scope(paths, "scope-x")

        def mistyped(paths):
            self.write_config(paths, text="protected = 1\n")
            self.make_scope(paths, "scope-x")

        self.check("writable config", ["move", "scope-x", "99"], writable)
        self.check("dir config", ["move", "scope-x", "99"], directory)
        self.check("broken toml", ["move", "scope-x", "99"], broken_toml)
        self.check("mistyped config", ["move", "scope-x", "99"], mistyped)

    def test_sudo_gate(self):
        self.check(
            "refuse uid 0", ["move", "scope-x", "99"], self.build_scope, sudo_uid="0"
        )
        self.check(
            "bad sudo", ["move", "scope-x", "99"], self.build_scope, sudo_uid="abc"
        )
        self.check(
            "default caller",
            ["move", "scope-x", "99"],
            self.build_scope,
            sudo_uid=str(os.getuid()),
            rust_sudo_uid=None,
        )

    # -- move and pid handling ------------------------------------------------

    def test_pid_edges(self):
        gone = self.gone_pid()
        self.check("bad pid text", ["move", "scope-x", "abc"], self.build_scope)
        self.check("pid zero", ["move", "scope-x", "0"], self.build_scope)
        self.check("pid one", ["move", "scope-x", "1"], self.build_scope)
        self.check("gone pid", ["move", "scope-x", str(gone)], self.build_scope)

    def test_foreign_pid(self):
        foreign = self.foreign_readable_pid()
        if foreign is None:
            self.skipTest("no readable foreign-uid pid")
        self.check("foreign pid", ["move", "scope-x", str(foreign)], self.build_scope)

    @staticmethod
    def foreign_readable_pid():
        me = os.getuid()
        for entry in sorted(os.listdir("/proc")):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                if os.stat("/proc/%d" % pid).st_uid == me:
                    continue
                for name in ("comm", "cgroup", "environ"):
                    with open("/proc/%d/%s" % (pid, name), "rb") as f:
                        f.read()
            except OSError:
                continue
            return pid
        return None

    def test_happy_move(self):
        pid = os.getpid()
        self.check("move self", ["move", "scope-x", str(pid)], self.build_scope)
        self.check("attach self", ["attach", str(pid), "x"], self.build_scope)

    def test_multi_pid_order(self):
        pid = os.getpid()
        gone = self.gone_pid()
        self.check(
            "ordered pids",
            ["move", "scope-x", str(pid), str(gone), str(pid)],
            self.build_scope,
        )
        # The first pid moves before the bad one refuses.
        self.check(
            "refusal after move", ["move", "scope-x", str(pid), "abc"], self.build_scope
        )

    @staticmethod
    def own_cgroup_is_session():
        cg = cgroup_of(os.getpid())
        return bool(re.fullmatch(r"/[0-9]+(/.*)?", cg)) or cg.startswith(
            "/user/%d/" % os.getuid()
        )

    def test_not_moved(self):
        if not self.own_cgroup_is_session():
            self.skipTest("test process is not in a session cgroup")

        def build(paths):
            self.write_config(paths)
            dest = os.path.join(paths["scope"], "scope-x")
            os.makedirs(paths["scope"], exist_ok=True)
            with open(dest, "w") as f:
                f.write("not a directory\n")

        self.check("dest is file", ["move", "scope-x", str(os.getpid())], build)

    def test_foreign_session_pid(self):
        pid = self.foreign_cgroup_pid()
        if pid is None:
            self.skipTest("no own-uid pid outside a session cgroup")
        self.check("foreign session", ["move", "scope-x", str(pid)], self.build_scope)

    @staticmethod
    def foreign_cgroup_pid():
        me = os.getuid()
        for entry in sorted(os.listdir("/proc")):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open("/proc/%d/cgroup" % pid) as f:
                    lines = f.read().splitlines()
                owner = os.stat("/proc/%d" % pid).st_uid
            except OSError:
                continue
            if owner != me:
                continue
            cg = next((l[3:].strip() for l in lines if l.startswith("0::")), "")
            if not re.fullmatch(r"/[0-9]+(/.*)?", cg) and not cg.startswith(
                "/user/%d/" % me
            ):
                return pid
        return None

    # -- protected rules --------------------------------------------------------

    def test_protected_comm(self):
        def star(paths):
            self.write_config(paths, text='[protected]\ncomm = ["*"]\n')
            self.make_scope(paths, "scope-x")

        def nomatch(paths):
            self.write_config(paths, text='[protected]\ncomm = ["zzz-no-match-*"]\n')
            self.make_scope(paths, "scope-x")

        def seq(paths):
            with open("/proc/%d/comm" % os.getpid()) as f:
                comm = f.read().strip()
            pattern = "[%sx]%s" % (comm[0], comm[1:])
            self.write_config(paths, text='[protected]\ncomm = ["%s"]\n' % pattern)
            self.make_scope(paths, "scope-x")

        def bare_string(paths):
            self.write_config(paths, text='[protected]\ncomm = "zzz"\n')
            self.make_scope(paths, "scope-x")

        pid = str(os.getpid())
        self.check("comm star", ["move", "scope-x", pid], star)
        self.check("comm nomatch", ["move", "scope-x", pid], nomatch)
        self.check("comm class", ["move", "scope-x", pid], seq)
        self.check("comm string", ["move", "scope-x", pid], bare_string)

    def test_protected_cgroup(self):
        cg = cgroup_of(os.getpid())

        def hit(paths):
            self.write_config(
                paths,
                text='[protected]\ncgroup_prefix = ["%s%s"]\n' % (paths["cg"], cg),
            )
            self.make_scope(paths, "scope-x")

        def miss(paths):
            self.write_config(
                paths, text='[protected]\ncgroup_prefix = ["%s/nope"]\n' % paths["cg"]
            )
            self.make_scope(paths, "scope-x")

        pid = str(os.getpid())
        self.check("cgroup hit", ["move", "scope-x", pid], hit)
        self.check("cgroup miss", ["move", "scope-x", pid], miss)

    def test_protected_env(self):
        home = os.environ.get("HOME", "")

        def hit(paths):
            self.write_config(
                paths, text='[protected.env_prefix]\nHOME = ["%s"]\n' % home
            )
            self.make_scope(paths, "scope-x")

        def miss(paths):
            self.write_config(
                paths, text='[protected.env_prefix]\nHOME = ["/definitely/not/home"]\n'
            )
            self.make_scope(paths, "scope-x")

        pid = str(os.getpid())
        self.check("env hit", ["move", "scope-x", pid], hit)
        self.check("env miss", ["move", "scope-x", pid], miss)

    # -- OOM flows --------------------------------------------------------------

    def test_oom_not_recorded(self):
        pid = os.getpid()
        start = starttime_of(pid)
        self.check(
            "restore unrecorded",
            ["oom-restore", str(pid), str(start), "0", "100"],
            self.build_oom,
        )

    def test_oom_gone_pid(self):
        gone = self.gone_pid()
        self.check(
            "record gone pid",
            ["oom-record", str(gone), "12345", "0", "100"],
            self.build_oom,
        )
        self.check(
            "restore gone pid",
            ["oom-restore", str(gone), "12345", "0", "100"],
            self.build_oom,
        )

    def test_oom_identity(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 100 if live + 100 <= 1000 else 1000

        def build(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)

        self.check(
            "wrong start",
            ["oom-restore", str(pid), str(start + 1), str(live), str(applied)],
            build,
        )
        self.check(
            "huge start",
            ["oom-record", str(pid), str(10**30), str(live), str(applied)],
            build,
        )

    def test_oom_record_happy(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 100 if live + 100 <= 1000 else 1000
        if applied <= live:
            self.skipTest("live OOM score already at the ceiling")
        self.check(
            "record happy",
            ["oom-record", str(pid), str(start), str(live), str(applied)],
            self.build_oom,
        )

    def test_oom_record_original_mismatch(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        other = live + 50 if live + 50 <= 999 else live - 50
        self.check(
            "record mismatch",
            ["oom-record", str(pid), str(start), str(other), str(other + 1)],
            self.build_oom,
        )

    def test_oom_record_conflict(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 100 if live + 100 <= 1000 else 1000

        def build(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)

        other = live + 10 if live + 10 < applied else live - 10
        self.check(
            "record conflict",
            ["oom-record", str(pid), str(start), str(other), str(applied)],
            build,
        )

    def test_oom_record_update(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        first, second = live + 100, live + 200
        if second > 1000:
            self.skipTest("live OOM score too close to the ceiling")

        def build(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, first)

        # Same original while current is still original: applied is updated.
        self.check(
            "record update",
            ["oom-record", str(pid), str(start), str(live), str(second)],
            build,
        )

    def test_oom_restore_early_return(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 100 if live + 100 <= 1000 else 1000

        def build(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)

        self.check(
            "restore no-op",
            ["oom-restore", str(pid), str(start), str(live), str(applied)],
            build,
        )

    def test_oom_restore_mismatches(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 100 if live + 100 <= 1000 else 1000

        def build(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)

        other = live + 10 if live + 10 < applied else live - 10
        self.check(
            "restore value mismatch",
            ["oom-restore", str(pid), str(start), str(other), str(applied)],
            build,
        )
        self.check(
            "restore applied mismatch",
            ["oom-restore", str(pid), str(start), str(live), str(applied - 1)],
            build,
        )

    def test_oom_restore_states(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        if live - 50 < -1000:
            self.skipTest("no room below the live OOM score")
        original, applied = live - 50, live - 40

        def done(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, original, live, state=1)

        def current_differs(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, original, applied, state=0)

        self.check(
            "restore completed",
            ["oom-restore", str(pid), str(start), str(original), str(live)],
            done,
        )
        self.check(
            "restore current differs",
            ["oom-restore", str(pid), str(start), str(original), str(applied)],
            current_differs,
        )

    def test_oom_restore_write_path(self):
        # current == applied != original forces the write: EACCES for an
        # unprivileged caller, success as root. Each side crafts its record
        # from the live score at its own runtime, so a root run mutating the
        # score cannot skew the other side.
        pid = os.getpid()
        sides = Sides(self)
        self.addCleanup(sides.close)
        results = {}
        for side in ("py", "rs"):
            paths = sides.paths(side)
            self.build_oom(paths)
            live = oom_of(pid)
            if live - 50 < -1000:
                self.skipTest("no room below the live OOM score")
            other = live - 50
            self.write_record(paths, pid, starttime_of(pid), other, live, state=0)
            argv = [
                "oom-restore",
                str(pid),
                str(starttime_of(pid)),
                str(other),
                str(live),
            ]
            if side == "py":
                code, out, err, _crashed = self.run_python(
                    argv, paths, str(os.getuid())
                )
            else:
                code, out, err = self.run_rust(argv, paths, str(os.getuid()))
            results[side] = (code, out, err, self.snapshot(paths), paths["root"])
        py, rs = results["py"], results["rs"]
        self.assertEqual(rs[0], py[0])
        self.assertEqual(rs[1], py[1])
        self.assertEqual(self.normalize(rs[2], rs[4]), self.normalize(py[2], py[4]))
        self.record(py[2], py[4])

        def mask_scores(text):
            text = re.sub(r"oom_score_adj=-?\d+(->-?\d+)?", "oom_score_adj=N", text)
            return re.sub(r'"(original|applied)":-?\d+', r'"\1":N', text)

        self.assertEqual(
            {k: mask_scores(v) for k, v in rs[3].items()},
            {k: mask_scores(v) for k, v in py[3].items()},
        )

    def test_oom_bad_records(self):
        pid = os.getpid()
        start = starttime_of(pid)
        live = oom_of(pid)
        applied = live + 1

        def record_path(paths):
            return os.path.join(
                paths["oom"], "%d-%d-%d.json" % (os.getuid(), pid, start)
            )

        def garbage(paths):
            self.build_oom(paths)
            with open(record_path(paths), "w") as f:
                f.write("{not json")
            os.chmod(record_path(paths), 0o600)

        def oversized(paths):
            self.build_oom(paths)
            with open(record_path(paths), "w") as f:
                f.write('"x"' + " " * 5000)
            os.chmod(record_path(paths), 0o600)

        def wrong_identity(paths):
            self.build_oom(paths)
            path = record_path(paths)
            with open(path, "w") as f:
                f.write(
                    json.dumps(
                        {
                            "uid": os.getuid(),
                            "pid": pid,
                            "start": start + 1,
                            "original": live,
                            "applied": applied,
                            "state": 0,
                        },
                        separators=(",", ":"),
                    )
                )
            os.chmod(path, 0o600)

        def bad_values(paths):
            self.build_oom(paths)
            path = record_path(paths)
            with open(path, "w") as f:
                f.write(
                    json.dumps(
                        {
                            "uid": os.getuid(),
                            "pid": pid,
                            "start": start,
                            "original": live,
                            "applied": live - 1,
                            "state": 0,
                        },
                        separators=(",", ":"),
                    )
                )
            os.chmod(path, 0o600)

        def world_readable(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)
            os.chmod(record_path(paths), 0o644)

        def symlink(paths):
            self.build_oom(paths)
            target = record_path(paths) + ".real"
            with open(target, "w") as f:
                f.write("{}")
            os.symlink(target, record_path(paths))

        def no_access(paths):
            self.build_oom(paths)
            self.write_record(paths, pid, start, live, applied)
            os.chmod(record_path(paths), 0)

        argv = ["oom-record", str(pid), str(start), str(live), str(applied)]
        self.check("record garbage", argv, garbage)
        self.check("record oversized", argv, oversized)
        self.check("record identity", argv, wrong_identity)
        self.check("record values", argv, bad_values)
        self.check("record perms", argv, world_readable)
        self.check("record symlink", argv, symlink)
        self.check("record no access", argv, no_access)

    def test_oom_untrusted_dirs(self):
        pid = os.getpid()
        start = starttime_of(pid)

        def open_parent(paths):
            self.write_config(paths)
            parent = os.path.join(paths["root"], "open")
            os.makedirs(parent, exist_ok=True)
            os.chmod(parent, 0o775)
            paths["oom"] = os.path.join(parent, "oom")

        def open_dir(paths):
            self.write_config(paths)
            self.make_oom(paths, mode=0o755)

        argv = ["oom-restore", str(pid), str(start), "0", "100"]
        for name, build in (("open parent", open_parent), ("open dir", open_dir)):
            sides = Sides(self)
            self.addCleanup(sides.close)
            per_side = {}
            for side in ("py", "rs"):
                paths = sides.paths(side)
                build(paths)
                per_side[side] = paths
            py_paths, rs_paths = per_side["py"], per_side["rs"]
            with self.subTest(case=name):
                py = self.run_python(argv, py_paths, str(os.getuid()))
                rs = self.run_rust(argv, rs_paths, str(os.getuid()))
                self.assertEqual(rs[0], py[0])
                self.assertEqual(
                    self.normalize(rs[2], rs_paths["root"]),
                    self.normalize(py[2], py_paths["root"]),
                )
            self.record(py[2], py_paths["root"])

    # -- logs ------------------------------------------------------------------

    def test_log_rotation(self):
        def build(paths):
            self.write_config(paths)
            self.make_scope(paths, "scope-x")
            os.makedirs(os.path.dirname(paths["log"]), exist_ok=True)
            with open(paths["log"], "w") as f:
                f.write("x" * (2**20 + 8))

        self.check("rotate log", ["move", "scope-x", str(os.getpid())], build)

    def test_zz9_refusal_catalog_is_covered(self):
        # Runs last alphabetically: every reachable refusal message must have
        # appeared in the corpus above. Deliberately not covered: messages
        # unreachable through the CLI (bad pid %d, restore-would-lower,
        # invalid restore/record target, too many records, unopenable OOM
        # target, short OOM write, un-updatable record, un-creatable record,
        # un-recordable OOM priority), racy identity messages (changed owner,
        # exited or replaced during the move), and the crash-class mappings.
        catalog = [
            "usage: taema-attach",
            "run through sudo",
            "refusing uid 0",
            "bad OOM priority target",
            "bad OOM priority value",
            "bad applied OOM priority value",
            "bad OOM priority target or value",
            "bad OOM priority record target",
            "bad OOM priority record value",
            "bad OOM priority record target or values",
            "bad name",
            "bad path",
            "no such scope: ",
            "scope not owned by uid ",
            "bad pid",
            "gone, skipped",
            "is protected",
            "is in protected cgroup ",
            "has protected ",
            "must be a regular file owned by root",
            "unreadable: ...",
            "unavailable: ",
            "OOM priority target is gone",
            "OOM priority target changed identity",
            "OOM priority restore was not recorded",
            "OOM priority value was not recorded",
            "applied OOM priority was not recorded",
            "OOM priority restoration was already completed",
            "current OOM priority is not the recorded value",
            "could not restore OOM priority: ",
            "conflicting OOM priority record exists",
            "OOM priority original does not match the live value",
            "OOM restoration record is too large",
            "could not read OOM restoration record",
            "OOM restoration record identity is invalid",
            "OOM restoration record values are invalid",
            "OOM restoration record is not a private root-owned file",
            "could not open OOM restoration record: ",
            "OOM record parent is not a trusted root directory",
            "OOM record directory must be root-owned and mode 0700",
            "pidfd_open(0) failed: ",
        ]
        # The not-moved refusal needs the test process itself inside a
        # session cgroup, which container runners lack.
        if self.own_cgroup_is_session():
            catalog.append("not moved: ")
        # The login-session refusal needs an own-uid pid outside a session
        # cgroup, which some machines lack.
        if self.foreign_cgroup_pid() is not None:
            catalog.append("only login-session and own scopes may be moved")
        # The ownership refusal needs a readable foreign-uid pid; locked-down
        # kernels hide every foreign environ.
        if self.foreign_readable_pid() is not None:
            catalog.append("is not owned by uid ")
        missing = [
            template
            for template in catalog
            if not any(template in seen for seen in self.seen_messages)
        ]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
