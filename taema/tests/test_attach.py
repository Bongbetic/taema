import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_helper():
    path = os.path.join(ROOT, "libexec", "taema-attach")
    loader = importlib.machinery.SourceFileLoader("taema_attach_t", path)
    spec = importlib.util.spec_from_loader("taema_attach_t", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class AttachTests(unittest.TestCase):
    def setUp(self):
        self.h = load_helper()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_missing_config_refuses(self):
        missing = os.path.join(self.tmp.name, "nope.toml")
        with self.assertRaises(self.h.Refused):
            self.h.load_rules(missing)
        with mock.patch.object(self.h, "CONFIG", missing):
            with self.assertRaises(self.h.Refused):
                self.h.load_rules()

    def test_group_writable_config_refuses(self):
        p = os.path.join(self.tmp.name, "t.toml")
        with open(p, "w") as f:
            f.write('[protected]\ncomm = ["x"]\n')
        os.chmod(p, 0o664)
        with self.assertRaises(self.h.Refused):
            self.h.load_rules(p)

    def test_trusted_config_loads(self):
        p = os.path.join(self.tmp.name, "t.toml")
        with open(p, "w") as f:
            f.write('[protected]\ncomm = ["x"]\n')
        os.chmod(p, 0o644)
        st = os.stat(p)
        real = os.stat
        fake = mock.Mock(st_uid=0, st_mode=st.st_mode)
        with mock.patch.object(
            self.h.os, "stat", side_effect=lambda q: fake if q == p else real(q)
        ):
            self.assertEqual(self.h.load_rules(p), {"comm": ["x"]})

    def test_main_refuses_without_config(self):
        dest = os.path.join(self.tmp.name, "user", "1000", "scope-x")
        os.makedirs(dest)
        with (
            mock.patch.object(self.h, "CG", self.tmp.name),
            mock.patch.object(
                self.h, "CONFIG", os.path.join(self.tmp.name, "nope.toml")
            ),
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_UID": "1000"}),
            mock.patch.object(self.h.os, "stat", wraps=os.stat),
        ):
            with self.assertRaises(self.h.Refused) as cm:
                self.h.main(["move", "scope-x", "50"])
        self.assertIn("unavailable", str(cm.exception))

    def test_starttime_parser(self):
        stat = b"123 (we ) ird (name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20\n"
        # fields after ')': state=3 ... field 22 is index 19 of the remainder
        rest = stat.decode()[stat.decode().rindex(")") + 2 :].split()
        self.assertEqual(rest[19], "99")
        with mock.patch.object(self.h, "read_proc", return_value=stat):
            self.assertEqual(self.h.starttime(123), 99)
        self.assertIsInstance(self.h.starttime(os.getpid()), int)

    def test_pid_reuse_moves_back(self):
        h = self.h
        dest = os.path.join(self.tmp.name, "dest")
        cg = os.path.join(self.tmp.name, "src")
        os.makedirs(dest)
        os.makedirs(cg)
        starts = iter([10, 11])
        with (
            mock.patch.object(h, "CG", ""),
            mock.patch.object(
                h.os, "pidfd_open", return_value=os.open("/dev/null", os.O_RDONLY)
            ),
            mock.patch.object(h, "check_pid", return_value=("sleep", cg)),
            mock.patch.object(h, "starttime", side_effect=lambda p: next(starts)),
            mock.patch.object(h, "pid_uid", return_value=1000),
            mock.patch.object(h, "pidfd_gone", return_value=False),
            mock.patch.object(h, "log"),
        ):
            with self.assertRaises(h.Refused):
                h.move_one(50, 1000, "scope-x", dest, {})
        with open(cg + "/cgroup.procs") as f:
            self.assertEqual(f.read(), "50\n")

    def test_log_rotation(self):
        log = os.path.join(self.tmp.name, "d", "attach.log")
        os.makedirs(os.path.dirname(log))
        with open(log, "w") as f:
            f.write("x" * (self.h.LOG_MAX + 1))
        with mock.patch.object(self.h, "LOG", log):
            self.h.log("line")
        self.assertTrue(os.path.exists(log + ".1"))
        with open(log) as f:
            self.assertEqual(f.read(), "line\n")

    def test_log_small_not_rotated(self):
        log = os.path.join(self.tmp.name, "attach.log")
        with mock.patch.object(self.h, "LOG", log):
            self.h.log("a")
            self.h.log("b")
        self.assertFalse(os.path.exists(log + ".1"))
        with open(log) as f:
            self.assertEqual(f.read(), "a\nb\n")


if __name__ == "__main__":
    unittest.main()
