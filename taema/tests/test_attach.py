import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_helper():
    path = os.path.join(ROOT, "libexec", "taema-attach.py")
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
        uid = str(os.getuid() or 1000)
        dest = os.path.join(self.tmp.name, "user", uid, "scope-x")
        os.makedirs(dest)
        if os.getuid() == 0:
            os.chown(dest, 1000, -1)
        with (
            mock.patch.object(self.h, "CG", self.tmp.name),
            mock.patch.object(
                self.h, "CONFIG", os.path.join(self.tmp.name, "nope.toml")
            ),
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_UID": uid}),
            mock.patch.object(self.h.os, "stat", wraps=os.stat),
        ):
            with self.assertRaises(self.h.Refused) as cm:
                self.h.main(["move", "scope-x", "50"])
        self.assertIn("unavailable", str(cm.exception))

    def test_main_dispatches_oom_restore_with_starttime(self):
        with (
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_UID": "1000"}),
            mock.patch.object(self.h, "restore_oom") as restore_oom,
        ):
            self.assertEqual(
                self.h.main(["oom-restore", "42", "987", "-200", "500"]), 0
            )
        restore_oom.assert_called_once_with(42, 1000, 987, -200, 500)

    def test_main_rejects_invalid_oom_restore_arguments(self):
        with (
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_UID": "1000"}),
            mock.patch.object(self.h, "restore_oom") as restore_oom,
        ):
            with self.assertRaises(self.h.Refused):
                self.h.main(["oom-restore", "42", "987", "1001", "1000"])
        restore_oom.assert_not_called()

    def test_main_dispatches_oom_record(self):
        with (
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_UID": "1000"}),
            mock.patch.object(self.h, "record_oom") as record_oom,
        ):
            self.assertEqual(self.h.main(["oom-record", "42", "987", "-200", "500"]), 0)
        record_oom.assert_called_once_with(42, 1000, 987, -200, 500)

    def test_helper_refuses_untrusted_record_files_and_directories(self):
        path = os.path.join(self.tmp.name, "untrusted.json")
        with open(path, "w", encoding="ascii") as target:
            target.write("{}")
        os.chmod(path, 0o644)
        fd = os.open(path, os.O_RDONLY)
        try:
            with self.assertRaises(self.h.Refused):
                self.h._validate_oom_record_fd(fd)
        finally:
            os.close(fd)

        state_dir = os.path.join(self.tmp.name, "state")
        os.mkdir(state_dir, 0o755)
        with mock.patch.object(self.h, "OOM_STATE_DIR", state_dir):
            with self.assertRaises(self.h.Refused):
                self.h.oom_state_dir()

    def _write_oom_record(self, directory, **overrides):
        record = {
            "uid": 1000,
            "pid": 42,
            "start": 987,
            "original": -200,
            "applied": 500,
            "state": 0,
        }
        record.update(overrides)
        path = os.path.join(directory, "1000-42-987.json")
        with open(path, "w", encoding="ascii") as target:
            json.dump(record, target, separators=(",", ":"))
        os.chmod(path, 0o600)
        return path

    def _patch_oom_process(self, target, score_values):
        real_open = os.open

        def open_path(path, flags, *args, **kwargs):
            if path == "/proc/42/oom_score_adj":
                path = target
            return real_open(path, flags, *args, **kwargs)

        return (
            mock.patch.object(
                self.h.os,
                "pidfd_open",
                side_effect=lambda _pid: real_open("/dev/null", os.O_RDONLY),
            ),
            mock.patch.object(self.h.os, "open", side_effect=open_path),
            mock.patch.object(self.h, "oom_state_dir", return_value=self.tmp.name),
            mock.patch.object(self.h, "_validate_oom_record_fd"),
            mock.patch.object(self.h, "pid_uid", return_value=1000),
            mock.patch.object(self.h, "starttime", return_value=987),
            mock.patch.object(self.h, "pidfd_gone", return_value=False),
            mock.patch.object(self.h, "read_oom_score", side_effect=score_values),
            mock.patch.object(self.h, "log"),
        )

    @contextmanager
    def _patched_oom_process(self, target, score_values):
        with ExitStack() as stack:
            for patcher in self._patch_oom_process(target, score_values):
                stack.enter_context(patcher)
            yield

    def test_restore_oom_checks_record_identity_and_restores_idempotently(self):
        target = os.path.join(self.tmp.name, "oom_score_adj")
        with open(target, "w", encoding="ascii"):
            pass
        record_path = self._write_oom_record(self.tmp.name)
        with self._patched_oom_process(target, [500, -200]):
            self.h.restore_oom(42, 1000, 987, -200, 500)
            self.h.restore_oom(42, 1000, 987, -200, 500)
        with open(target, encoding="ascii") as source:
            self.assertEqual(source.read(), "-200\n")
        with open(record_path, encoding="ascii") as source:
            self.assertEqual(json.load(source)["state"], 1)

    def test_restore_oom_refuses_wrong_uid_and_reused_pid(self):
        self._write_oom_record(self.tmp.name)
        real_open = os.open
        with (
            mock.patch.object(
                self.h.os,
                "pidfd_open",
                side_effect=lambda _pid: real_open("/dev/null", os.O_RDONLY),
            ),
            mock.patch.object(self.h, "oom_state_dir", return_value=self.tmp.name),
            mock.patch.object(self.h, "_validate_oom_record_fd"),
            mock.patch.object(self.h, "pid_uid", return_value=1000),
            mock.patch.object(self.h, "starttime", return_value=988),
        ):
            with self.assertRaises(self.h.Refused):
                self.h.restore_oom(42, 1000, 987, -200, 500)
        with (
            mock.patch.object(
                self.h.os,
                "pidfd_open",
                side_effect=lambda _pid: real_open("/dev/null", os.O_RDONLY),
            ),
            mock.patch.object(self.h, "pid_uid", return_value=1001),
            mock.patch.object(self.h, "starttime", return_value=987),
        ):
            with self.assertRaises(self.h.Refused):
                self.h.restore_oom(42, 1000, 987, -200, 500)

    def test_restore_oom_refuses_invalid_targets_and_exited_pidfds(self):
        with mock.patch.object(self.h.os, "pidfd_open") as open_pid:
            for args in (
                (1, 1000, 987, -200, 500),
                (42, 0, 987, -200, 500),
                (42, 1000, 0, -200, 500),
                (42, 1000, 987, True, 500),
                (42, 1000, 987, -200, 1001),
            ):
                with self.subTest(args=args), self.assertRaises(self.h.Refused):
                    self.h.restore_oom(*args)
        open_pid.assert_not_called()

        target = os.path.join(self.tmp.name, "oom_score_adj")
        with open(target, "w", encoding="ascii"):
            pass
        self._write_oom_record(self.tmp.name)
        with (
            self._patched_oom_process(target, [500]),
            mock.patch.object(self.h, "pidfd_gone", return_value=True),
        ):
            with self.assertRaisesRegex(self.h.Refused, "changed identity"):
                self.h.restore_oom(42, 1000, 987, -200, 500)

    def test_restore_oom_refuses_unrecorded_values_and_unexpected_current_score(self):
        target = os.path.join(self.tmp.name, "oom_score_adj")
        self._write_oom_record(self.tmp.name)
        for value, applied in ((-300, 500), (-200, 400)):
            with self._patched_oom_process(target, [500]):
                with self.assertRaises(self.h.Refused):
                    self.h.restore_oom(42, 1000, 987, value, applied)
        with self._patched_oom_process(target, [300]):
            with self.assertRaises(self.h.Refused):
                self.h.restore_oom(42, 1000, 987, -200, 500)

    def test_restore_oom_refuses_missing_or_corrupt_records(self):
        target = os.path.join(self.tmp.name, "oom_score_adj")
        with self._patched_oom_process(target, [500]):
            with self.assertRaises(self.h.Refused):
                self.h.restore_oom(42, 1000, 987, -200, 500)
        path = os.path.join(self.tmp.name, "1000-42-987.json")
        with open(path, "w", encoding="ascii") as target_file:
            target_file.write("{")
        with self._patched_oom_process(target, [500]):
            with self.assertRaises(self.h.Refused):
                self.h.restore_oom(42, 1000, 987, -200, 500)

    def test_record_oom_seals_only_a_live_original_value(self):
        target = os.path.join(self.tmp.name, "oom_score_adj")
        with open(target, "w", encoding="ascii"):
            pass
        real_open = os.open
        with (
            mock.patch.object(
                self.h.os,
                "pidfd_open",
                side_effect=lambda _pid: real_open("/dev/null", os.O_RDONLY),
            ),
            mock.patch.object(self.h, "oom_state_dir", return_value=self.tmp.name),
            mock.patch.object(self.h, "_validate_oom_record_fd"),
            mock.patch.object(self.h, "_prune_oom_records", return_value=0),
            mock.patch.object(self.h, "pid_uid", return_value=1000),
            mock.patch.object(self.h, "starttime", return_value=987),
            mock.patch.object(self.h, "pidfd_gone", return_value=False),
            mock.patch.object(self.h, "read_oom_score", return_value=-200),
            mock.patch.object(self.h, "log"),
        ):
            self.h.record_oom(42, 1000, 987, -200, 500)
            self.h.record_oom(42, 1000, 987, -200, 500)
        with open(
            os.path.join(self.tmp.name, "1000-42-987.json"), encoding="ascii"
        ) as source:
            self.assertEqual(
                json.load(source),
                {
                    "uid": 1000,
                    "pid": 42,
                    "start": 987,
                    "original": -200,
                    "applied": 500,
                    "state": 0,
                },
            )
        with (
            mock.patch.object(
                self.h.os,
                "pidfd_open",
                side_effect=lambda _pid: real_open("/dev/null", os.O_RDONLY),
            ),
            mock.patch.object(self.h, "oom_state_dir", return_value=self.tmp.name),
            mock.patch.object(self.h, "_validate_oom_record_fd"),
            mock.patch.object(self.h, "pid_uid", return_value=1000),
            mock.patch.object(self.h, "starttime", return_value=987),
            mock.patch.object(self.h, "read_oom_score", return_value=-100),
        ):
            with self.assertRaises(self.h.Refused):
                self.h.record_oom(42, 1000, 987, -200, 500)

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
