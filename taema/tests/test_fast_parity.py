"""Differential parity: the same inputs to libexec/taema-hook and taema-fast.

done/kill compare exit code, silence, and the request envelope the fake
daemon receives. ask drives both programs through identical pty sessions
against the same fake daemon and compares the full tty transcript.
prompt compares the cached-segment output. Run the strict p50 gate with
TAEMA_FAST_BIN pointing at the release binary.
"""

import fcntl
import json
import os
import pty
import select
import shutil
import statistics
import subprocess
import sys
import tempfile
import termios
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_phase3 import FakeDaemon, QUESTION  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "libexec", "taema-hook")
FAST_BIN = os.environ.get(
    "TAEMA_FAST_BIN", os.path.join(ROOT, "rust", "target", "debug", "taema-fast")
)


def run_py(*args, sock):
    env = dict(os.environ, TAEMA_SOCKET=sock)
    return subprocess.run([HOOK, *args], env=env, capture_output=True, timeout=20)


def run_rs(*args, sock, extra=None):
    env = dict(os.environ, TAEMA_SOCKET=sock)
    if extra:
        env.update(extra)
    return subprocess.run([FAST_BIN, *args], env=env, capture_output=True, timeout=20)


THREE_CANDIDATES = json.loads(json.dumps(QUESTION))
THREE_CANDIDATES["candidates"].append(
    {"id": 3, "kind": "historic", "key": "idea", "label": "idea"}
)


def replies_for(question):
    def replies(body):
        if body.get("cmd") == "ask":
            return {"question": question}
        return {"ok": True, "owner": "npm"}

    return replies


class SendParity(unittest.TestCase):
    """done/kill: same silence, same envelope."""

    def setUp(self):
        self.py = FakeDaemon()
        self.rs = FakeDaemon()
        self.addCleanup(self.py.close)
        self.addCleanup(self.rs.close)

    def check_same(self, args):
        r_py = run_py(*args, sock=self.py.path)
        r_rs = run_rs(*args, sock=self.rs.path)
        self.assertEqual(
            (r_py.returncode, r_py.stdout, r_py.stderr),
            (r_rs.returncode, r_rs.stdout, r_rs.stderr),
            args,
        )
        self.assertEqual(self.py.got, self.rs.got, args)
        py_ids = [e["id"] for e in self.py.envelopes]
        rs_ids = [e["id"] for e in self.rs.envelopes]
        self.assertEqual(py_ids, [1] * len(py_ids), args)
        self.assertEqual(rs_ids, [1] * len(rs_ids), args)

    def test_done(self):
        self.check_same(("done", "20", "20.3", "1", "npm"))

    def test_done_strips_and_caps_word(self):
        self.check_same(("done", "20", "20.3", "0", "a\x1b[2Jb" + "x" * 50))

    def test_done_without_word(self):
        self.check_same(("done", "20", "20.3", "0", ""))

    def test_done_failed_status_sends_anyway(self):
        self.check_same(("done", "99", "99.1", "137", "make"))

    def test_kill_word(self):
        self.check_same(("kill", "20", "pkill"))

    def test_kill_other_word_sends_nothing(self):
        self.check_same(("kill", "20", "rm"))

    def test_kill_default_shell_word(self):
        self.check_same(("kill", "20", "taema"))

    def test_garbage_arguments_exit_zero_silent(self):
        for args in (
            (),
            ("done",),
            ("done", "x", "y", "z"),
            ("ask", "notanumber"),
            ("bogus", "20"),
            ("done", "1", "1.1", "0", "x"),
            ("done", "0", "0.1", "0", "x"),
        ):
            with self.subTest(args=args):
                self.check_same(args)
        self.assertEqual(self.py.got, [])
        self.assertEqual(self.rs.got, [])

    def test_daemon_down_is_silent(self):
        for args in (
            ("done", "20", "20.1", "0", "x"),
            ("kill", "20", "kill"),
            ("ask", "20"),
        ):
            with self.subTest(args=args):
                r_py = run_py(*args, sock="/nonexistent/none.sock")
                r_rs = run_rs(*args, sock="/nonexistent/none.sock")
                self.assertEqual(
                    (r_py.returncode, r_py.stdout, r_py.stderr),
                    (r_rs.returncode, r_rs.stdout, r_rs.stderr),
                    args,
                )
                self.assertEqual(
                    (r_rs.returncode, r_rs.stdout, r_rs.stderr), (0, b"", b"")
                )


class PtySession:
    """One ask run with the pty slave as the controlling terminal."""

    def __init__(self, argv, sock, rdir):
        self.master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        env = dict(os.environ, TAEMA_SOCKET=sock, XDG_RUNTIME_DIR=rdir)

        def pre():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=subprocess.DEVNULL,
            env=env,
            preexec_fn=pre,
            close_fds=True,
        )
        os.close(slave)

    def read(self):
        try:
            return os.read(self.master, 4096)
        except OSError:
            return b""

    def read_until(self, needle, timeout=10.0):
        out, end = b"", time.time() + timeout
        while needle not in out and time.time() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                chunk = self.read()
                if not chunk:
                    break
                out += chunk
        return out

    def drain(self, wait=0.5):
        out, end = b"", time.time() + wait
        while time.time() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                chunk = self.read()
                if not chunk:
                    break
                out += chunk
                end = time.time() + 0.2
        return out

    def close(self):
        try:
            self.proc.wait(timeout=20)
        finally:
            os.close(self.master)


def ask_transcript(argv, daemon, keys, hello=b"[Enter]"):
    rdir = tempfile.mkdtemp()
    session = PtySession(argv, daemon.path, rdir)
    try:
        out = session.read_until(hello)
        for key in keys:
            time.sleep(0.2)
            os.write(session.master, key)
            time.sleep(0.2)
        out += session.drain()
        code = session.proc.wait(timeout=20)
    finally:
        session.close()
        shutil.rmtree(rdir, ignore_errors=True)
    return code, out


class AskParity(unittest.TestCase):
    """ask: identical tty transcripts for identical key scripts."""

    def run_both(self, question, keys):
        self.py = FakeDaemon(replies=replies_for(question))
        self.rs = FakeDaemon(replies=replies_for(question))
        self.addCleanup(self.py.close)
        self.addCleanup(self.rs.close)
        code_py, out_py = ask_transcript([HOOK, "ask", "20"], self.py, keys)
        code_rs, out_rs = ask_transcript([FAST_BIN, "ask", "20"], self.rs, keys)
        self.assertEqual(self.py.got, self.rs.got)
        return (code_py, out_py), (code_rs, out_rs)

    def check_same(self, question, keys):
        (code_py, out_py), (code_rs, out_rs) = self.run_both(question, keys)
        self.assertEqual(code_py, code_rs)
        self.assertEqual(code_py, 0)
        self.assertEqual(out_py, out_rs)
        return out_rs

    def test_answer_first_candidate(self):
        out = self.check_same(QUESTION, [b"1"])
        self.assertIn(b"will stop when npm closes", out)

    def test_answer_second_candidate(self):
        out = self.check_same(QUESTION, [b"2"])
        # the fake daemon answers owner npm, which wins for the message
        self.assertIn(b"will stop when npm closes", out)

    def test_standalone(self):
        out = self.check_same(QUESTION, [b"3"])
        self.assertIn(b"their own scope", out)

    def test_never(self):
        out = self.check_same(QUESTION, [b"4"])
        self.assertIn(b"will stop when", out)

    def test_later_key(self):
        out = self.check_same(QUESTION, [b"x"])
        self.assertIn(b"ask me later", out)

    def test_escape_key_asks_later(self):
        out = self.check_same(QUESTION, [b"\x1b"])
        self.assertIn(b"ask me later", out)

    def test_menu_then_owner(self):
        out = self.check_same(THREE_CANDIDATES, [b"2", b"1"])
        self.assertIn(b"which app?", out)
        self.assertIn(b"will stop when npm closes", out)

    def test_menu_then_later(self):
        out = self.check_same(THREE_CANDIDATES, [b"2", b"9"])
        self.assertIn(b"ask me later", out)

    def test_no_question_stays_silent(self):
        self.py = FakeDaemon(replies=lambda body: {})
        self.rs = FakeDaemon(replies=lambda body: {})
        self.addCleanup(self.py.close)
        self.addCleanup(self.rs.close)
        for argv, daemon in (
            ([HOOK, "ask", "20"], self.py),
            ([FAST_BIN, "ask", "20"], self.rs),
        ):
            rdir = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, rdir, True)
            session = PtySession(argv, daemon.path, rdir)
            try:
                out = session.drain()
                code = session.proc.wait(timeout=20)
            finally:
                session.close()
            self.assertEqual(code, 0)
            self.assertEqual(out, b"")
        self.assertEqual(self.py.got, self.rs.got)
        self.assertEqual(len(self.py.got), 1)

    def test_typeahead_stays_silent(self):
        for argv in ([HOOK, "ask", "20"], [FAST_BIN, "ask", "20"]):
            d = FakeDaemon(replies=replies_for(QUESTION))
            self.addCleanup(d.close)
            rdir = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, rdir, True)
            session = PtySession(argv, d.path, rdir)
            try:
                os.write(session.master, b"x")
                time.sleep(0.3)
                out = session.drain()
                code = session.proc.wait(timeout=20)
            finally:
                session.close()
            self.assertEqual(code, 0)
            self.assertEqual(out, b"")
            self.assertEqual(d.got, [])


class PromptParity(unittest.TestCase):
    def run_both(self, content):
        from taema.cli import framework

        rdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rdir, True)
        os.mkdir(os.path.join(rdir, "taema"))
        with open(os.path.join(rdir, "taema", "summary"), "w") as f:
            f.write(content)
        env = dict(os.environ, XDG_RUNTIME_DIR=rdir)
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": rdir}):
            with redirect_stdout(buf):
                code_py = framework._fast_prompt()
        out_py = buf.getvalue()
        r = subprocess.run(
            [FAST_BIN, "prompt"], env=env, capture_output=True, timeout=20
        )
        return (code_py, out_py), (r.returncode, r.stdout.decode())

    def test_prompt_matches(self):
        for content in (
            "tæma: idle (2 scopes)\n",
            "",
            "x" * 3000 + "\nsecond\n",
            "no trailing newline",
        ):
            with self.subTest(content=content[:20]):
                (code_py, out_py), (code_rs, out_rs) = self.run_both(content)
                self.assertEqual((code_py, out_py), (code_rs, out_rs))

    def test_prompt_missing_file_is_silent(self):
        rdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rdir, True)
        env = dict(os.environ, XDG_RUNTIME_DIR=rdir)
        r = subprocess.run(
            [FAST_BIN, "prompt"], env=env, capture_output=True, timeout=20
        )
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))


class PerfGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("WITHOUT_RUST"):
            raise unittest.SkipTest("WITHOUT_RUST=1 skips the p50 gate")
        cls.bin = os.environ.get("TAEMA_FAST_BIN")
        if cls.bin:
            return
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
                "--release",
                "--manifest-path",
                os.path.join(ROOT, "rust", "Cargo.toml"),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        if built.returncode != 0:
            raise AssertionError("cargo build --release failed:\n" + built.stderr)
        cls.bin = os.path.join(ROOT, "rust", "target", "release", "taema-fast")

    def p50(self, argv, env, runs=100):
        times = []
        for _ in range(runs):
            t = time.monotonic()
            r = subprocess.run(argv, env=env, capture_output=True, timeout=20)
            times.append((time.monotonic() - t) * 1000.0)
            self.assertEqual(r.returncode, 0)
        return statistics.median(times)

    def test_prompt_p50_under_5ms(self):
        rdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rdir, True)
        os.mkdir(os.path.join(rdir, "taema"))
        with open(os.path.join(rdir, "taema", "summary"), "w") as f:
            f.write("tæma: idle\n")
        env = dict(os.environ, XDG_RUNTIME_DIR=rdir)
        med = self.p50([self.bin, "prompt"], env)
        self.assertLess(med, 5.0, "prompt p50 %.2f ms" % med)

    def test_launch_dry_run_p50_under_30ms(self):
        cgr = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, cgr, True)
        os.makedirs(os.path.join(cgr, "user", str(os.getuid())), exist_ok=True)
        env = dict(os.environ, TAEMA_CGROOT=cgr)
        med = self.p50([self.bin, "launch", "--dry-run", "--", "true"], env)
        self.assertLess(med, 30.0, "launch p50 %.2f ms" % med)

    def test_done_down_p50_under_5ms(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, True)
        env = dict(
            os.environ,
            TAEMA_SOCKET="/nonexistent/none.sock",
            HOME=home,
        )
        if os.path.exists("/run/user/%d/taema.sock" % os.getuid()):
            raise unittest.SkipTest(
                "live daemon socket present: client-only latency not isolated"
            )
        med = self.p50([self.bin, "done", "20", "20.1", "0", "x"], env)
        self.assertLess(med, 5.0, "done-down p50 %.2f ms" % med)


if __name__ == "__main__":
    unittest.main()
