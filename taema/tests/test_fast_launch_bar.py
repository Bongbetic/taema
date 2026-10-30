"""Contract: Python and Rust fast client agree on launch and bar (issue #72).

Python stays the fallback. bar output identical in every format.
launch behaves exactly like the Python path.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAST_BIN = os.environ.get(
    "TAEMA_FAST_BIN", os.path.join(ROOT, "rust", "target", "debug", "taema-fast")
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_bar import sample_status  # noqa: E402
from tests.test_phase3 import FakeDaemon  # noqa: E402


def run_rs(*args, sock=None, extra=None):
    env = dict(os.environ)
    if sock is not None:
        env["TAEMA_SOCKET"] = sock
    if extra:
        env.update(extra)
    return subprocess.run(
        [FAST_BIN, *args], env=env, capture_output=True, text=True, timeout=20
    )


_SAMPLE = object()


def run_py_bar(format_name, sock=None, follow=False, status=_SAMPLE):
    import taema.cli.commands as cli
    import types
    from tests.test_phase0 import make_cfg, tmp

    cfg = make_cfg(tmp())
    if sock is not None:
        cfg["paths"]["socket"] = sock
        cfg["paths"]["socket_fallback"] = sock
    args = types.SimpleNamespace(
        format=format_name,
        follow=follow,
        json=False,
        jsonl=False,
        socket=None,
        config=None,
    )
    reply = sample_status() if status is _SAMPLE else status
    with (
        mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
        mock.patch.object(cli, "ask", return_value=reply),
    ):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.cmd_bar(args)
    return rc, out.getvalue()


class BarOneShotParity(unittest.TestCase):
    def check_format(self, format_name):
        if not os.path.exists(FAST_BIN):
            self.skipTest("taema-fast not built")
        daemon = FakeDaemon(replies=lambda body: sample_status())
        self.addCleanup(daemon.close)
        py_rc, py_out = run_py_bar(format_name, daemon.path)
        rs = run_rs("bar", "--format", format_name, sock=daemon.path)
        self.assertEqual(rs.returncode, py_rc, format_name)
        self.assertEqual(rs.stdout, py_out, format_name)

    def test_plain(self):
        self.check_format("plain")

    def test_waybar(self):
        self.check_format("waybar")

    def test_i3bar(self):
        self.check_format("i3bar")

    def test_json(self):
        self.check_format("json")

    def test_daemon_down(self):
        if not os.path.exists(FAST_BIN):
            self.skipTest("taema-fast not built")
        py_rc, py_out = run_py_bar("plain", status=None)
        rs = run_rs("bar", "--socket", "/nonexistent/none.sock", "--format", "plain")
        self.assertEqual((rs.returncode, rs.stdout), (py_rc, py_out))
        # error model renders the daemon-unreachable line
        self.assertIn("tæma", rs.stdout + rs.stderr + py_out)


class BarFollowParity(unittest.TestCase):
    def test_follow_streams_identical_plain(self):
        if not os.path.exists(FAST_BIN):
            self.skipTest("taema-fast not built")
        import socket as _socket
        import threading

        first = sample_status()
        second = sample_status(reviews=3)

        def serve(path, status_calls):
            srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            try:
                srv.bind(path)
            except OSError:
                return
            srv.listen(8)
            srv.settimeout(2)
            end = __import__("time").monotonic() + 10
            while __import__("time").monotonic() < end:
                try:
                    conn, _ = srv.accept()
                except _socket.timeout:
                    break
                except OSError:
                    break
                with conn:
                    conn.settimeout(5)
                    buf = b""
                    while not buf.endswith(b"\n"):
                        try:
                            chunk = conn.recv(65536)
                        except _socket.timeout:
                            break
                        if not chunk:
                            break
                        buf += chunk
                    try:
                        msg = json.loads(buf or b"{}")
                    except ValueError:
                        continue
                    ident = msg.get("id", 1)
                    cmd = msg.get("cmd")
                    if cmd == "status":
                        status_calls.append(1)
                        result = first if len(status_calls) == 1 else second
                        reply = {"v": 2, "id": ident, "ok": True, "result": result}
                        try:
                            conn.sendall((json.dumps(reply) + "\n").encode())
                        except OSError:
                            pass
                    elif cmd == "subscribe":
                        lines = [
                            {"subscribed": True, "topics": ["status"], "since_seq": 1},
                            {"event": {"event": "review_created"}},
                            {"event": {"event": "review_created"}},
                        ]
                        try:
                            for item in lines:
                                reply = {
                                    "v": 2,
                                    "id": ident,
                                    "ok": True,
                                    "result": item,
                                }
                                conn.sendall((json.dumps(reply) + "\n").encode())
                                __import__("time").sleep(0.1)
                            # Hold briefly for re-queries, then close for EOF.
                            __import__("time").sleep(1.0)
                        except OSError:
                            pass
                    else:
                        reply = {"v": 2, "id": ident, "ok": True, "result": {}}
                        try:
                            conn.sendall((json.dumps(reply) + "\n").encode())
                        except OSError:
                            pass
            srv.close()

        def run_follow(sock_path, use_rs):
            if use_rs:
                proc = subprocess.run(
                    [
                        FAST_BIN,
                        "bar",
                        "--socket",
                        sock_path,
                        "--format",
                        "plain",
                        "--follow",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                return proc.returncode, proc.stdout
            import taema.cli.commands as cli
            import types
            from tests.test_phase0 import make_cfg, tmp

            cfg = make_cfg(tmp())
            cfg["paths"]["socket"] = sock_path
            cfg["paths"]["socket_fallback"] = sock_path
            args = types.SimpleNamespace(
                format="plain",
                follow=True,
                json=False,
                jsonl=False,
                socket=None,
                config=None,
            )
            with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = cli.cmd_bar(args)
            return rc, out.getvalue()

        for use_rs in (False, True):
            tmpdir = tempfile.mkdtemp()
            self.addCleanup(
                lambda d=tmpdir: __import__("shutil").rmtree(d, ignore_errors=True)
            )
            sock = os.path.join(tmpdir, "t.sock")
            calls: list = []
            thread = threading.Thread(target=serve, args=(sock, calls), daemon=True)
            thread.start()
            # Wait for the socket to appear.
            for _ in range(100):
                if os.path.exists(sock):
                    break
                __import__("time").sleep(0.02)
            rc, out = run_follow(sock, use_rs)
            thread.join(timeout=20)
            lines = out.splitlines()
            # Initial, one change, then the daemon-gone error.
            self.assertEqual(rc, 1, (use_rs, out))
            self.assertEqual(len(lines), 3, (use_rs, out))
            self.assertIn("\u27f22", lines[0], (use_rs, out))
            self.assertIn("\u27f23", lines[1], (use_rs, out))
            self.assertEqual(lines[2], "t\u00e6ma error", (use_rs, out))
            if use_rs:
                rs_out = out
            else:
                py_out = out
        self.assertEqual(rs_out, py_out)


class LaunchDryRunParity(unittest.TestCase):
    def test_dry_run_identical(self):
        if not os.path.exists(FAST_BIN):
            self.skipTest("taema-fast not built")
        import taema.cli.commands as cli
        import types
        from tests.test_phase0 import FakeCg, make_cfg, tmp

        with FakeCg() as fake:
            cfg = make_cfg(tmp())
            args = types.SimpleNamespace(
                app="x",
                unit=None,
                bind=False,
                dry_run=True,
                cmd=["true"],
                socket=None,
                config=None,
            )
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(cli.os, "execvp") as _ex,
            ):
                out = io.StringIO()
                with redirect_stdout(out):
                    py_rc = cli.cmd_launch(args)
                py_out = out.getvalue()
            rs = run_rs(
                "launch",
                "--dry-run",
                "--app",
                "x",
                "--",
                "true",
                extra={"TAEMA_CGROOT": fake.root},
            )
        self.assertEqual(rs.returncode, py_rc)
        self.assertEqual(rs.stdout, py_out)

    def test_bad_app_and_missing_command(self):
        if not os.path.exists(FAST_BIN):
            self.skipTest("taema-fast not built")
        for argv, py_args in (
            (
                ["launch", "--app", "../evil", "--", "true"],
                {"app": "../evil", "cmd": ["true"]},
            ),
            (["launch", "--app", "x"], {"app": "x", "cmd": []}),
        ):
            with self.subTest(argv=argv):
                import taema.cli.commands as cli
                import types
                from tests.test_phase0 import FakeCg, make_cfg, tmp

                with FakeCg():
                    cfg = make_cfg(tmp())
                    args = types.SimpleNamespace(
                        app=py_args["app"],
                        unit=None,
                        bind=False,
                        dry_run=False,
                        cmd=py_args["cmd"],
                        socket=None,
                        config=None,
                    )
                    with mock.patch.object(cli, "_load", return_value=(cfg, None, [])):
                        err = io.StringIO()
                        with mock.patch.object(sys, "stderr", err):
                            py_rc = cli.cmd_launch(args)
                rs = run_rs(*argv)
                self.assertEqual(rs.returncode, py_rc, argv)
                self.assertEqual(rs.returncode, 2, argv)


if __name__ == "__main__":
    unittest.main()
