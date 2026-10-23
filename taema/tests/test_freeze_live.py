"""Opt-in live acceptance test for waking a frozen HTTP listener."""

import http.client
import math
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from taema.core import cgroup
from taema.daemon import service
from tests.test_phase0 import make_cfg


def _move_http_server(pid, scope_path):
    """Use the delegated write first, with the VM's root helper as a fallback."""
    try:
        return cgroup.move(pid, scope_path)
    except PermissionError:
        result = subprocess.run(
            ["sudo", "-n", "tee", os.path.join(scope_path, "cgroup.procs")],
            input="%d\n" % pid,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            detail = (result.stderr or "").strip()
            raise PermissionError(detail or "privileged cgroup move failed")
        return True


class CgroupMoveTests(unittest.TestCase):
    def test_http_scope_move_falls_back_to_privileged_cgroup_write(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(cgroup, "move", side_effect=PermissionError("denied")):
            with mock.patch.object(
                cgroup, "base", return_value="/sys/fs/cgroup/user/1000"
            ):
                with mock.patch.object(
                    subprocess, "run", return_value=completed
                ) as run:
                    self.assertTrue(
                        _move_http_server(123, "/sys/fs/cgroup/user/1000/leftover/test")
                    )

        run.assert_called_once_with(
            [
                "sudo",
                "-n",
                "tee",
                "/sys/fs/cgroup/user/1000/leftover/test/cgroup.procs",
            ],
            input="123\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_http_scope_move_keeps_delegated_direct_write(self):
        with mock.patch.object(cgroup, "move", return_value=True):
            with mock.patch.object(subprocess, "run") as run:
                self.assertTrue(_move_http_server(123, "/cgroup/test"))
        run.assert_not_called()


@unittest.skipUnless(
    os.environ.get("TAEMA_LIVE_FREEZE_TEST") == "1",
    "set TAEMA_LIVE_FREEZE_TEST=1 in a delegated writable cgroup-v2 sandbox",
)
class LiveListenerWakeTests(unittest.TestCase):
    """Exercise real ss queues, cgroup.freeze, and an HTTP request end to end."""

    trials = 10

    def setUp(self):
        self.server = None
        self.daemon = None
        self.scope_path = None
        self.parent_path = os.path.join(cgroup.base(), "leftover")
        self.created_parent = not os.path.exists(self.parent_path)
        try:
            os.makedirs(self.parent_path, exist_ok=True)
            self.scope = "leftover/taema_live_http_%d" % os.getpid()
            self.scope_path = os.path.join(cgroup.base(), self.scope)
            os.mkdir(self.scope_path)
        except OSError as error:
            self.skipTest("cannot create a disposable delegated cgroup: %s" % error)
        freeze_path = os.path.join(self.scope_path, "cgroup.freeze")
        if not os.path.isfile(freeze_path) or not os.access(freeze_path, os.W_OK):
            self.skipTest("the delegated cgroup has no writable cgroup.freeze control")
        self.temporary = tempfile.TemporaryDirectory(prefix="taema-freeze-http-")
        self.addCleanup(self.temporary.cleanup)

    def tearDown(self):
        if self.scope_path and os.path.exists(self.scope_path):
            try:
                with open(
                    os.path.join(self.scope_path, "cgroup.freeze"), "w"
                ) as target:
                    target.write("0\n")
            except OSError:
                pass
        if self.server is not None and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=2)
        if self.daemon is not None:
            self.daemon.sel.close()
        if self.scope_path and os.path.exists(self.scope_path):
            try:
                os.rmdir(self.scope_path)
            except OSError:
                pass
        if self.created_parent and os.path.isdir(self.parent_path):
            try:
                os.rmdir(self.parent_path)
            except OSError:
                pass

    def _wait_until_frozen(self):
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                with open(os.path.join(self.scope_path, "cgroup.events")) as source:
                    if "frozen 1" in source.read().splitlines():
                        return
            except OSError:
                break
            time.sleep(0.01)
        self.fail("kernel did not report the HTTP scope frozen")

    def _start_http_server(self, directory):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "http.server",
                str(port),
                "--bind",
                "127.0.0.1",
                "--directory",
                directory,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("python3 -m http.server exited during startup")
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                connection.request("GET", "/")
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 200:
                    return port
            except OSError:
                time.sleep(0.05)
        self.fail("python3 -m http.server did not become ready")

    @staticmethod
    def _issue_request(port, completed, sent):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=6.0)
        started = time.monotonic()
        try:
            connection.connect()
            connection.putrequest("GET", "/")
            connection.endheaders()
            sent.set()
            response = connection.getresponse()
            body = response.read()
            completed.put((response.status, body, time.monotonic() - started))
        except Exception as error:
            sent.set()
            completed.put((None, error, time.monotonic() - started))
        finally:
            connection.close()

    def test_http_request_thaws_listener_with_p95_under_three_seconds(self):
        directory = self.temporary.name
        with open(
            os.path.join(directory, "index.html"), "w", encoding="utf-8"
        ) as target:
            target.write("wake-on-connect\n")
        port = self._start_http_server(directory)

        if not _move_http_server(self.server.pid, self.scope_path):
            self.skipTest("HTTP server exited before cgroup placement")
        self.assertIn(self.server.pid, cgroup.tree_procs(self.scope_path))

        cfg = make_cfg(
            os.path.join(directory, "state"),
            mode="enforce",
            freeze={
                "enabled": True,
                "adopt": False,
                "after": 0,
                "wake_on_connect": True,
                "max_frozen": 16,
                "cpu_idle_max": 0.5,
            },
            experimental={"freeze": True},
            protected={"comm": [], "cgroup_prefix": [], "env_prefix": {}},
            mem={"enabled": False},
        )
        self.daemon = service.Daemon(cfg)
        latencies = []

        for _ in range(self.trials):
            cursor = self.daemon.store.events_since(0)["latest_seq"]
            frozen = self.daemon.freeze_scope(
                self.scope, manual=False, cpu_verified=True
            )
            self.assertTrue(frozen.get("ok"), frozen)
            self._wait_until_frozen()

            # Match the daemon's two-second sample cadence. If a previous
            # wake just sampled the queue, let this request wait for that tick.
            now = time.time()
            if now - self.daemon.last_listener_check >= 2.0:
                self.daemon.listener_wake_pass(now=now)
            completed = queue.Queue(maxsize=1)
            sent = threading.Event()
            client = threading.Thread(
                target=self._issue_request,
                args=(port, completed, sent),
                daemon=True,
            )
            client.start()
            self.assertTrue(sent.wait(timeout=2.0), "HTTP request was not sent")

            next_check = self.daemon.last_listener_check + 2.0
            time.sleep(max(0.0, next_check - time.time()))
            wake = self.daemon.listener_wake_pass()
            self.assertTrue(
                any(item.get("thawed") for item in wake),
                "pending HTTP connection did not thaw the scope: %r" % wake,
            )
            client.join(timeout=6.0)
            self.assertFalse(client.is_alive(), "HTTP request stayed blocked")
            status, body, elapsed = completed.get_nowait()
            self.assertEqual(status, 200, body)
            self.assertIn(b"wake-on-connect", body)
            latencies.append(elapsed)

            thaws = [
                event
                for event in self.daemon.store.events_since(cursor)["events"]
                if event["event"] == "thaw"
                and event["data"].get("scope") == self.scope
                and event["data"].get("reason") == "connect"
            ]
            self.assertTrue(thaws, "daemon did not log thaw reason=connect")

        p95 = sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1]
        self.assertLessEqual(
            p95,
            3.0,
            "HTTP wake p95 %.3fs exceeds the 3s acceptance limit: %r"
            % (p95, latencies),
        )
