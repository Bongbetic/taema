"""Guest acceptance test for save/stop safety around a live QMP connection."""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from taema.core import process
from taema.daemon import service
from tests.test_phase0 import FakeCg, make_cfg


FAKE_QEMU = r"""
import ctypes, os, signal, socket, sys, time

scope, events, socket_path = sys.argv[1:4]
ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"qemu-system-x86_64"), 0, 0, 0)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)
connection = None

def stop(*_args):
    with open(events, "a", encoding="utf-8") as target:
        target.write("stop\n")
    with open(os.path.join(scope, "cgroup.procs"), "w", encoding="ascii") as target:
        target.write("")
    if connection is not None:
        connection.close()
    server.close()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
connection, _address = server.accept()
while connection.recv(1):
    pass
connection.close()
connection = None
while True:
    signal.pause()
"""


@unittest.skipUnless(
    os.environ.get("TAEMA_LIVE_QMP_TEST") == "1",
    "set TAEMA_LIVE_QMP_TEST=1 to run the disposable Unix QMP guest fixture",
)
class LiveQmpSaveStopTests(unittest.TestCase):
    def test_connected_qmp_client_blocks_save_and_stop_until_disconnect(self):
        with (
            FakeCg() as cg,
            tempfile.TemporaryDirectory(prefix="taema-m3-qmp-") as temporary,
        ):
            scope = "app-libvirt-qemu-m3"
            scope_path = cg.leaf(scope, [])
            socket_path = os.path.join(temporary, "qmp.sock")
            events_path = os.path.join(temporary, "events.log")
            hook_path = os.path.join(temporary, "save-hook")
            with open(hook_path, "w", encoding="utf-8") as target:
                target.write('#!/bin/sh\nprintf \'save:%s\\n\' "$1" >> "$2"\n')
            os.chmod(hook_path, 0o755)

            qemu = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    FAKE_QEMU,
                    scope_path,
                    events_path,
                    socket_path,
                    "-qmp",
                    "unix:" + socket_path,
                    "-name",
                    "guest=m3-fake-domain",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            client = None
            daemon = None
            try:
                deadline = time.monotonic() + 5
                while not os.path.exists(socket_path) and time.monotonic() < deadline:
                    if qemu.poll() is not None:
                        self.fail("fake QEMU exited before creating its QMP socket")
                    time.sleep(0.01)
                self.assertTrue(
                    os.path.exists(socket_path), "fake QMP socket did not appear"
                )
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(2)
                client.connect(socket_path)
                cg.set_procs(scope, [qemu.pid])

                qmp_edges = process.edges({qemu.pid}, process.Snapshot())
                self.assertTrue(
                    any(edge["kind"] == "qmp" for edge in qmp_edges.get(qemu.pid, [])),
                    "the live external client was not identified as a QMP dependency: %r"
                    % qmp_edges,
                )

                config = make_cfg(os.path.join(temporary, "state"), mode="enforce")
                config["mem"] = {
                    "enabled": True,
                    "reclaim": True,
                    "reclaim_max": "32M",
                    "reclaim_minimum": "1M",
                    "reclaim_cooldown": 0,
                    "idle_reclaim_grace": 0,
                }
                daemon = service.Daemon(config)
                daemon.units = [
                    {
                        "unit": {
                            "name": "app-libvirt-qemu",
                            "kind": "app",
                            "class": "vm",
                            "domain": "m3-fake-domain",
                            "stop_when_unneeded": True,
                        },
                        "mem": {"save_state": [hook_path, "%(domain)s", events_path]},
                        "gc": {"qmp_socket": True, "no_attach_grace": 0},
                    }
                ]

                with mock.patch.object(
                    daemon, "_reclaim_idle", return_value=(True, "idle fixture")
                ):
                    blocked = daemon.gc_pass()
                    self.assertEqual(blocked, [])
                    self.assertEqual(qemu.poll(), None)
                    self.assertFalse(os.path.exists(events_path))

                    client.close()
                    client = None
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        current = process.edges({qemu.pid}, process.Snapshot())
                        if not any(
                            edge["kind"] == "qmp" for edge in current.get(qemu.pid, [])
                        ):
                            break
                        time.sleep(0.02)
                    else:
                        self.fail(
                            "QMP peer stayed visible after the client disconnected"
                        )

                    stopped = daemon.gc_pass()

                self.assertTrue(stopped, "daemon did not select the idle fake VM")
                qemu.wait(timeout=5)
                with open(events_path, encoding="utf-8") as source:
                    events = source.read().splitlines()
                self.assertEqual(events, ["save:m3-fake-domain", "stop"])
            finally:
                if client is not None:
                    client.close()
                if daemon is not None:
                    daemon.sel.close()
                if qemu.poll() is None:
                    qemu.terminate()
                    try:
                        qemu.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        qemu.kill()
                        qemu.wait(timeout=2)
