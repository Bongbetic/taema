"""`taema-eventd`: optional root process-event forwarder and daemon collector.

Seams under test (spec issue #73, ADR-0002):
- kernel frame decode: recorded proc-connector bytes -> typed fork/exec/exit events
- compact record framing: forwarder output parses back exactly
- uid isolation: a consumer socket only receives its own uid's records
- drop counting: a slow consumer's 4,096-record ring counts drops, never blocks
- no commands: bytes sent to the forwarder never trigger a reply or action
- daemon collector: fork+exit within 1s lands in the instance ledger through
  the collector queue; with eventd disabled behaviour is unchanged
"""

import os
import socket
import struct
import tempfile
import time
import unittest

from taema import eventd
from taema.daemon import service as daemon_service
from tests.test_phase0 import make_cfg


def kernel_frame(what, first, second, third=0, fourth=0):
    """Hand-packed proc-connector frame (nlmsghdr + cn_msg + proc_event)."""
    payload = struct.pack(
        "<IIQIIII",
        what,  # proc_event.what
        0,  # cpu
        0,  # timestamp_ns
        first,
        second,
        third,
        fourth,
    )
    cn_msg = struct.pack("<IIIIHH", 1, 1, 0, 0, len(payload), 0) + payload
    nlmsg = struct.pack("<IHHII", 16 + len(cn_msg), 0, 0, 0, 0) + cn_msg
    return nlmsg


class KernelDecodeTests(unittest.TestCase):
    def test_fork_frame_decodes_parent_and_child(self):
        events = eventd.decode_kernel_frames(
            kernel_frame(eventd.PROC_EVENT_FORK, 11, 12, 33, 34)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "fork")
        self.assertEqual((events[0].pid, events[0].ppid), (33, 11))

    def test_exec_frame_decodes_pid(self):
        events = eventd.decode_kernel_frames(
            kernel_frame(eventd.PROC_EVENT_EXEC, 55, 55)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "exec")
        self.assertEqual(events[0].pid, 55)

    def test_exit_frame_decodes_status(self):
        events = eventd.decode_kernel_frames(
            kernel_frame(eventd.PROC_EVENT_EXIT, 77, 77, 9, 15)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "exit")
        self.assertEqual((events[0].pid, events[0].exit_code), (77, 9))

    def test_truncated_frame_is_ignored(self):
        self.assertEqual(eventd.decode_kernel_frames(b"\x01\x02"), [])


class RecordFramingTests(unittest.TestCase):
    def test_compact_records_round_trip(self):
        record = eventd.CompactRecord(
            kind="fork",
            pid=10,
            tgid=10,
            ppid=1,
            uid=1000,
            ts_ns=123,
            exit_code=0,
            exe="/bin/sleep",
            comm="sleep",
        )
        records, rest = eventd.decode_records(eventd.encode_record(record))
        self.assertEqual(rest, b"")
        self.assertEqual(records, [record])


class ProtocolEdgeTests(unittest.TestCase):
    def test_subscription_message_carries_listen_op(self):
        for listen, op in ((True, 1), (False, 2)):
            message = eventd.subscription_message(listen)
            nlmsg_len, nl_type = struct.unpack_from("<IH", message)
            self.assertEqual(nlmsg_len, len(message))
            self.assertEqual(nl_type, 3)
            idx, val, _seq, _ack, cn_len, _flags = struct.unpack_from(
                "<IIIIHH", message, 16
            )
            self.assertEqual((idx, val, cn_len), (1, 1, 4))
            (seen,) = struct.unpack_from("<i", message, 16 + 20)
            self.assertEqual(seen, op)

    def test_foreign_connector_id_is_ignored(self):
        frame = kernel_frame(eventd.PROC_EVENT_FORK, 1, 1, 2, 2)
        tampered = frame[:16] + struct.pack("<IIIIHH", 9, 9, 0, 0, 32, 0) + frame[36:]
        self.assertEqual(eventd.decode_kernel_frames(tampered), [])

    def test_unknown_proc_event_is_ignored(self):
        self.assertEqual(
            eventd.decode_kernel_frames(kernel_frame(0x40, 1, 1, 2, 2)), []
        )

    def test_partial_record_frame_waits_for_more_bytes(self):
        record = eventd.CompactRecord(
            "exec",
            7,
            7,
            1,
            1000,
            9,
            0,
            "/bin/x",
            "x",
        )
        frame = eventd.encode_record(record)
        records, rest = eventd.decode_records(frame[: len(frame) - 3])
        self.assertEqual(records, [])
        self.assertEqual(rest, frame[: len(frame) - 3])

    def test_corrupt_magic_stops_the_stream(self):
        record = eventd.CompactRecord(
            "exec",
            7,
            7,
            1,
            1000,
            9,
            0,
            "/bin/x",
            "x",
        )
        frame = bytearray(eventd.encode_record(record))
        frame[4:8] = b"BAD!"
        records, rest = eventd.decode_records(bytes(frame))
        self.assertEqual(records, [])

    def test_proc_facts_blank_for_gone_pid(self):
        self.assertEqual(eventd.proc_facts(2**30), ("", "", 0))
        self.assertIsNone(eventd.uid_of(2**30))


class ForwarderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.uids = {}
        self.forwarder = eventd.Forwarder(
            self.tmp.name, uid_of=lambda pid: self.uids.get(pid, 1000)
        )
        self.addCleanup(self.forwarder.close)

    def fork_as(self, pid, ppid, uid):
        self.uids[pid] = uid
        frame = kernel_frame(eventd.PROC_EVENT_FORK, ppid, ppid, pid, pid)
        self.forwarder.feed_kernel(frame)

    def test_sockets_are_created_mode_0600(self):
        self.fork_as(101, 1, 1000)
        path = os.path.join(self.tmp.name, "1000.sock")
        self.assertTrue(os.path.exists(path))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_uid_isolation(self):
        self.fork_as(101, 1, 1000)
        self.fork_as(202, 1, 1001)
        got1000 = self.forwarder.drain_for_test(1000)
        got1001 = self.forwarder.drain_for_test(1001)
        self.assertEqual([r.pid for r in got1000], [101])
        self.assertEqual([r.pid for r in got1001], [202])

    def test_slow_consumer_drops_are_counted_and_bounded(self):
        for pid in range(5000):
            self.fork_as(10000 + pid, 1, 1000)
        ring = self.forwarder.ring_for_test(1000)
        self.assertEqual(len(ring.records), eventd.RING_CAPACITY)
        self.assertEqual(ring.drops, 5000 - eventd.RING_CAPACITY)
        self.assertEqual(ring.records[-1].pid, 10000 + 4999)

    def test_commands_receive_no_reply(self):
        self.fork_as(101, 1, 1000)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(os.path.join(self.tmp.name, "1000.sock"))
        client.settimeout(2)
        self.forwarder.pump_once_for_test(0.5)
        backlog, _ = eventd.decode_records(client.recv(65536))
        self.assertEqual([r.pid for r in backlog], [101])
        client.sendall(b'{"cmd": "status"}\n')
        client.settimeout(0.3)
        self.forwarder.pump_once_for_test(0.3)
        with self.assertRaises(socket.timeout):
            client.recv(1024)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.daemon = daemon_service.Daemon(make_cfg(self.tmp.name))
        self.addCleanup(self.daemon.sel.close)

    def test_eventd_disabled_by_default(self):
        self.assertFalse(self.daemon.eventd_enabled())
        self.assertEqual(self.daemon.poll_eventd(), 0)

    def test_enabled_without_forwarder_stays_quiet(self):
        cfg = make_cfg(self.tmp.name)
        cfg["experimental"] = {"eventd": True}
        daemon = daemon_service.Daemon(cfg)
        self.addCleanup(daemon.sel.close)
        missing = os.path.join(self.tmp.name, "no-such-dir", "1000.sock")
        old = os.environ.get("TAEMA_EVENTD_SOCKET")
        os.environ["TAEMA_EVENTD_SOCKET"] = missing
        self.addCleanup(
            lambda: (
                os.environ.__setitem__("TAEMA_EVENTD_SOCKET", old)
                if old is not None
                else os.environ.pop("TAEMA_EVENTD_SOCKET", None)
            )
        )
        self.assertEqual(daemon.poll_eventd(), 0)
        self.assertIsNone(daemon.eventd_sock)

    def test_poll_reads_live_forwarder_stream(self):
        import shutil

        run_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, run_dir, True)
        forwarder = eventd.Forwarder(
            run_dir,
            uid_of=lambda pid: os.getuid(),
            facts_of=lambda pid: ("/bin/x-test-73", "x-test-73", 4242),
        )
        self.addCleanup(forwarder.close)
        forwarder.feed_kernel(
            kernel_frame(eventd.PROC_EVENT_FORK, 1, 1, 424301, 424301)
        )
        path = os.path.join(run_dir, "%d.sock" % os.getuid())
        old_env = dict(os.environ)
        os.environ["TAEMA_EVENTD"] = "1"
        os.environ["TAEMA_EVENTD_SOCKET"] = path
        self.addCleanup(lambda: os.environ.clear() or os.environ.update(old_env))
        cfg = make_cfg(self.tmp.name)
        daemon = daemon_service.Daemon(cfg)
        self.addCleanup(daemon.sel.close)
        self.addCleanup(daemon._close_eventd)
        self.assertTrue(daemon.eventd_enabled())
        forwarder.pump_once_for_test(0.5)
        daemon.poll_eventd()
        forwarder.pump_once_for_test(0.5)
        self.assertGreater(daemon.poll_eventd(), 0)
        daemon.drain_collector_events()
        row = daemon.store.db.latest_app_instance("exe:x-test-73")
        self.assertIsNotNone(row)
        self.assertEqual(row["pid"], 424301)
        forwarder.close()
        daemon.poll_eventd()
        self.assertIsNone(daemon.eventd_sock)

    def test_short_lived_process_reaches_the_ledger(self):
        cfg = make_cfg(self.tmp.name)
        cfg["experimental"] = {"eventd": True}
        daemon = daemon_service.Daemon(cfg)
        self.addCleanup(daemon.sel.close)
        now_ns = time.time_ns()
        daemon.ingest_eventd_records(
            [
                eventd.CompactRecord(
                    "fork",
                    424201,
                    424201,
                    99,
                    os.getuid(),
                    now_ns,
                    0,
                    "/bin/sleep-test-73",
                    "sleep-test-73",
                    4242,
                ),
                eventd.CompactRecord(
                    "exit",
                    424201,
                    424201,
                    99,
                    os.getuid(),
                    now_ns + 400_000_000,
                    0,
                    "/bin/sleep-test-73",
                    "sleep-test-73",
                    4242,
                ),
            ]
        )
        daemon.drain_collector_events()
        row = daemon.store.db.latest_app_instance("exe:sleep-test-73")
        self.assertIsNotNone(row)
        self.assertEqual(row["pid"], 424201)
        self.assertIsNotNone(row["exited"])
        self.assertLess(row["exited"] - row["born"], 1.0)

    def test_exit_carries_facts_captured_while_alive(self):
        run_dir = tempfile.mkdtemp()
        self.addCleanup(
            lambda: __import__("shutil").rmtree(run_dir, ignore_errors=True)
        )
        forwarder = eventd.Forwarder(
            run_dir,
            uid_of=lambda pid: os.getuid(),
            facts_of=lambda pid: ("/bin/sleep-test-73", "sleep-test-73", 4242),
        )
        self.addCleanup(forwarder.close)
        frames = b"".join(
            [
                kernel_frame(eventd.PROC_EVENT_FORK, 99, 99, 424202, 424202),
                kernel_frame(eventd.PROC_EVENT_EXIT, 424202, 424202, 0, 0),
            ]
        )
        self.assertEqual(forwarder.feed_kernel(frames), 2)
        records = forwarder.drain_for_test(os.getuid())
        self.assertEqual([r.kind for r in records], ["fork", "exit"])
        self.assertEqual(records[1].exe, "/bin/sleep-test-73")
        self.assertEqual(records[1].start, 4242)


class PackagingTests(unittest.TestCase):
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def read(self, rel):
        with open(os.path.join(self.ROOT, rel), encoding="utf-8") as stream:
            return stream.read()

    def test_template_splits_optional_eventd_subpackage(self):
        template = self.read("srcpkgs/taema/template")
        self.assertIn("taema-eventd_package()", template)
        self.assertIn("usr/bin/taema-eventd", template)

    def test_build_script_splits_eventd_package(self):
        script = self.read("tools/build-xbps.sh")
        self.assertIn("taema-eventd-", script)
        self.assertIn("usr/bin/taema-eventd", script)

    def test_makefile_installs_the_forwarder(self):
        self.assertIn("bin/taema-eventd", self.read("Makefile"))

    def test_service_setting_defaults_off_and_reaches_daemon(self):
        run = self.read("sv/taema/run")
        self.assertIn("TAEMA_EVENTD:-0", run)
        self.assertIn("export TAEMA_EVENTD", run)
        self.assertIn("taema-eventd", run)
        user = self.read("libexec/taemad-user")
        self.assertIn('TAEMA_EVENTD="${TAEMA_EVENTD:-0}"', user)


if __name__ == "__main__":
    unittest.main()
