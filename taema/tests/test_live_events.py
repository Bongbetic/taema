"""Event replay, bounded subscriptions, CLI views, and cached prompt summary."""

import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from taema import protocol
from taema.cli import commands, framework
from taema.daemon import service
from taema.store import knowledge
from tests.test_ipc_v2 import matches
from tests.test_phase0 import make_cfg


ROOT = Path(__file__).resolve().parents[1]


class LiveEventTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.daemon = service.Daemon(make_cfg(self.temporary.name))
        self.addCleanup(self.daemon.sel.close)

    @staticmethod
    def read_replies(connection, count):
        data = b""
        while data.count(b"\n") < count:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
        return [json.loads(line) for line in data.splitlines()]

    def open_subscription(self, since_seq=0, topics=("status", "review")):
        server, client = socket.socketpair()
        client.settimeout(2)
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        self.assertIsNone(
            self.daemon._start_subscription(
                server,
                73,
                {"topics": list(topics), "since_seq": since_seq},
            )
        )
        self.addCleanup(self.daemon._drop_subscriber, server)
        return server, client

    def test_reconnect_replays_matching_events_in_sequence_order(self):
        self.daemon.store.log(event="daemon_start")
        self.daemon.store.log(event="review_created", scope="scope-a")
        self.daemon.store.log(event="attach", scope="scope-b")
        server, client = self.open_subscription(since_seq=0)

        self.daemon._write_subscriber(server)
        replies = self.read_replies(client, 3)

        self.assertEqual(replies[0]["result"]["subscribed"], True)
        replay = [reply["result"]["event"] for reply in replies[1:]]
        self.assertEqual([event["seq"] for event in replay], [1, 2])
        self.assertEqual(replay[0]["topics"], ["status"])
        self.assertIn("review", replay[1]["topics"])

        self.daemon.store.log(event="mode_changed", old="observe", new="adopt")
        self.daemon._write_subscriber(server)
        live = self.read_replies(client, 1)[0]["result"]["event"]
        self.assertEqual(live["seq"], 4)
        self.assertIn("profile", live["topics"])

    def test_v2_subscribe_request_keeps_the_socket_open_for_stream_frames(self):
        self.daemon.store.log(event="daemon_start")
        path = os.path.join(self.temporary.name, "subscribe.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2)
        self.addCleanup(listener.close)
        self.addCleanup(client.close)
        client.connect(path)
        request = {
            "v": 2,
            "id": 81,
            "cmd": "subscribe",
            "args": {"topics": ["status"], "since_seq": 0},
        }
        client.sendall((json.dumps(request) + "\n").encode())

        self.daemon.serve(listener)
        stream_socket = next(iter(self.daemon.subscribers))
        self.addCleanup(self.daemon._drop_subscriber, stream_socket)
        self.daemon._write_subscriber(stream_socket)
        replies = self.read_replies(client, 2)

        self.assertTrue(
            matches(
                replies[0],
                json.loads((ROOT / "schema/ipc/v2-reply.json").read_text()),
                json.loads((ROOT / "schema/ipc/v2-reply.json").read_text()),
            )
        )
        result_schema = json.loads((ROOT / "schema/ipc/v2-results.json").read_text())
        self.assertTrue(
            matches(
                replies[0]["result"], result_schema["$defs"]["subscribe"], result_schema
            )
        )
        self.assertEqual(replies[1]["result"]["event"]["seq"], 1)

    def test_expired_history_returns_resync_marker(self):
        self.daemon.store.log(event="daemon_start")
        self.daemon.store.log(event="daemon_stop")
        self.daemon.store.save()
        with self.daemon.store.db.connection() as connection:
            connection.execute("DELETE FROM events")
            connection.commit()
        server, client = self.open_subscription(since_seq=0, topics=("status",))

        self.daemon._write_subscriber(server)
        replies = self.read_replies(client, 2)

        self.assertTrue(replies[0]["result"]["subscribed"])
        self.assertEqual(replies[1]["result"], {"resync": True, "latest_seq": 2})

    def test_more_than_one_thousand_missed_events_returns_resync(self):
        with mock.patch.object(
            self.daemon.store,
            "events_since",
            return_value={
                "events": [],
                "oldest_seq": 1,
                "latest_seq": 1001,
                "more": True,
            },
        ):
            server, client = self.open_subscription(since_seq=0, topics=("status",))
            self.daemon._write_subscriber(server)
            replies = self.read_replies(client, 2)
        self.assertEqual(replies[1]["result"], {"resync": True, "latest_seq": 1001})

    def test_cursor_ahead_of_store_requests_resync(self):
        with mock.patch.object(
            self.daemon.store,
            "events_since",
            return_value={
                "events": [],
                "oldest_seq": None,
                "latest_seq": 0,
                "more": False,
            },
        ):
            server, client = self.open_subscription(since_seq=1, topics=("status",))
            self.daemon._write_subscriber(server)
            replies = self.read_replies(client, 2)
        self.assertEqual(replies[1]["result"], {"resync": True, "latest_seq": 0})

    def test_slow_subscriber_is_bounded_and_gets_a_terminal_error(self):
        server, client = self.open_subscription(since_seq=0, topics=("status",))
        started = time.monotonic()
        for _ in range(service.MAX_SUBSCRIBER_QUEUE + 1):
            self.daemon.store.log(event="status_ping")
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(self.daemon.subscribers[server]["closing"])
        self.assertEqual(self.daemon.subscribers[server]["queued_events"], 0)

        self.daemon._write_subscriber(server)
        reply = self.read_replies(client, 1)[0]
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "slow_consumer")
        self.assertNotIn(server, self.daemon.subscribers)

    def test_subscriber_limit_rejects_the_seventeenth_client(self):
        for identifier in range(service.MAX_SUBSCRIBERS):
            server, _client = self.open_subscription()
            self.daemon.subscribers[server]["id"] = identifier + 1
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)

        result = self.daemon._start_subscription(
            server,
            99,
            {"topics": ["status"], "since_seq": 0},
        )

        self.assertEqual(result, {"error": "subscriber limit reached"})

    def test_event_history_merges_unsaved_rows_and_respects_a_cursor(self):
        self.daemon.store.log(event="one")
        self.daemon.store.log(event="two")
        self.daemon.store.save()
        self.daemon.store.log(event="three")

        result = self.daemon.store.events_since(1, limit=10)

        self.assertEqual([event["seq"] for event in result["events"]], [2, 3])
        self.assertEqual(result["latest_seq"], 3)
        self.assertFalse(result["more"])

    def test_oversized_audit_payload_is_bounded_before_streaming(self):
        self.daemon.store.log(event="large", detail="x" * 70000)

        event = self.daemon.store.events_since(0, limit=1)["events"][0]

        self.assertTrue(event["data"]["truncated"])
        self.assertLess(len(json.dumps(event["data"]).encode()), knowledge.MAX_LOG_LINE)

    def test_subscribe_protocol_validates_topics_and_cursor(self):
        request = {
            "v": 2,
            "id": 9,
            "cmd": "subscribe",
            "args": {"topics": ["status", "profile"], "since_seq": 3},
        }
        self.assertTrue(
            matches(
                request,
                json.loads((ROOT / "schema/ipc/v2-request.json").read_text()),
                json.loads((ROOT / "schema/ipc/v2-request.json").read_text()),
            )
        )
        self.assertEqual(protocol.decode_v2(request)["since_seq"], 3)
        for args in (
            {"topics": ["unknown"], "since_seq": 0},
            {"topics": ["status", "status"], "since_seq": 0},
            {"topics": ["status"], "since_seq": -1},
            {"topics": ["status"], "since_seq": True},
        ):
            with self.subTest(args=args), self.assertRaises(protocol.ProtocolError):
                protocol.decode_v2({**request, "args": args})

    def test_summary_rewrites_atomically_and_prompt_reads_without_a_socket(self):
        runtime = os.path.join(self.temporary.name, "runtime")
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}):
            daemon = service.Daemon(make_cfg(self.temporary.name))
            self.addCleanup(daemon.sel.close)
            self.assertTrue(daemon._write_summary_if_dirty())
            summary_path = Path(runtime, "taema", "summary")
            first = summary_path.read_text()
            self.assertIn("mode=observe", first)
            self.assertEqual(summary_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(summary_path.parent.stat().st_mode & 0o777, 0o700)

            daemon.cfg["_profile_name"] = "quiet"
            daemon.profile_reason = "selected for a long running job"
            daemon.store.log(event="profile_changed", profile="quiet")
            self.assertTrue(daemon._write_summary_if_dirty())
            second = summary_path.read_text()
            self.assertNotEqual(first, second)
            self.assertIn("profile=quiet", second)
            self.assertIn("event=profile_changed", second)

            output = StringIO()
            with (
                mock.patch("socket.socket", side_effect=AssertionError("socket used")),
                redirect_stdout(output),
            ):
                started = time.monotonic()
                self.assertEqual(framework.main(["prompt"]), 0)
                self.assertLess(time.monotonic() - started, 0.04)
            self.assertEqual(output.getvalue(), second)

    def test_events_command_emits_schema_tagged_json_and_filter(self):
        store = knowledge.Store(self.temporary.name, {})
        store.log(event="daemon_start")
        store.log(event="review_created", scope="scope-a")
        args = SimpleNamespace(
            config=None,
            socket=None,
            since=0,
            event="review_created",
            json=True,
            jsonl=False,
            follow=False,
        )
        output = StringIO()
        with mock.patch.object(commands, "_load_events", return_value=({}, store)):
            with redirect_stdout(output):
                self.assertEqual(commands.cmd_events(args), 0)

        payload = json.loads(output.getvalue())
        schema = json.loads((ROOT / "schema/cli/read-v1.json").read_text())
        self.assertTrue(matches(payload, schema, schema))
        self.assertEqual(
            [item["event"] for item in payload["events"]], ["review_created"]
        )

    def test_events_rejects_negative_sequence_before_loading_state(self):
        args = SimpleNamespace(since=-1)
        error = StringIO()
        with (
            mock.patch.object(commands, "_load_events") as load_events,
            redirect_stderr(error),
        ):
            result = commands.cmd_events(args)
        self.assertEqual(result, 1)
        self.assertIn("--since must be", error.getvalue())
        load_events.assert_not_called()

    def test_cli_subscription_stream_and_watch_render_plain_lines(self):
        path = os.path.join(self.temporary.name, "client.sock")
        cfg = {"paths": {"socket": path, "socket_fallback": path}}
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        received = []

        def serve_client():
            connection, _address = server.accept()
            with connection:
                data = b""
                while not data.endswith(b"\n"):
                    data += connection.recv(65536)
                received.append(json.loads(data))
                identifier = received[0]["id"]
                for result in (
                    {"subscribed": True, "topics": ["status"], "since_seq": 4},
                    {"event": {"seq": 5, "event": "daemon_start", "data": {}}},
                ):
                    connection.sendall(
                        (
                            json.dumps(protocol.reply_v2(identifier, result)) + "\n"
                        ).encode()
                    )

        thread = threading.Thread(target=serve_client)
        thread.start()
        messages = list(commands.subscribe(cfg, ["status"], 4))
        thread.join(timeout=2)
        server.close()
        self.assertEqual(received[0]["cmd"], "subscribe")
        self.assertEqual(messages[0]["subscribed"], True)
        self.assertEqual(messages[1]["event"]["seq"], 5)

        args = SimpleNamespace(
            config=None, socket=None, event=None, json=False, jsonl=False
        )
        store = knowledge.Store(self.temporary.name, {}, read_only=True)
        output = StringIO()
        with (
            mock.patch.object(commands, "_load_events", return_value=(cfg, store)),
            mock.patch.object(
                commands,
                "subscribe",
                return_value=iter(
                    [
                        {"subscribed": True},
                        {"event": {"seq": 5, "event": "daemon_start", "data": {}}},
                    ]
                ),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.cmd_watch(args), 0)
        self.assertEqual(output.getvalue(), "5 daemon_start\n")


if __name__ == "__main__":
    unittest.main()
