"""Versioned IPC compatibility, rejection, and schema checks."""

from contextlib import closing, nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from taema import protocol
from taema.cli import commands as cli
from taema.core import process as inspect
from taema.daemon import service as daemon
from tests.test_phase0 import make_cfg

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schema" / "ipc"


def schema(name):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def matches(value, rule, document):
    """Small JSON Schema subset used by these contract tests; schemas remain standard JSON."""
    if "$ref" in rule:
        target = document
        for part in rule["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        return matches(value, target, document)
    if "oneOf" in rule:
        return sum(matches(value, option, document) for option in rule["oneOf"]) == 1
    if "anyOf" in rule:
        return any(matches(value, option, document) for option in rule["anyOf"])
    expected = rule.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        type_matches = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
            "null": lambda v: v is None,
        }
        if not any(type_matches[kind](value) for kind in expected_types):
            return False
    if "const" in rule and value != rule["const"]:
        return False
    if "enum" in rule and value not in rule["enum"]:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < rule.get("minimum", value) or value > rule.get("maximum", value):
            return False
    if isinstance(value, str):
        if len(value) < rule.get("minLength", 0) or len(value) > rule.get(
            "maxLength", len(value)
        ):
            return False
    if isinstance(value, list):
        if len(value) < rule.get("minItems", 0) or len(value) > rule.get(
            "maxItems", len(value)
        ):
            return False
        if "items" in rule and not all(
            matches(item, rule["items"], document) for item in value
        ):
            return False
    if isinstance(value, dict):
        if len(value) > rule.get("maxProperties", len(value)):
            return False
        if not set(rule.get("required", ())) <= set(value):
            return False
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False and set(value) - set(properties):
            return False
        if any(
            key in properties and not matches(item, properties[key], document)
            for key, item in value.items()
        ):
            return False
    return True


class IpcV2Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.daemon = daemon.Daemon(make_cfg(self.temporary.name))
        self.request_schema = schema("v2-request.json")
        self.reply_schema = schema("v2-reply.json")
        self.results_schema = schema("v2-results.json")
        self.v1_schema = schema("v1-compat.json")

    def converse(self, payload, wait_for_request=True):
        path = os.path.join(self.temporary.name, "ipc-%d.sock" % time.time_ns())
        with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as server:
            server.bind(path)
            server.listen(1)
            with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as client:
                client.connect(path)
                if payload:
                    client.sendall(payload)
                if not wait_for_request:
                    client.settimeout(2)
                reply = self.daemon.serve(server)
                client.settimeout(2)
                response = b""
                while not response.endswith(b"\n"):
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    response += chunk
                return json.loads(response), reply

    def request(self, identifier, command, args):
        return {"v": 2, "id": identifier, "cmd": command, "args": args}

    def test_v1_remains_unwrapped_and_v2_echoes_correlation_id(self):
        v1_request = {"cmd": "status"}
        self.assertTrue(
            matches(v1_request, self.v1_schema["$defs"]["request"], self.v1_schema)
        )
        v1, _ = self.converse(json.dumps(v1_request).encode() + b"\n")
        self.assertTrue(matches(v1, self.v1_schema["$defs"]["reply"], self.v1_schema))
        self.assertIn("mode", v1)
        self.assertNotIn("v", v1)

        v2, _ = self.converse(
            json.dumps(self.request(42, "status", {})).encode() + b"\n"
        )
        self.assertTrue(matches(v2, self.reply_schema, self.reply_schema))
        self.assertEqual((v2["v"], v2["id"], v2["ok"]), (2, 42, True))
        self.assertTrue(
            matches(
                v2["result"],
                self.results_schema["$defs"]["status"],
                self.results_schema,
            )
        )

    def test_serve_leaves_summary_write_for_the_tick(self):
        payload = json.dumps(self.request(7, "status", {})).encode() + b"\n"
        first, _ = self.converse(payload)
        self.assertTrue(first["ok"])
        self.daemon._summary_dirty = True
        with mock.patch.object(self.daemon, "_write_summary_if_dirty") as writer:
            second, _ = self.converse(payload)
        self.assertTrue(second["ok"])
        writer.assert_not_called()
        self.assertTrue(self.daemon._summary_dirty)

    def test_old_feedback_v1_marker_still_uses_v1_reply(self):
        message = {
            "cmd": "feedback",
            "v": 1,
            "id": "old-feedback-client",
            "op": "veto",
            "target": {"kind": "app", "value": "legacy-app", "start": None},
        }
        reply, _ = self.converse(json.dumps(message).encode() + b"\n")
        self.assertTrue(
            matches(reply, self.v1_schema["$defs"]["reply"], self.v1_schema)
        )
        self.assertTrue(reply["ok"])
        self.assertNotIn("v", reply)

    def test_reload_reason_is_bounded_and_reaches_daemon(self):
        envelope = self.request(9, "reload", {"reason": "manual profile selection"})
        self.assertTrue(matches(envelope, self.request_schema, self.request_schema))
        with mock.patch.object(
            self.daemon,
            "reload_config",
            return_value={"reloaded": True, "sources": []},
        ) as reload_config:
            reply, _ = self.converse(json.dumps(envelope).encode() + b"\n")
        self.assertTrue(reply["ok"])
        reload_config.assert_called_once_with("manual profile selection")

        invalid = self.request(10, "reload", {"reason": "x" * 257})
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_v2(invalid)

    def test_freeze_and_thaw_requests_are_typed_and_exclusive(self):
        freeze = self.request(1, "freeze", {"scope": "leftover/browser"})
        thaw = self.request(2, "thaw", {"scope": "leftover/browser"})
        thaw_all = self.request(3, "thaw", {"all": True})
        for envelope in (freeze, thaw, thaw_all):
            self.assertTrue(matches(envelope, self.request_schema, self.request_schema))
        self.assertEqual(
            protocol.decode_v2(freeze),
            {"cmd": "freeze", "scope": "leftover/browser"},
        )
        self.assertEqual(protocol.decode_v2(thaw_all), {"cmd": "thaw", "all": True})
        for args in ({}, {"all": True, "scope": "leftover/browser"}, {"all": False}):
            with self.subTest(args=args), self.assertRaises(protocol.ProtocolError):
                protocol.decode_v2(self.request(4, "thaw", args))

    def test_every_current_command_reply_matches_its_schema(self):
        pid = os.getpid()
        requests = [
            ("status", {}),
            ("memory_budget", {}),
            ("reload", {}),
            ("review", {}),
            ("register", {"scope": "scope-ipc", "owner": pid}),
            ("attach", {"scope": "scope-ipc", "pids": [pid]}),
            (
                "register_agent",
                {
                    "session": "ipc-agent",
                    "pid": pid,
                    "capabilities": ["heartbeat"],
                    "compositor": "",
                },
            ),
            ("agent_beat", {"session": "ipc-agent", "pid": pid}),
            (
                "job_done",
                {"shell_pid": pid, "tag": "%d.1" % pid, "status": 0, "word": "cmd"},
            ),
            ("kill_done", {"shell_pid": pid, "word": "kill"}),
            ("ask", {"shell_pid": pid}),
            ("gc", {"dry_run": True, "memory": True}),
            (
                "reclaim",
                {"scope": "leftover/reclaim-test", "force_veto": True, "dry_run": True},
            ),
            ("freeze", {"scope": "leftover/browser"}),
            ("thaw", {"scope": "leftover/browser"}),
            ("thaw", {"all": True}),
            ("feedback", {"op": "keep", "key": "ipc-schema"}),
            (
                "feedback",
                {
                    "v": 1,
                    "id": "ipc-v1-operation",
                    "op": "veto",
                    "target": {"kind": "app", "value": "schema-app", "start": None},
                },
            ),
            (
                "feedback",
                {
                    "v": 2,
                    "id": "ipc-v2-hold",
                    "op": "hold",
                    "scope": "scope-ipc",
                    "held": True,
                },
            ),
        ]
        for identifier, (command, args) in enumerate(requests, start=1):
            envelope = self.request(identifier, command, args)
            self.assertTrue(
                matches(envelope, self.request_schema, self.request_schema), command
            )
            payload = json.dumps(envelope).encode() + b"\n"
            uid = mock.patch.object(inspect, "uid_of", return_value=os.getuid())
            memory_operation = nullcontext()
            with uid:
                if command == "register":
                    operation = mock.patch.object(
                        self.daemon, "watch_owner", return_value=True
                    )
                elif command == "reload":
                    operation = mock.patch.object(
                        self.daemon,
                        "reload_config",
                        return_value={"reloaded": True, "sources": []},
                    )
                elif command == "attach":
                    operation = mock.patch.object(daemon.engine, "helper_attach")
                elif command == "gc":
                    operation = mock.patch.object(
                        self.daemon, "gc_pass", return_value=[]
                    )
                    memory_operation = mock.patch.object(
                        self.daemon, "reclaim_pass", return_value=[]
                    )
                elif command == "reclaim":
                    operation = mock.patch.object(
                        self.daemon,
                        "reclaim_scope",
                        return_value={"scope": args["scope"], "status": "would"},
                    )
                    memory_operation = nullcontext()
                elif command == "freeze":
                    operation = mock.patch.object(
                        self.daemon,
                        "freeze_scope",
                        return_value={
                            "ok": True,
                            "scope": args["scope"],
                            "frozen": True,
                        },
                    )
                elif command == "thaw" and "scope" in args:
                    operation = mock.patch.object(
                        self.daemon,
                        "_thaw_scope",
                        return_value={
                            "ok": True,
                            "scope": args["scope"],
                            "thawed": True,
                        },
                    )
                elif command == "thaw":
                    operation = mock.patch.object(
                        self.daemon, "thaw_all_managed_scopes", return_value=[]
                    )
                else:
                    operation = nullcontext()
                    memory_operation = nullcontext()
                with operation, memory_operation:
                    reply, _ = self.converse(payload)
            self.assertTrue(
                matches(reply, self.reply_schema, self.reply_schema), command
            )
            self.assertTrue(reply["ok"], (command, reply))
            result_schema = self.results_schema["$defs"][command]
            self.assertTrue(
                matches(reply["result"], result_schema, self.results_schema), command
            )

        question = {
            "id": 100,
            "shell_pid": pid,
            "nonce": "schema-nonce",
            "created": time.time(),
            "owner": "owner",
            "ask_keys": ["leftover"],
            "candidates": [{"key": "owner"}],
        }
        self.daemon.pending[100] = question
        envelope = self.request(
            99, "answer", {"nonce": "schema-nonce", "choice": "keep"}
        )
        reply, _ = self.converse(json.dumps(envelope).encode() + b"\n")
        self.assertTrue(matches(reply, self.reply_schema, self.reply_schema))
        self.assertTrue(
            matches(
                reply["result"],
                self.results_schema["$defs"]["answer"],
                self.results_schema,
            )
        )

    def test_unknown_keys_and_wrong_types_are_structured_without_mutation(self):
        before = deepcopy(self.daemon.store.export_legacy())
        requests = [
            self.request(1, "status", {"extra": True}),
            self.request(2, "register", {"scope": 10, "owner": os.getpid()}),
            self.request(3, "not-a-command", {}),
        ]
        for envelope in requests:
            reply, _ = self.converse(json.dumps(envelope).encode() + b"\n")
            self.assertTrue(matches(reply, self.reply_schema, self.reply_schema))
            self.assertFalse(reply["ok"])
        unsupported, _ = self.converse(
            json.dumps({"v": 3, "id": 4, "cmd": "status", "args": {}}).encode() + b"\n"
        )
        self.assertTrue(matches(unsupported, self.reply_schema, self.reply_schema))
        self.assertEqual(unsupported["error"]["code"], "unsupported_version")
        self.assertEqual(self.daemon.store.export_legacy(), before)

    def test_protocol_rejects_invalid_envelopes_and_maps_domain_errors(self):
        invalid = [
            [],
            {"v": 2, "id": 1, "cmd": "status", "args": {}, "extra": 1},
            {"v": 2, "id": True, "cmd": "status", "args": {}},
            {"v": 2, "id": 1, "cmd": 5, "args": {}},
            {"v": 2, "id": 1, "cmd": "status", "args": []},
            {"v": 2, "id": 1, "cmd": "register", "args": {"scope": "x"}},
            {"v": 2, "id": 1, "cmd": "attach", "args": {"scope": "x", "pids": [True]}},
            {
                "v": 2,
                "id": 1,
                "cmd": "job_done",
                "args": {"shell_pid": 2, "tag": "2.1", "status": 999, "word": "cmd"},
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "kill_done",
                "args": {"shell_pid": 2, "word": "rm"},
            },
            {"v": 2, "id": 1, "cmd": "answer", "args": {"nonce": "", "choice": "stop"}},
            {
                "v": 2,
                "id": 1,
                "cmd": "feedback",
                "args": {"op": "keep", "key": "x", "extra": 1},
            },
            {"v": 3, "id": 1, "cmd": "status", "args": {}},
            {"v": 2, "id": 1, "cmd": "register", "args": {"scope": "x", "owner": 1}},
            {"v": 2, "id": 1, "cmd": "attach", "args": {"scope": "x", "pids": []}},
            {
                "v": 2,
                "id": 1,
                "cmd": "job_done",
                "args": {"shell_pid": 2, "tag": "2.1", "status": 256, "word": "cmd"},
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "answer",
                "args": {"nonce": "x", "choice": "later"},
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "feedback",
                "args": {
                    "v": 1,
                    "id": "x",
                    "op": "veto",
                    "target": {"kind": "app", "value": "x"},
                    "trigger": "bad",
                },
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "feedback",
                "args": {"v": 2, "id": "x", "op": "mode", "value": "auto"},
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "feedback",
                "args": {"v": 2, "id": "x", "op": "snooze", "until": float("nan")},
            },
            {
                "v": 2,
                "id": 1,
                "cmd": "feedback",
                "args": {
                    "v": 1,
                    "id": "x",
                    "op": "vetoed",
                    "target": {"kind": "app", "value": "x"},
                },
            },
        ]
        for message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaises(protocol.ProtocolError),
            ):
                protocol.decode_v2(message)

        self.assertTrue(protocol.is_v2({"v": 2}))
        self.assertFalse(protocol.is_v2([]))
        self.assertTrue(protocol.is_legacy({"cmd": "status"}))
        self.assertTrue(protocol.is_legacy({"cmd": "feedback", "v": 1, "id": "old-id"}))
        self.assertFalse(protocol.is_legacy({"cmd": "status", "v": 3}))
        self.assertEqual(protocol.request_id({"id": 7}), 7)
        self.assertEqual(protocol.request_id({"id": True}), 0)

        for text, code in (
            ("unknown command", "unknown_command"),
            ("forbidden", "forbidden"),
            ("unknown or expired nonce", "invalid_nonce"),
            ("bad request", "invalid_request"),
            ("some other error", "operation_failed"),
        ):
            reply = protocol.reply_v2(9, {"error": text})
            self.assertEqual(reply["error"]["code"], code)
            self.assertTrue(matches(reply, self.reply_schema, self.reply_schema))

    def test_hold_and_snooze_feedback_reasons_are_bounded_strings(self):
        operations = (
            {"op": "hold", "held": True},
            {"op": "snooze", "until": time.time() + 60},
        )
        for index, operation in enumerate(operations):
            valid = {"v": 2, "id": "hold-reason-%d" % index, **operation}
            valid["reason"] = "m" * 256
            protocol.validate_feedback(valid)
            for reason in ("m" * 257, 12):
                invalid = {**valid, "reason": reason}
                with self.subTest(
                    op=operation["op"], reason_type=type(reason).__name__
                ):
                    with self.assertRaises(protocol.ProtocolError):
                        protocol.validate_feedback(invalid)

    def test_forget_all_feedback_is_limited_to_forget_and_matches_schema(self):
        operation = {
            "v": 2,
            "id": "forget-all",
            "op": "forget",
            "key": "browser",
            "all": True,
        }
        protocol.validate_feedback(operation)
        self.assertTrue(
            matches(
                operation,
                self.request_schema["$defs"]["feedback_args"],
                self.request_schema,
            )
        )

        for invalid in (
            {**operation, "all": "yes"},
            {**operation, "op": "keep"},
            {**operation, "op": "kill"},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_feedback(invalid)
                self.assertFalse(
                    matches(
                        invalid,
                        self.request_schema["$defs"]["feedback_args"],
                        self.request_schema,
                    )
                )

    def test_veto_feedback_accepts_pair_targets_and_rejects_malformed_targets(self):
        valid = {
            "v": 2,
            "id": "pair-veto",
            "op": "veto",
            "target": {
                "kind": "pair",
                "value": "firefox",
                "owner": "browser",
                "leftover": "firefox",
            },
            "reason": "keep this process",
            "expires": time.time() + 60,
        }
        protocol.validate_feedback(valid)
        self.assertTrue(
            matches(
                valid,
                self.request_schema["$defs"]["feedback_args"],
                self.request_schema,
            )
        )

        invalid_targets = (
            {"kind": "pair", "value": "firefox", "owner": "browser"},
            {
                "kind": "pair",
                "value": "firefox",
                "owner": "browser",
                "leftover": "node",
            },
            {"kind": "app", "value": "firefox", "owner": "browser"},
            {"kind": "app", "value": True},
            {"kind": "unknown", "value": "firefox"},
        )
        for index, target in enumerate(invalid_targets):
            with self.subTest(target=target):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_feedback(
                        {**valid, "id": "invalid-target-%d" % index, "target": target}
                    )
        for expires in (True, float("inf"), 10**1000):
            with self.subTest(expires=expires):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_feedback({**valid, "expires": expires})

    def test_unveto_pid_target_keeps_v1_wildcard_removal_compatibility(self):
        operation = {
            "v": 1,
            "id": "legacy-unveto-pid",
            "op": "unveto",
            "target": {"kind": "pid", "value": "42"},
        }
        protocol.validate_feedback(operation)

    def test_review_feedback_requires_valid_id_owner_and_choice(self):
        operations = (
            {"op": "review_shown", "review_id": 3, "owner": "editor"},
            {"op": "review_answer", "review_id": 3, "choice": "never"},
        )
        for index, operation in enumerate(operations):
            message = {"v": 2, "id": "review-%d" % index, **operation}
            protocol.validate_feedback(message)
            self.assertTrue(
                matches(
                    message,
                    self.request_schema["$defs"]["feedback_args"],
                    self.request_schema,
                )
            )
        for index, operation in enumerate(
            (
                {"op": "review_shown", "review_id": True},
                {"op": "review_answer", "review_id": 3, "choice": "later"},
                {
                    "op": "review_shown",
                    "review_id": 3,
                    "owner": "x" * 257,
                },
            )
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_feedback(
                        {"v": 2, "id": "bad-review-%d" % index, **operation}
                    )
        answer_result = {
            "ok": True,
            "choice": "never",
            "owner": "editor",
            "leftovers": ["helper"],
        }
        self.assertTrue(
            matches(
                answer_result,
                self.results_schema["$defs"]["answer"],
                self.results_schema,
            )
        )

    def test_fuzz_inputs_get_errors_without_state_change(self):
        valid = json.dumps(self.request(9, "status", {})).encode()
        too_large = valid + b" " * (65538 - len(valid)) + b"\n"
        cases = [
            b'{"cmd":\n',
            b"\xff\xfe\n",
            b"[]\n",
            json.dumps(self.request(4, "register", {"scope": 3, "owner": 4})).encode()
            + b"\n",
            json.dumps(self.request(5, "status", {"unexpected": 1})).encode() + b"\n",
            json.dumps({**self.request(6, "status", {}), "extra": 1}).encode() + b"\n",
            too_large,
        ]
        before = deepcopy(self.daemon.store.export_legacy())
        for payload in cases:
            reply, _ = self.converse(payload)
            self.assertTrue(
                isinstance(reply, dict)
                and ("error" in reply or reply.get("ok") is False)
            )
            if "v" in reply:
                self.assertTrue(matches(reply, self.reply_schema, self.reply_schema))
            else:
                self.assertTrue(
                    matches(reply, self.v1_schema["$defs"]["reply"], self.v1_schema)
                )
        start = time.monotonic()
        reply, _ = self.converse(b"", wait_for_request=False)
        self.assertLess(time.monotonic() - start, 2)
        self.assertIn("error", reply)
        self.assertEqual(self.daemon.store.export_legacy(), before)

        still_alive, _ = self.converse(
            json.dumps(self.request(10, "status", {})).encode() + b"\n"
        )
        self.assertTrue(still_alive["ok"])

    def test_cli_sends_v2_and_unwraps_result(self):
        path = os.path.join(self.temporary.name, "cli.sock")
        cfg = make_cfg(self.temporary.name)
        cfg["paths"]["socket"] = path
        cfg["paths"]["socket_fallback"] = path
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        received = []

        def serve_client():
            with server.accept()[0] as connection:
                data = b""
                while not data.endswith(b"\n"):
                    data += connection.recv(65536)
                received.append(json.loads(data))
                connection.sendall(
                    json.dumps(
                        {
                            "v": 2,
                            "id": received[0]["id"],
                            "ok": True,
                            "result": {"mode": "observe"},
                        }
                    ).encode()
                    + b"\n"
                )

        thread = threading.Thread(target=serve_client)
        thread.start()
        result = cli.ask(cfg, {"cmd": "status"})
        thread.join(timeout=2)
        server.close()
        self.assertEqual(result, {"mode": "observe"})
        self.assertEqual(received[0]["v"], 2)
        self.assertEqual(received[0]["cmd"], "status")
        self.assertEqual(received[0]["args"], {})


if __name__ == "__main__":
    unittest.main()
