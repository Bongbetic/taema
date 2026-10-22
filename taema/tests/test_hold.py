"""Runtime hold behavior through public CLI and daemon boundaries."""

import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from contextlib import redirect_stderr
from contextlib import redirect_stdout
import io
from unittest import mock

from taema.cli import commands
from taema.daemon import service
from taema.model import authorization
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg


class HoldCli(unittest.TestCase):
    def test_global_hold_queues_offline_and_writes_private_runtime_flag(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")

            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
            ):
                result = commands.main(["hold", "--reason", "maintenance"])

            self.assertEqual(result, 0)
            with open(store.feedback_path, encoding="utf-8") as queue:
                operation = json.loads(queue.readline())
            self.assertEqual(operation["op"], "hold")
            self.assertEqual(operation["reason"], "maintenance")
            self.assertEqual(store.hold_reason(), "global hold")

            hold_file = Path(runtime_dir, "taema", "HOLD")
            self.assertTrue(hold_file.is_file())
            self.assertEqual(json.loads(hold_file.read_text())["reason"], "maintenance")
            self.assertEqual(stat.S_IMODE(hold_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(hold_file.parent.stat().st_mode), 0o700)

    def test_scope_hold_and_resume_are_queued_and_cover_descendants(self):
        with tempfile.TemporaryDirectory() as root, FakeCg() as cg:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            scope = cg.leaf("scope-browser")
            os.makedirs(os.path.join(scope, "child"))
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
            ):
                held = commands.main(["hold", "browser", "--reason", "debugging"])
                held_reason = store.hold_reason("scope-browser/child")
                resumed = commands.main(["resume", "scope-browser"])

            self.assertEqual(held, 0)
            self.assertEqual(held_reason, "scope hold")
            self.assertEqual(resumed, 0)
            self.assertEqual(store.hold_reason("scope-browser/child"), "")
            with open(store.feedback_path, encoding="utf-8") as queue:
                operations = [json.loads(line) for line in queue]
            self.assertEqual(
                [(op["op"], op["scope"], op["held"]) for op in operations],
                [
                    ("hold", "scope-browser", True),
                    ("hold", "scope-browser", False),
                ],
            )

    def test_duration_snooze_queues_deadline_and_enforces_hold_offline(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
            ):
                result = commands.main(["snooze", "2h"])

            self.assertEqual(result, 0)
            self.assertEqual(store.hold_reason(), "snoozed")
            status = store.hold_status()
            self.assertGreater(status["snooze_remaining_s"], 7000)
            self.assertLessEqual(status["snooze_remaining_s"], 7200)
            with open(store.feedback_path, encoding="utf-8") as queue:
                operation = json.loads(queue.readline())
            self.assertEqual(operation["op"], "snooze")
            self.assertGreater(operation["until"], store.now())
            self.assertTrue(Path(runtime_dir, "taema", "HOLD").is_file())

    def test_snooze_until_local_time_uses_next_occurrence(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")
            now = datetime.now().astimezone()
            expected = now.replace(hour=18, minute=0, second=0, microsecond=0)
            if expected <= now:
                expected += timedelta(days=1)
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
            ):
                result = commands.main(["snooze", "until", "18:00"])

            self.assertEqual(result, 0)
            with open(store.feedback_path, encoding="utf-8") as queue:
                operation = json.loads(queue.readline())
            self.assertAlmostEqual(operation["until"], expected.timestamp(), delta=1)

    def test_runtime_hold_flag_refuses_offline_stop_without_daemon(self):
        with tempfile.TemporaryDirectory() as root, FakeCg() as cg:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(os.path.join(runtime_dir, "taema"), mode=0o700)
            cg.leaf("scope-browser")
            store = knowledge.Store(state_dir, {}, read_only=True)
            cfg = make_cfg(state_dir, mode="enforce")
            Path(runtime_dir, "taema", "HOLD").write_text(
                '{"held":true,"reason":"offline safety"}\n', encoding="utf-8"
            )
            error = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
                redirect_stderr(error),
            ):
                result = commands.main(["kill", "scope-browser"])

            self.assertEqual(result, 4)
            self.assertIn("global hold", error.getvalue())

    def test_status_shows_held_scope_and_snooze_countdown(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            store = knowledge.Store(state_dir, {})
            store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "hold-status",
                    "op": "hold",
                    "scope": "scope-browser",
                    "held": True,
                    "reason": "debugging",
                }
            )
            store.apply_feedback_command(
                {
                    "v": 2,
                    "id": "snooze-status",
                    "op": "snooze",
                    "until": time.time() + 600,
                }
            )
            store.save()
            cfg = make_cfg(state_dir, mode="enforce")
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load_status", return_value=(cfg, store)),
                mock.patch.object(commands, "ask", return_value=None),
                mock.patch.object(
                    commands.cgroup, "base", return_value="/missing/cgroup"
                ),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = commands.main(["status", "--json"])
                report = json.loads(output.getvalue())
                output = io.StringIO()
                with redirect_stdout(output):
                    commands.main(["status"])

        state = report["status"]["hold_state"]
        self.assertEqual(result, 3)
        self.assertEqual(state["scopes"], ["scope-browser"])
        self.assertGreater(state["snooze_remaining_s"], 500)
        self.assertLessEqual(state["snooze_remaining_s"], 600)
        self.assertIn("scope-browser", output.getvalue())
        self.assertIn("snooze 10m", output.getvalue())

    def test_hold_slot_blocks_every_current_stop_trigger(self):
        triggers = (
            authorization.OWNER_EXIT,
            authorization.JOB_SURVIVORS,
            authorization.GC_STOP,
            authorization.SESSION_END,
            authorization.MANUAL_STOP,
            authorization.FREEZE,
            authorization.MANUAL_FREEZE,
        )
        for trigger in triggers:
            with self.subTest(trigger=trigger):
                decision = authorization.authorize(
                    trigger,
                    "enforce",
                    authorization.Facts(scope="scope-browser", held="global hold"),
                )
                self.assertEqual(decision.verdict, authorization.KEEP)
                self.assertEqual(decision.slot, authorization.HOLD)
                self.assertIn("held", decision.reason)

    def test_hold_ladder_contract_covers_each_registered_governor_action(self):
        self.assertEqual(
            authorization.HOLD_BLOCKED_ACTIONS,
            frozenset(("freeze", "stop", "reclaim")),
        )
        self.assertEqual(
            set(authorization.TRIGGER_ACTIONS), set(authorization._CAPABILITY)
        )
        for trigger, action in authorization.TRIGGER_ACTIONS.items():
            with self.subTest(trigger=trigger, action=action):
                baseline = authorization.authorize(trigger, "enforce")
                held = authorization.authorize(
                    trigger,
                    "enforce",
                    authorization.Facts(held="maintenance"),
                )
                if action in authorization.HOLD_BLOCKED_ACTIONS:
                    self.assertEqual(held.verdict, authorization.KEEP)
                    self.assertEqual(held.slot, authorization.HOLD)
                else:
                    self.assertEqual(held.verdict, baseline.verdict)
                    self.assertEqual(held.slot, baseline.slot)

    def test_global_resume_clears_snooze(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands, "ask", return_value=None),
            ):
                self.assertEqual(commands.main(["snooze", "2h"]), 0)
                self.assertEqual(commands.main(["resume"]), 0)

            self.assertIsNone(store.hold_status(include_runtime=False)["snooze_until"])
            self.assertFalse(Path(runtime_dir, "taema", "HOLD").exists())

    def test_hold_rejects_an_overlong_reason_before_queueing(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state")
            os.makedirs(state_dir)
            store = knowledge.Store(state_dir, {})
            cfg = make_cfg(state_dir, mode="enforce")
            error = io.StringIO()
            with (
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                redirect_stderr(error),
            ):
                result = commands.main(["hold", "--reason", "r" * 257])

            self.assertEqual(result, 2)
            self.assertIn("at most 256 characters", error.getvalue())
            self.assertFalse(os.path.exists(store.feedback_path))

    def test_daemon_imports_runtime_marker_and_service_boot_hold(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = os.path.join(root, "state-runtime")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(os.path.join(runtime_dir, "taema"), mode=0o700)
            marker = Path(runtime_dir, "taema", "HOLD")
            marker.write_text(
                '{"held":true,"reason":"queued maintenance"}\n', encoding="utf-8"
            )
            cfg = make_cfg(state_dir, mode="enforce")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}):
                daemon = service.Daemon(cfg)

            self.assertTrue(daemon.store.data["held"])
            self.assertEqual(daemon.store.hold_reason(), "global hold")
            lines = [
                json.loads(line)
                for line in Path(daemon.store.log_path).read_text().splitlines()
            ]
            reasons = [line["reason"] for line in lines if line["event"] == "hold"]
            self.assertIn("queued maintenance", reasons)

            boot_dir = os.path.join(root, "state-boot")
            boot_runtime_dir = os.path.join(root, "runtime-boot")
            os.makedirs(boot_dir)
            os.makedirs(boot_runtime_dir, mode=0o700)
            boot_cfg = make_cfg(boot_dir, mode="enforce")
            with mock.patch.dict(
                os.environ,
                {"XDG_RUNTIME_DIR": boot_runtime_dir, "TAEMA_HOLD": "1"},
            ):
                boot_daemon = service.Daemon(boot_cfg)
            boot_lines = [
                json.loads(line)
                for line in Path(boot_daemon.store.log_path).read_text().splitlines()
            ]
            boot_reasons = [
                line["reason"] for line in boot_lines if line["event"] == "hold"
            ]
            self.assertIn("TAEMA_HOLD=1 service setting", boot_reasons)

    def test_sigusr1_toggles_hold_and_writes_audit_reasons(self):
        with tempfile.TemporaryDirectory() as root, FakeCg():
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            cfg = make_cfg(state_dir, mode="enforce")
            with (
                mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}),
                mock.patch.object(service.Daemon, "check_socket"),
            ):
                daemon = service.Daemon(cfg)
                daemon._on_signal(service.signal.SIGUSR1, None)
                with (
                    mock.patch.object(daemon, "adopt_pass"),
                    mock.patch.object(daemon, "session_ended", return_value=False),
                    mock.patch.object(daemon, "gc_pass"),
                ):
                    daemon.tick()
                self.assertTrue(daemon.store.data["held"])
                daemon._on_signal(service.signal.SIGUSR1, None)
                with (
                    mock.patch.object(daemon, "adopt_pass"),
                    mock.patch.object(daemon, "session_ended", return_value=False),
                    mock.patch.object(daemon, "gc_pass"),
                ):
                    daemon.tick()

            self.assertFalse(daemon.store.data["held"])
            lines = [
                json.loads(line)
                for line in Path(daemon.store.log_path).read_text().splitlines()
            ]
            reasons = [line["reason"] for line in lines if line["event"] == "hold"]
            self.assertIn("SIGUSR1 toggled actions on hold", reasons)
            self.assertIn("SIGUSR1 toggled actions back on", reasons)

    def test_daemon_logs_when_the_ladder_holds_a_governor_action(self):
        with tempfile.TemporaryDirectory() as root, FakeCg() as cg:
            state_dir = os.path.join(root, "state")
            os.makedirs(state_dir)
            cg.leaf("scope-browser")
            daemon = service.Daemon(make_cfg(state_dir, mode="enforce"))
            daemon.store.data["held"] = True

            decision = daemon.authorize(
                authorization.MANUAL_STOP,
                authorization.Facts(scope="scope-browser"),
            )

            self.assertEqual(decision.slot, authorization.HOLD)
            lines = [
                json.loads(line)
                for line in Path(daemon.store.log_path).read_text().splitlines()
            ]
            self.assertTrue(any(line["event"] == "action_held" for line in lines))

    def test_daemon_tick_thaws_frozen_scopes_and_keeps_observing_while_held(self):
        with tempfile.TemporaryDirectory() as root, FakeCg() as cg:
            state_dir = os.path.join(root, "state")
            runtime_dir = os.path.join(root, "runtime")
            os.makedirs(state_dir)
            os.makedirs(runtime_dir, mode=0o700)
            scope = cg.leaf("scope-browser")
            freeze = Path(scope, "cgroup.freeze")
            freeze.write_text("1\n", encoding="utf-8")
            cfg = make_cfg(state_dir, mode="enforce")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime_dir}):
                daemon = service.Daemon(cfg)
                daemon.store.set_frozen_scope(
                    "scope-browser", time.time(), source="manual"
                )
                daemon.store.apply_feedback_command(
                    {
                        "v": 2,
                        "id": "tick-hold",
                        "op": "hold",
                        "held": True,
                        "reason": "maintenance",
                    }
                )
                daemon.iv_adopt = 0
                daemon.iv_gc = 0
                daemon.last = {"adopt": 0, "gc": 0}
                with (
                    mock.patch.object(daemon, "check_socket"),
                    mock.patch.object(daemon, "adopt_pass") as adopt,
                    mock.patch.object(daemon, "session_ended", return_value=False),
                    mock.patch.object(daemon, "gc_pass") as gc,
                ):
                    daemon.tick()

            self.assertEqual(freeze.read_text(encoding="utf-8"), "0\n")
            adopt.assert_called_once()
            gc.assert_called_once()


if __name__ == "__main__":
    unittest.main()
