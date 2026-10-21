"""Reversible QoS classification for contained scopes."""

import io
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import taema.cli.commands as cli
from taema.core import cgroup, qos
from taema.daemon import service
from taema.cli import view
from taema.model import authorization
from tests.test_phase0 import FakeCg, make_cfg


def write(path, value):
    Path(path).write_text(value, encoding="ascii")


@contextmanager
def emulate_io_weight_commands():
    """Model the kernel's one-command-per-write io.weight pseudo-file behavior."""
    writes = []
    real_write = qos.write_control

    def write_control(path, name, value):
        if name != "io.weight":
            return real_write(path, name, value)
        writes.append(value)
        target = Path(path, name)
        lines = target.read_text(encoding="ascii").splitlines()
        command = value.split()
        for index, line in enumerate(lines):
            fields = line.split()
            if fields and fields[0] == command[0]:
                lines[index] = value
                break
        else:
            lines.append(value)
        target.write_text("\n".join(lines) + "\n", encoding="ascii")

    with mock.patch.object(qos, "write_control", side_effect=write_control):
        yield writes


@contextmanager
def fake_oom_process(scores, protected=()):
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(
                service.inspect, "starttime", side_effect=lambda pid: 1000 + pid
            )
        )
        stack.enter_context(
            mock.patch.object(service.inspect, "uid_of", return_value=os.getuid())
        )
        stack.enter_context(
            mock.patch.object(
                service.policy,
                "protected_reason",
                side_effect=lambda pid, _cfg: "protected" if pid in protected else None,
            )
        )
        stack.enter_context(
            mock.patch.object(
                service.oom, "read_score", side_effect=lambda pid: scores[pid]
            )
        )
        write_score = stack.enter_context(mock.patch.object(service.oom, "write_score"))
        record = stack.enter_context(
            mock.patch.object(service.engine, "helper_oom_record")
        )
        restore = stack.enter_context(
            mock.patch.object(service.engine, "helper_oom_restore")
        )
        yield SimpleNamespace(write=write_score, record=record, restore=restore)


class QoSIntegration(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.cfg = make_cfg(os.path.join(self.cg.root, "state"), mode="enforce")
        self.cfg["mem"] = {"enabled": False}
        self.daemon = service.Daemon(self.cfg)
        protection = mock.patch.object(
            service.policy, "protected_reason", return_value=None
        )
        protection.start()
        self.addCleanup(protection.stop)

    def add_scope_controls(self, scope, controls, pids=(42,)):
        path = self.cg.leaf(scope, pids)
        parents = [self.cg.base]
        parent = os.path.dirname(path)
        if parent != self.cg.base:
            parents.append(parent)
        for directory in parents:
            write(os.path.join(directory, "cgroup.controllers"), "cpu io\n")
            write(os.path.join(directory, "cgroup.subtree_control"), "\n")
            write(os.path.join(directory, "cgroup.procs"), "")
        for name, value in controls.items():
            write(os.path.join(path, name), value)
        return path

    def apply_after_debounce(self, scope="leftover/browser", now=100.0):
        self.daemon.qos_pass(now=now)
        self.daemon.qos_pass(now=now + qos.DEBOUNCE_SECONDS)
        path = cgroup.resolve(scope)
        return path

    def test_leftover_controls_wait_two_seconds_and_restore_through_undo(self):
        path = self.add_scope_controls(
            "leftover/browser",
            {
                "cpu.idle": "0\n",
                "cpu.weight": "100\n",
                "io.weight": "default 100\n",
                "memory.oom.group": "0\n",
                "pids.max": "max\n",
            },
        )

        with fake_oom_process({42: -100}) as oom_process:
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=101.99)
            self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
            self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")

            self.daemon.qos_pass(now=102.0)
            self.assertEqual(Path(path, "cpu.idle").read_text(), "1\n")
            self.assertEqual(Path(path, "io.weight").read_text(), "default 10\n")
            self.assertEqual(Path(path, "memory.oom.group").read_text(), "1\n")
            self.assertEqual(Path(path, "pids.max").read_text(), "max\n")
            self.assertEqual(
                self.daemon.store.data["qos_scopes"]["leftover/browser"]["class"],
                "leftover",
            )
            oom_process.record.assert_called_once_with(
                self.daemon.cfg, 42, 1042, -100, 500
            )
            oom_process.write.assert_called_once_with(42, 500, 1042, -100)

            decision = self.daemon.store.latest_undoable_decision(kinds=("qos",))
            self.assertIsNotNone(decision)
            result = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "qos-undo-1",
                    "op": "undo",
                    "action_id": str(decision["id"]),
                }
            )
            self.assertEqual(result["target_decision_id"], decision["id"])
            self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
            self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")
            self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
            self.assertIn("leftover/browser", self.daemon.store.data["qos_exempt"])
            oom_process.restore.assert_called_once_with(
                self.daemon.cfg, 42, 1042, -100, 500
            )

            self.daemon.qos_pass(now=110.0)
            self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")

    def test_shared_oom_target_preserves_higher_existing_scores(self):
        path = self.add_scope_controls(
            "shared/adb",
            {"cpu.weight": "100\n", "memory.oom.group": "0\n"},
            pids=(43, 44),
        )
        with fake_oom_process({43: -50, 44: 300}) as oom_process:
            self.apply_after_debounce("shared/adb")

        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")
        self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
        oom_process.record.assert_called_once_with(self.daemon.cfg, 43, 1043, -50, 200)
        oom_process.write.assert_called_once_with(43, 200, 1043, -50)

    def test_new_members_in_an_active_scope_get_their_own_original_record(self):
        scope = "leftover/browser"
        self.add_scope_controls(scope, {"cpu.idle": "0\n", "memory.oom.group": "0\n"})
        with fake_oom_process({42: -100, 43: -50}) as oom_process:
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            self.cg.set_procs(scope, (42, 43))
            self.daemon.qos_pass(now=103.0)
            self.daemon.qos_pass(now=105.0)

        self.assertEqual(
            self.daemon.store.data["qos_scopes"][scope]["oom_score_adj"],
            [
                {"pid": 42, "start": 1042, "value": -100, "applied": 500},
                {"pid": 43, "start": 1043, "value": -50, "applied": 500},
            ],
        )
        self.assertEqual(oom_process.record.call_count, 2)
        self.assertEqual(oom_process.write.call_count, 2)

    def test_oom_group_flag_can_be_disabled_independently(self):
        path = self.add_scope_controls(
            "leftover/no-group",
            {"cpu.idle": "0\n", "memory.oom.group": "0\n"},
        )
        self.cfg["guard"] = {"oom_group_leftover": False}
        with fake_oom_process({42: -100}) as oom_process:
            self.apply_after_debounce("leftover/no-group")

        self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
        oom_process.record.assert_called_once_with(self.daemon.cfg, 42, 1042, -100, 500)
        oom_process.write.assert_called_once_with(42, 500, 1042, -100)

    def test_live_config_disabling_oom_group_restores_only_the_group_flag(self):
        scope = "leftover/live-group"
        path = self.add_scope_controls(
            scope,
            {"cpu.idle": "0\n", "memory.oom.group": "0\n"},
        )
        with fake_oom_process({42: -100}) as oom_process:
            self.apply_after_debounce(scope)
            self.assertEqual(Path(path, "memory.oom.group").read_text(), "1\n")

            self.cfg["guard"] = {"oom_group_leftover": False}
            self.daemon.qos_pass(now=104.0)

        self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
        self.assertEqual(Path(path, "cpu.idle").read_text(), "1\n")
        record = self.daemon.store.data["qos_scopes"][scope]
        self.assertEqual(record["oom_score_adj"][0]["applied"], 500)
        self.assertNotIn(
            "memory.oom.group", [item["file"] for item in record["originals"]]
        )
        oom_process.restore.assert_not_called()

    def test_active_scope_prunes_stale_oom_history_before_adding_member(self):
        scope = "leftover/prune-history"
        path = self.add_scope_controls(
            scope,
            {"cpu.idle": "1\n", "memory.oom.group": "0\n"},
        )
        stale = [
            {"pid": pid, "start": 1, "value": -100, "applied": 500}
            for pid in range(10000, 10000 + service.MAX_QOS_OOM_RECORDS)
        ]
        self.daemon.store.data["qos_scopes"] = {
            scope: {
                "class": "leftover",
                "active": True,
                "applied": True,
                "originals": [],
                "oom_score_adj": stale,
                "available": ["cpu.idle"],
            }
        }
        with (
            mock.patch.object(
                service.inspect,
                "starttime",
                side_effect=lambda pid: 1042 if pid == 42 else 2,
            ),
            mock.patch.object(
                service.inspect,
                "uid_of",
                side_effect=lambda pid: os.getuid() if pid == 42 else os.getuid() + 1,
            ),
            mock.patch.object(service.oom, "read_score", return_value=-100),
            mock.patch.object(service.engine, "helper_oom_record") as register,
            mock.patch.object(service.oom, "write_score") as write_score,
        ):
            self.assertTrue(self.daemon._apply_qos_class(scope, path, "leftover"))

        record = self.daemon.store.data["qos_scopes"][scope]
        self.assertEqual(
            record["oom_score_adj"],
            [{"pid": 42, "start": 1042, "value": -100, "applied": 500}],
        )
        register.assert_called_once_with(self.daemon.cfg, 42, 1042, -100, 500)
        write_score.assert_called_once_with(42, 500, 1042, -100)

    def test_observe_logs_oom_plan_without_shaping_scores_or_group(self):
        path = self.add_scope_controls(
            "leftover/preview",
            {"cpu.idle": "0\n", "memory.oom.group": "0\n"},
        )
        self.daemon.cfg["mode"] = "observe"
        with fake_oom_process({42: -100}) as oom_process:
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)

        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
        oom_process.record.assert_not_called()
        oom_process.write.assert_not_called()
        self.assertTrue(
            any(
                event["event"] == "qos_would"
                and event.get("data", {}).get("oom_pids") == [42]
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_vetoed_or_protected_scope_never_shapes_oom_scores(self):
        veto_path = self.add_scope_controls(
            "leftover/vetoed", {"cpu.idle": "0\n", "memory.oom.group": "0\n"}
        )
        with fake_oom_process({42: -100}) as oom_process:
            with mock.patch.object(
                self.daemon,
                "authorize",
                return_value=SimpleNamespace(
                    verdict=authorization.KEEP, reason="vetoed by user"
                ),
            ):
                self.daemon.qos_pass(now=100.0)
                self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(veto_path, "memory.oom.group").read_text(), "0\n")
        oom_process.record.assert_not_called()
        oom_process.write.assert_not_called()

        protected_path = self.add_scope_controls(
            "leftover/protected",
            {"cpu.idle": "0\n", "memory.oom.group": "0\n"},
            pids=(42, 43),
        )
        with fake_oom_process({42: -100, 43: -100}, protected={42}) as oom_process:
            self.daemon.qos_pass(now=110.0)
            self.daemon.qos_pass(now=112.0)
        self.assertEqual(Path(protected_path, "memory.oom.group").read_text(), "0\n")
        oom_process.record.assert_not_called()
        oom_process.write.assert_not_called()
        shutil.rmtree(veto_path)
        shutil.rmtree(protected_path)

        changed_path = self.add_scope_controls(
            "leftover/veto-after", {"cpu.idle": "0\n", "memory.oom.group": "0\n"}
        )
        with fake_oom_process({42: -100}) as oom_process:
            self.daemon.qos_pass(now=120.0)
            self.daemon.qos_pass(now=122.0)
            with mock.patch.object(
                self.daemon,
                "authorize",
                return_value=SimpleNamespace(
                    verdict=authorization.KEEP, reason="vetoed after shaping"
                ),
            ):
                self.daemon.qos_pass(now=123.0)
        self.assertEqual(Path(changed_path, "memory.oom.group").read_text(), "0\n")
        oom_process.restore.assert_called_once_with(
            self.daemon.cfg, 42, 1042, -100, 500
        )

    def test_cpu_weight_is_fallback_and_io_default_preserves_device_weights(self):
        path = self.add_scope_controls(
            "leftover/compiler",
            {
                "cpu.weight": "100\n",
                "io.weight": "default 100\n8:0 300\n",
            },
        )
        with emulate_io_weight_commands() as io_writes:
            self.apply_after_debounce("leftover/compiler")
            self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "10\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 10\n8:0 300\n")
        self.assertEqual(io_writes, ["default 10"])

    def test_available_cpu_control_is_enabled_when_optional_io_is_missing(self):
        parent = self.cg.base
        write(os.path.join(parent, "cgroup.controllers"), "cpu\n")
        write(os.path.join(parent, "cgroup.subtree_control"), "\n")
        write(os.path.join(parent, "cgroup.procs"), "")
        reason = qos.enable_controllers(parent)
        self.assertEqual(reason, "delegated controllers unavailable: io")
        self.assertEqual(Path(parent, "cgroup.subtree_control").read_text(), "+cpu\n")

    def test_newly_available_controls_are_retried_and_keep_first_originals(self):
        path = self.add_scope_controls("shared/late", {})
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        self.assertTrue(self.daemon.store.data["qos_scopes"]["shared/late"]["active"])
        self.assertEqual(
            self.daemon.store.data["qos_scopes"]["shared/late"]["available"], []
        )

        write(os.path.join(path, "cpu.weight"), "100\n")
        self.daemon.qos_pass(now=103.0)
        self.daemon.qos_pass(now=105.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")
        write(os.path.join(path, "io.weight"), "default 100\n")
        write(os.path.join(path, "cpu.weight"), "80\n")
        self.daemon.qos_pass(now=106.0)
        with emulate_io_weight_commands() as io_writes:
            self.daemon.qos_pass(now=108.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "80\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 50\n")
        self.assertEqual(io_writes, ["default 50"])
        self.assertEqual(
            self.daemon.store.data["qos_scopes"]["shared/late"]["originals"],
            [
                {"file": "cpu.weight", "value": "100"},
                {"file": "io.weight", "value": "default 100"},
            ],
        )

        decision = self.daemon.store.latest_undoable_decision(kinds=("qos",))
        result = self.daemon.handle(
            {
                "cmd": "feedback",
                "v": 2,
                "id": "qos-late-undo",
                "op": "undo",
                "action_id": str(decision["id"]),
            }
        )
        self.assertEqual(result["target_decision_id"], decision["id"])
        self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")

    def test_keep_answer_restores_shared_scope_and_prevents_reapplication(self):
        path = self.add_scope_controls(
            "shared/vite", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        with mock.patch.object(service.policy, "app_key", return_value="vite"):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            result = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "qos-shared-keep",
                    "op": "answer",
                    "owner": "npm",
                    "leftovers": ["vite"],
                    "choice": "keep",
                }
            )
            self.assertTrue(result["ok"])
            self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
            self.daemon.qos_pass(now=110.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
        self.assertIn("shared/vite", self.daemon.store.data["qos_exempt"])

    def test_protected_member_is_denied_by_common_qos_authorization(self):
        path = self.add_scope_controls("shared/protected", {"cpu.weight": "100\n"})
        with mock.patch.object(
            service.policy, "protected_reason", return_value="protected comm steam"
        ):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
        self.assertNotIn("shared/protected", self.daemon.store.data["qos_scopes"])
        self.assertTrue(
            any(
                event["event"] == "qos_refused"
                and "protected comm" in event.get("data", {}).get("reason", "")
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_shared_scope_uses_weight_fifty_and_enables_parent_controllers_once(self):
        path = self.add_scope_controls(
            "shared/adb", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        with mock.patch.object(
            qos, "enable_controllers", wraps=qos.enable_controllers
        ) as enable:
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            self.daemon.qos_pass(now=110.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 50\n")
        self.assertEqual(enable.call_count, 2)

    def test_same_class_control_drift_does_not_trigger_another_write(self):
        path = self.add_scope_controls(
            "shared/helper", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")

        write(os.path.join(path, "cpu.weight"), "80\n")
        write(os.path.join(path, "io.weight"), "default 80\n")
        self.daemon.qos_pass(now=103.0)
        self.daemon.qos_pass(now=105.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "80\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 80\n")

    def test_controller_enablement_is_retried_after_a_failure(self):
        path = self.add_scope_controls("shared/retry", {})
        calls = []

        def enable_on_retry(parent):
            calls.append(parent)
            if len(calls) == 3:
                write(os.path.join(path, "cpu.weight"), "100\n")
            return "temporary delegation failure" if len(calls) <= 2 else None

        with mock.patch.object(qos, "enable_controllers", side_effect=enable_on_retry):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            record = self.daemon.store.data["qos_scopes"]["shared/retry"]
            self.assertFalse(record["controllers_ready"])

            self.daemon.last.update(adopt=117.0, gc=117.0, memory=117.0)
            self.daemon.qos_pass(now=117.0)
            self.assertAlmostEqual(self.daemon.next_timeout(now=117.0), 2.0)
            self.daemon.qos_pass(now=119.0)

        self.assertEqual(len(calls), 4)
        self.assertTrue(
            self.daemon.store.data["qos_scopes"]["shared/retry"]["controllers_ready"]
        )
        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")

    def test_removed_scope_clears_unpersisted_debounce_state(self):
        path = self.add_scope_controls("leftover/transient", {"cpu.idle": "0\n"})
        self.daemon.qos_pass(now=100.0)
        self.assertIn("leftover/transient", self.daemon.qos_pending)

        shutil.rmtree(path)
        self.daemon.last.update(adopt=103.0, gc=103.0, memory=103.0)
        self.daemon.qos_pass(now=103.0)

        self.assertNotIn("leftover/transient", self.daemon.qos_pending)
        self.assertGreater(self.daemon.next_timeout(now=103.0), 0.0)

    def test_unclassified_live_app_does_not_schedule_a_qos_debounce(self):
        self.add_scope_controls("app-active", {"cpu.weight": "100\n"})
        self.daemon.last.update(adopt=100.0, gc=100.0, memory=100.0)

        self.daemon.qos_pass(now=100.0)

        self.assertNotIn("app-active", self.daemon.qos_pending)
        self.assertGreater(self.daemon.next_timeout(now=100.0), 0.0)

    def test_observe_only_logs_and_marks_the_would_be_class(self):
        path = self.add_scope_controls(
            "leftover/preview", {"cpu.idle": "0\n", "io.weight": "default 100\n"}
        )
        self.daemon.cfg["mode"] = "observe"
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")
        self.assertTrue(
            any(
                event["event"] == "qos_would"
                for event in self.daemon.store.events_since(0)["events"]
            )
        )
        self.assertEqual(
            self.daemon.store.data["qos_scopes"]["leftover/preview"]["class"],
            "leftover",
        )

    def test_observe_record_does_not_create_an_expired_controller_timer(self):
        self.add_scope_controls("shared/preview", {"cpu.weight": "100\n"})
        self.daemon.cfg["mode"] = "observe"
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        self.daemon.last.update(adopt=102.0, gc=102.0, memory=102.0)

        self.assertGreater(self.daemon.next_timeout(now=102.0), 0.0)

    def test_keep_answer_restores_controls_and_prevents_reapplication(self):
        path = self.add_scope_controls(
            "leftover/vite",
            {
                "cpu.idle": "0\n",
                "io.weight": "default 100\n",
                "memory.oom.group": "0\n",
            },
        )
        with (
            mock.patch.object(service.policy, "app_key", return_value="vite"),
            fake_oom_process({42: -100}) as oom_process,
        ):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            result = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "qos-keep-1",
                    "op": "answer",
                    "owner": "npm",
                    "leftovers": ["vite"],
                    "choice": "keep",
                }
            )
            self.assertTrue(result["ok"])
            self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
            self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
            oom_process.restore.assert_called_once_with(
                self.daemon.cfg, 42, 1042, -100, 500
            )
            self.daemon.qos_pass(now=110.0)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertIn("leftover/vite", self.daemon.store.data["qos_exempt"])

    def test_standalone_answer_restores_controls(self):
        path = self.add_scope_controls(
            "leftover/vite",
            {
                "cpu.idle": "0\n",
                "io.weight": "default 100\n",
                "memory.oom.group": "0\n",
            },
        )
        with (
            mock.patch.object(service.policy, "app_key", return_value="vite"),
            fake_oom_process({42: -100}) as oom_process,
        ):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=102.0)
            result = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "qos-standalone-1",
                    "op": "answer",
                    "owner": "npm",
                    "leftovers": ["vite"],
                    "choice": "standalone",
                }
            )
        self.assertTrue(result["ok"])
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")
        self.assertEqual(Path(path, "memory.oom.group").read_text(), "0\n")
        oom_process.restore.assert_called_once_with(
            self.daemon.cfg, 42, 1042, -100, 500
        )

    def test_idle_app_scope_gets_background_weights_then_restores_when_active(self):
        path = self.add_scope_controls(
            "app-firefox", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        write(os.path.join(path, "cpu.stat"), "usage_usec 0\n")
        with (
            mock.patch.object(
                service.inspect,
                "LazySnapshot",
                return_value=SimpleNamespace(get=lambda: SimpleNamespace(ok=True)),
            ),
            mock.patch.object(service.inspect, "edges", return_value={}),
        ):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=105.0)
            self.daemon.qos_pass(now=107.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "50\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 50\n")

        write(os.path.join(path, "cpu.stat"), "usage_usec 1000000\n")
        with (
            mock.patch.object(
                service.inspect,
                "LazySnapshot",
                return_value=SimpleNamespace(get=lambda: SimpleNamespace(ok=True)),
            ),
            mock.patch.object(service.inspect, "edges", return_value={}),
        ):
            self.daemon.qos_pass(now=110.0)
            self.daemon.qos_pass(now=112.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")

    def test_podman_runtime_scope_keeps_normal_weight_despite_idle_cpu(self):
        path = self.add_scope_controls(
            "app-podman-deadbeef", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        write(os.path.join(path, "cpu.stat"), "usage_usec 0\n")
        self.daemon.units = [
            {
                "unit": {
                    "name": "app-podman",
                    "kind": "app",
                    "group_by_env": "XDG_RUNTIME_DIR",
                },
                "gc": {"keep_while_children": True},
            }
        ]
        with (
            mock.patch.object(
                service.inspect,
                "LazySnapshot",
                return_value=SimpleNamespace(get=lambda: SimpleNamespace(ok=True)),
            ),
            mock.patch.object(service.inspect, "edges", return_value={}),
        ):
            self.daemon.qos_pass(now=100.0)
            self.daemon.qos_pass(now=105.0)
            self.daemon.qos_pass(now=107.0)
        self.assertEqual(Path(path, "cpu.weight").read_text(), "100\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")
        self.assertNotIn("app-podman-deadbeef", self.daemon.store.data["qos_scopes"])

    def test_store_persists_qos_scope_classification(self):
        self.add_scope_controls(
            "shared/adb", {"cpu.weight": "100\n", "io.weight": "default 100\n"}
        )
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        self.daemon.store.save()
        reopened = service.knowledge.Store(self.daemon.store.dir, {}, read_only=True)
        self.assertEqual(reopened.data["qos_scopes"]["shared/adb"]["class"], "shared")


class QoSViews(unittest.TestCase):
    def test_ls_marks_persisted_deprioritized_scopes(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state_dir:
            cg.leaf("leftover/browser")
            cfg = make_cfg(state_dir, mode="observe")
            cfg["mem"] = {"enabled": False}
            store = service.knowledge.Store(state_dir, {})
            store.data["qos_scopes"] = {
                "leftover/browser": {"class": "leftover", "deprioritized": True}
            }
            output = io.StringIO()
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                redirect_stdout(output),
            ):
                self.assertEqual(
                    cli.cmd_ls(SimpleNamespace(json=False, jsonl=False, wide=True)), 0
                )
            self.assertIn("browser ↓", output.getvalue())

    def test_why_marks_deprioritized_live_scope(self):
        with tempfile.TemporaryDirectory() as state_dir:
            cfg = make_cfg(state_dir, mode="observe")
            store = service.knowledge.Store(state_dir, {})
            store.data["qos_scopes"] = {
                "leftover/browser": {"class": "leftover", "deprioritized": True}
            }
            explanation = cli._why_report(
                cfg,
                store,
                target_scope="leftover/browser",
                scope_live=True,
            )
            self.assertTrue(explanation["scope"]["deprioritized"])
            self.assertIn(
                "leftover/browser ↓",
                view.render_explanation("scope:leftover/browser", explanation),
            )
