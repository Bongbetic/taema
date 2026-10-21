"""Reversible QoS classification for contained scopes."""

import io
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import taema.cli.commands as cli
from taema.core import cgroup, qos
from taema.daemon import service
from taema.cli import view
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


class QoSIntegration(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.cfg = make_cfg(os.path.join(self.cg.root, "state"), mode="enforce")
        self.cfg["memory"] = {"enabled": False}
        self.daemon = service.Daemon(self.cfg)
        protection = mock.patch.object(
            service.policy, "protected_reason", return_value=None
        )
        protection.start()
        self.addCleanup(protection.stop)

    def add_scope_controls(self, scope, controls):
        path = self.cg.leaf(scope, [42])
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
        self.daemon.qos_pass(now=now + qos.DEBOUNCE_SECONDS - 0.01)
        path = cgroup.resolve(scope)
        return path

    def test_leftover_controls_wait_two_seconds_and_restore_through_undo(self):
        path = self.add_scope_controls(
            "leftover/browser",
            {
                "cpu.idle": "0\n",
                "cpu.weight": "100\n",
                "io.weight": "default 100\n",
                "pids.max": "max\n",
            },
        )

        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=101.99)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 100\n")

        self.daemon.qos_pass(now=102.0)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "1\n")
        self.assertEqual(Path(path, "io.weight").read_text(), "default 10\n")
        self.assertEqual(Path(path, "pids.max").read_text(), "max\n")
        self.assertEqual(
            self.daemon.store.data["qos_scopes"]["leftover/browser"]["class"],
            "leftover",
        )

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
        self.assertIn("leftover/browser", self.daemon.store.data["qos_exempt"])

        self.daemon.qos_pass(now=110.0)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")

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
            "leftover/vite", {"cpu.idle": "0\n", "io.weight": "default 100\n"}
        )
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        with mock.patch.object(service.policy, "app_key", return_value="vite"):
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
            self.daemon.qos_pass(now=110.0)
        self.assertEqual(Path(path, "cpu.idle").read_text(), "0\n")
        self.assertIn("leftover/vite", self.daemon.store.data["qos_exempt"])

    def test_standalone_answer_restores_controls(self):
        path = self.add_scope_controls(
            "leftover/vite", {"cpu.idle": "0\n", "io.weight": "default 100\n"}
        )
        self.daemon.qos_pass(now=100.0)
        self.daemon.qos_pass(now=102.0)
        with mock.patch.object(service.policy, "app_key", return_value="vite"):
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
            cfg["memory"] = {"enabled": False}
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
