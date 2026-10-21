"""Budget arithmetic and managed memory-control integration tests."""

import json
import io
import os
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema.cli import commands
from taema.daemon import service
from taema.governor import memory_budget
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_ipc_v2 import matches
from tests.test_phase1 import write

MIB = 1024**2
GIB = 1024**3
ROOT = Path(__file__).resolve().parents[1]
CLI_SCHEMA = json.loads((ROOT / "schema/cli/read-v1.json").read_text())


def scope_files(path, current, *, high="max", low="0", maximum="max"):
    write(path + "/memory.current", "%d\n" % current)
    write(path + "/memory.high", high + "\n")
    write(path + "/memory.low", low + "\n")
    write(path + "/memory.max", maximum + "\n")
    write(path + "/memory.swap.max", "max\n")
    write(path + "/memory.swap.current", "0\n")
    write(path + "/memory.zswap.writeback", "1\n")
    write(path + "/memory.stat", "anon 1\nfile 1\ninactive_file 1\n")


def snapshot(*scopes, cap=6 * GIB, total=8 * GIB):
    return {
        "enabled": True,
        "host": {"total_bytes": total},
        "scopes": [
            {
                "name": name,
                "class": "app",
                "current_bytes": current,
            }
            for name, current in scopes
        ],
        "delegated_max_bytes": cap,
    }


class MemoryBudgetArithmeticTests(unittest.TestCase):
    def test_budget_headroom_and_alignment_reject_invalid_boundaries(self):
        self.assertEqual(memory_budget.budget_bytes(-1, None), 0)
        self.assertEqual(memory_budget.budget_bytes(GIB, None, True), 0)
        self.assertEqual(memory_budget.budget_bytes(GIB, -1), 0)
        self.assertEqual(memory_budget.budget_bytes(GIB, None, explicit=-1), 0)
        self.assertIsNone(memory_budget.headroom_bytes(None))
        self.assertIsNone(memory_budget.headroom_bytes(10, minimum=True))
        self.assertIsNone(memory_budget.headroom_bytes(10, percent=float("nan")))
        with self.assertRaises(ValueError):
            memory_budget.align_up(10, 0)
        self.assertTrue(memory_budget.materially_changed("max", 100))
        self.assertTrue(memory_budget.materially_changed("invalid", 100))

    def test_budget_and_headroom_hold_for_a_range_of_inputs(self):
        for total in (0, MIB, 512 * MIB, GIB, 16 * GIB):
            for cap in (None, 0, MIB, 4 * GIB, 32 * GIB):
                for fraction in (0, 0.2, 0.8, 1):
                    budget = memory_budget.budget_bytes(total, cap, fraction)
                    self.assertLessEqual(budget, int(total * fraction))
                    if cap is not None:
                        self.assertLessEqual(budget, cap)
                    for current in (0, MIB, 128 * MIB, 4 * GIB):
                        headroom = memory_budget.headroom_bytes(current, 128 * MIB, 10)
                        self.assertGreaterEqual(headroom, 128 * MIB)
                        self.assertGreaterEqual(headroom, current * 0.1)

    def test_class_reservations_and_background_shares_stay_inside_allocatable_budget(
        self,
    ):
        scopes = [
            memory_budget.BudgetScope("app-active", "app", False),
            memory_budget.BudgetScope("app-idle-a", "app", True),
            memory_budget.BudgetScope("app-idle-b", "app", True),
            memory_budget.BudgetScope("container-x", "container", False),
        ]
        result = memory_budget.plan(8 * GIB, 512 * MIB, 512 * MIB, scopes)
        self.assertEqual(result.allocatable_bytes, 7 * GIB)
        self.assertEqual(sum(result.reservations.values()), result.reserved_bytes)
        self.assertEqual(sum(result.shares.values()), result.background_bytes)
        self.assertLessEqual(
            result.reserved_bytes + result.background_bytes,
            result.allocatable_bytes,
        )


class MemoryBudgetDaemonTests(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg()
        self.cg.__enter__()
        self.active = self.cg.leaf("app-active", [91])
        self.idle = self.cg.leaf("app-idle", [92])
        scope_files(self.active, GIB)
        scope_files(self.idle, 512 * MIB)
        write(self.cg.base + "/memory.max", "%d\n" % (6 * GIB))
        self.cfg = make_cfg(tmp(), mode="adopt")
        self.cfg["mem"] = {
            "enabled": True,
            "manage": "soft",
            "budget": "auto",
            "fraction": 0.8,
            "floor": "512M",
            "min_headroom": "128M",
            "headroom_percent": 10,
        }
        self.daemon = service.Daemon(self.cfg)
        self.now = 1000.0
        self.daemon.qos_idle_since["app-idle"] = self.now - 10
        self.snapshot = snapshot(("app-active", GIB), ("app-idle", 512 * MIB))
        self.authorization = mock.patch.object(
            self.daemon,
            "_qos_hard_safety",
            return_value="",
        )
        self.authorization.start()
        self.addCleanup(self.authorization.stop)
        self.addCleanup(self.cg.patch.stop)

    def test_soft_budget_protects_active_scope_and_sets_background_high(self):
        report = self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        self.assertEqual(report["budget_bytes"], 6 * GIB)
        active = next(row for row in report["scopes"] if row["name"] == "app-active")
        self.assertGreaterEqual(
            int(Path(self.active, "memory.low").read_text()),
            active["desired_low_bytes"],
        )
        idle = next(row for row in report["scopes"] if row["name"] == "app-idle")
        self.assertTrue(idle["background"])
        applied_high = int(Path(self.idle, "memory.high").read_text())
        self.assertGreaterEqual(
            applied_high,
            idle["current_bytes"] + idle["headroom_bytes"],
        )
        self.assertEqual(Path(self.active, "memory.max").read_text(), "max\n")

    def test_interactive_unit_is_an_active_app_reservation(self):
        self.daemon.units = [
            {
                "unit": {
                    "name": "app-active",
                    "kind": "app",
                    "class": "interactive",
                }
            }
        ]
        report = self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        active = next(row for row in report["scopes"] if row["name"] == "app-active")
        self.assertEqual(active["class"], "app")
        self.assertGreater(active["reservation_bytes"], 0)
        self.assertEqual(report["infrastructure_bytes"], 0)
        self.assertGreater(int(Path(self.active, "memory.low").read_text()), 0)

    def test_arbitrary_named_vm_unit_is_included_in_budget_and_hard_cap(self):
        vm = self.cg.leaf("my-vm", [93])
        scope_files(vm, GIB)
        self.cfg["mem"]["manage"] = "hard"
        self.daemon.units = [
            {"unit": {"name": "my-vm", "kind": "vm"}, "mem": {"max": "2G"}}
        ]
        report = self.daemon.memory_governor_pass(
            now=self.now, snapshot=snapshot(("my-vm", GIB))
        )
        row = next(item for item in report["scopes"] if item["name"] == "my-vm")
        self.assertEqual(row["class"], "vm")
        self.assertGreater(row["reservation_bytes"], 0)
        self.assertEqual(Path(vm, "memory.max").read_text(), "%d\n" % (2 * GIB))

    def test_vm_swap_limit_defaults_to_zero_even_above_current_usage(self):
        vm = self.cg.leaf("my-vm", [93])
        scope_files(vm, GIB)
        write(vm + "/memory.swap.current", "%d\n" % (64 * MIB))
        self.daemon.units = [{"unit": {"name": "my-vm", "kind": "vm"}}]
        vm_snapshot = snapshot(("my-vm", GIB))
        plan = self.daemon.memory_governor_pass(now=self.now, snapshot=vm_snapshot)
        row = next(item for item in plan["scopes"] if item["name"] == "my-vm")
        self.assertEqual(row["desired_swap_max_bytes"], 0)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "0\n")
        self.assertEqual(Path(vm, "memory.zswap.writeback").read_text(), "1\n")

        self.daemon.mark_vm_saved("my-vm")
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=vm_snapshot)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "max\n")
        self.daemon.mark_vm_resumed("my-vm")
        self.daemon.memory_governor_pass(now=self.now + 120, snapshot=vm_snapshot)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "0\n")

    def test_saved_vm_guard_returns_when_member_processes_are_replaced(self):
        vm = self.cg.leaf("my-vm", [93])
        scope_files(vm, GIB)
        self.daemon.units = [{"unit": {"name": "my-vm", "kind": "vm"}}]
        vm_snapshot = snapshot(("my-vm", GIB))
        self.daemon.memory_governor_pass(now=self.now, snapshot=vm_snapshot)
        self.daemon.mark_vm_saved("my-vm")
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=vm_snapshot)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "max\n")

        self.cg.set_procs("my-vm", [])
        self.daemon.memory_governor_pass(
            now=self.now + 120, snapshot=snapshot(("my-vm", GIB))
        )
        self.assertIn("my-vm", self.daemon.saved_vm_scopes)
        self.cg.set_procs("my-vm", [94])
        self.daemon.memory_governor_pass(
            now=self.now + 180, snapshot=snapshot(("my-vm", GIB))
        )
        self.assertNotIn("my-vm", self.daemon.saved_vm_scopes)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "0\n")

    def test_vm_unit_swap_max_is_applied_and_external_change_is_preserved(self):
        vm = self.cg.leaf("my-vm", [93])
        scope_files(vm, GIB)
        self.daemon.units = [
            {
                "unit": {"name": "my-vm", "kind": "vm"},
                "mem": {"swap_max": "2G"},
            }
        ]
        vm_snapshot = snapshot(("my-vm", GIB))
        plan = self.daemon.memory_governor_pass(now=self.now, snapshot=vm_snapshot)
        row = next(item for item in plan["scopes"] if item["name"] == "my-vm")
        self.assertEqual(row["desired_swap_max_bytes"], 2 * GIB)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "%d\n" % (2 * GIB))

        write(vm + "/memory.swap.max", "%d\n" % (3 * GIB))
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=vm_snapshot)
        self.assertEqual(Path(vm, "memory.swap.max").read_text(), "%d\n" % (3 * GIB))
        self.assertTrue(
            any(
                event["event"] == "memory_control_external_change"
                and event.get("data", {}).get("control") == "memory.swap.max"
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_active_transition_restores_owned_high_and_leaves_external_change_alone(
        self,
    ):
        self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        old_high = Path(self.idle, "memory.high").read_text().strip()
        self.assertNotEqual(old_high, "max")
        self.daemon.qos_idle_since.clear()
        next_snapshot = snapshot(("app-active", GIB), ("app-idle", 512 * MIB))
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=next_snapshot)
        self.assertEqual(Path(self.idle, "memory.high").read_text(), "max\n")
        self.assertGreater(int(Path(self.idle, "memory.low").read_text()), 0)

    def test_scope_exit_restores_reservation_and_logs_rebalance(self):
        self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        self.cg.set_procs("app-active", [])
        remaining = snapshot(("app-idle", 512 * MIB))
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=remaining)
        self.assertEqual(Path(self.active, "memory.low").read_text(), "0\n")
        self.assertTrue(
            any(
                event["event"] == "rebalance"
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_controls_are_not_restored_after_scope_becomes_unowned(self):
        self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        prior_low = Path(self.active, "memory.low").read_text()
        self.assertNotEqual(prior_low, "0\n")
        with (
            mock.patch.object(self.daemon, "_memory_scope_owned", return_value=False),
            mock.patch.object(
                service.memory,
                "_write_control",
                wraps=service.memory._write_control,
            ) as write_control,
        ):
            self.daemon._memory_restore_scope("app-active", self.active)
            self.daemon.memory_governor_pass(now=self.now + 60, snapshot=self.snapshot)
        write_control.assert_not_called()
        self.assertEqual(Path(self.active, "memory.low").read_text(), prior_low)
        self.assertNotIn("app-active", self.daemon.store.data["memory_scopes"])

    def test_empty_managed_scope_after_restart_logs_rebalance(self):
        self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        self.daemon.memory_scope_seen.clear()
        self.cg.set_procs("app-active", [])
        remaining = snapshot(("app-active", 0), ("app-idle", 512 * MIB))
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=remaining)
        events = self.daemon.store.events_since(0)["events"]
        self.assertTrue(any(event["event"] == "rebalance" for event in events))

    def test_force_restore_releases_all_controls(self):
        self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        self.daemon.memory_governor_pass(force_restore=True)
        self.assertEqual(Path(self.active, "memory.low").read_text(), "0\n")
        self.assertEqual(Path(self.idle, "memory.high").read_text(), "max\n")

    def test_high_updates_skip_changes_under_five_percent_but_keep_headroom(self):
        write(self.idle + "/memory.high", "%d\n" % (100 * MIB))
        self.assertTrue(
            self.daemon._memory_apply_control(
                "app-idle",
                self.idle,
                "memory.high",
                104 * MIB,
                soft_threshold=True,
                minimum_target=90 * MIB,
            )
        )
        self.assertEqual(
            Path(self.idle, "memory.high").read_text(), "%d\n" % (100 * MIB)
        )
        self.daemon._memory_apply_control(
            "app-idle",
            self.idle,
            "memory.high",
            101 * MIB,
            soft_threshold=True,
            minimum_target=101 * MIB,
        )
        self.assertEqual(
            Path(self.idle, "memory.high").read_text(), "%d\n" % (101 * MIB)
        )

    def test_hard_cap_requires_explicit_unit_value_and_current_plus_headroom(self):
        self.cfg["mem"]["manage"] = "hard"
        self.daemon.units = [
            {"unit": {"name": "app-active", "kind": "app"}, "mem": {"max": "2G"}}
        ]
        one_scope = snapshot(("app-active", GIB))
        self.daemon.memory_governor_pass(now=self.now, snapshot=one_scope)
        self.assertEqual(
            Path(self.active, "memory.max").read_text(), "%d\n" % (2 * GIB)
        )
        self.daemon.units[0]["mem"]["max"] = "1G"
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=one_scope)
        self.assertEqual(Path(self.active, "memory.max").read_text(), "max\n")
        self.assertTrue(
            any(
                event["event"] == "memory_cap_refused"
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_kernel_normalized_hard_cap_restores_using_effective_value(self):
        requested = 1_395_864_372
        effective = ((requested + 4095) // 4096) * 4096

        def write_rounded(path, name, value):
            rounded = ((int(value) + 4095) // 4096) * 4096
            write(os.path.join(path, name), f"{rounded}\n")

        with mock.patch.object(
            service.memory, "_write_control", side_effect=write_rounded
        ) as writer:
            self.assertTrue(
                self.daemon._memory_apply_control(
                    "app-active", self.active, "memory.max", requested
                )
            )
            self.assertTrue(
                self.daemon._memory_apply_control(
                    "app-active", self.active, "memory.max", requested
                )
            )
            writer.assert_called_once()
        state = self.daemon.store.data["memory_scopes"]["app-active"]["memory.max"]
        self.assertEqual(state["applied"], str(effective))
        self.assertTrue(
            self.daemon._memory_restore_control("app-active", self.active, "memory.max")
        )
        self.assertEqual(Path(self.active, "memory.max").read_text(), "max\n")

    def test_oom_growth_does_not_change_an_explicit_hard_limit(self):
        self.cfg["mem"]["manage"] = "hard"
        self.daemon.units = [
            {"unit": {"name": "app-active", "kind": "app"}, "mem": {"max": "2G"}}
        ]
        one_scope = snapshot(("app-active", GIB))
        self.daemon.memory_governor_pass(now=self.now, snapshot=one_scope)
        write(self.active + "/memory.events", "oom 100\n")
        self.daemon.memory_governor_pass(now=self.now + 60, snapshot=one_scope)
        self.assertEqual(
            Path(self.active, "memory.max").read_text(), "%d\n" % (2 * GIB)
        )

    def test_observe_and_unowned_scopes_do_not_write_controls(self):
        self.cfg["mode"] = "observe"
        with mock.patch.object(self.daemon, "_memory_scope_owned", return_value=False):
            self.daemon.memory_governor_pass(now=self.now, snapshot=self.snapshot)
        self.assertEqual(Path(self.active, "memory.low").read_text(), "0\n")
        self.assertEqual(Path(self.idle, "memory.high").read_text(), "max\n")

    def test_memory_budget_cli_emits_schema_valid_json(self):
        report = self.daemon._memory_budget_report(self.snapshot, self.now)
        output = io.StringIO()
        with (
            mock.patch.object(
                commands, "_memory_config", return_value=(self.cfg, None)
            ),
            mock.patch.object(commands, "ask", return_value=report),
            redirect_stdout(output),
        ):
            result = commands.main(["memory", "budget", "--json"])
        self.assertEqual(result, 0)
        self.assertTrue(matches(json.loads(output.getvalue()), CLI_SCHEMA, CLI_SCHEMA))


if __name__ == "__main__":
    unittest.main()
