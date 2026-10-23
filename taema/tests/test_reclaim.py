"""Bounded page-cache reclaim through memory and daemon command seams."""

import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema import protocol
from taema.cli import commands
from taema.core import memory
from taema.daemon import service
from taema.model import authorization
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_ipc_v2 import matches
from tests.test_phase1 import write

MIB = 1024**2
ROOT = Path(__file__).resolve().parents[1]
CLI_SCHEMA = json.loads((ROOT / "schema" / "cli" / "read-v1.json").read_text())


def write_scope(
    path,
    *,
    current=1024 * MIB,
    anon=256 * MIB,
    file=640 * MIB,
    swap=0,
    zswap=0,
):
    write(path + "/memory.current", "%d\n" % current)
    write(
        path + "/memory.stat",
        "anon %d\nfile %d\ninactive_file %d\nshmem %d\n"
        "workingset_refault_file 4\npgmajfault 1\n" % (anon, file, 600 * MIB, 32 * MIB),
    )
    write(path + "/memory.events", "low 0\nhigh 2\nmax 0\nome 0\n")
    write(
        path + "/memory.pressure", "some avg10=0.00 total=0\nfull avg10=0.00 total=0\n"
    )
    write(path + "/memory.high", "max\n")
    write(path + "/memory.reclaim", "")
    write(path + "/memory.swap.current", "%d\n" % swap)
    write(path + "/memory.swap.max", "max\n")
    write(path + "/memory.zswap.current", "%d\n" % zswap)
    write(path + "/memory.zswap.writeback", "1\n")
    write(path + "/cgroup.freeze", "0\n")


class ReclaimMemoryTests(unittest.TestCase):
    def test_pressure_reports_some_and_full(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "memory.pressure")
            write(path, "some avg10=11.25 total=1\nfull avg10=2.50 total=2\n")
            self.assertEqual(
                memory.pressure(path), {"some_avg10": 11.25, "full_avg10": 2.5}
            )

    def test_page_cache_budget_enforces_anon_headroom_and_caps(self):
        self.assertEqual(
            memory.page_cache_budget(
                1024 * MIB,
                256 * MIB,
                800 * MIB,
                memory.ReclaimBounds(300 * MIB, 128 * MIB, 10, 16 * MIB),
            ),
            300 * MIB,
        )
        self.assertEqual(
            memory.page_cache_budget(
                1024 * MIB,
                900 * MIB,
                800 * MIB,
                memory.ReclaimBounds(2 * 1024 * MIB, 128 * MIB, 10),
            ),
            0,
        )

    def test_anonymous_budget_obeys_resident_swap_and_request_bounds(self):
        amount = memory.anonymous_reclaim_budget(
            1000 * MIB,
            500 * MIB,
            60 * MIB,
            100 * MIB,
            200 * MIB,
            memory.ReclaimBounds(400 * MIB, 128 * MIB, 10, MIB),
        )
        self.assertEqual(amount, 40 * MIB)
        self.assertEqual(
            memory.anonymous_reclaim_budget(
                1000 * MIB,
                500 * MIB,
                100 * MIB,
                100 * MIB,
                200 * MIB,
                memory.ReclaimBounds(400 * MIB, 128 * MIB, 10, MIB),
            ),
            0,
        )
        self.assertEqual(
            memory.anonymous_reclaim_budget(
                1000 * MIB,
                500 * MIB,
                0,
                None,
                0,
                memory.ReclaimBounds(400 * MIB, 128 * MIB, 10, MIB),
            ),
            0,
        )

    def test_counter_delta_preserves_direction_and_unknown_values(self):
        self.assertEqual(memory.counter_delta(100, 75, direction="decrease"), 25)
        self.assertEqual(memory.counter_delta(75, 100, direction="decrease"), 0)
        self.assertEqual(memory.counter_delta(75, 100, direction="increase"), 25)
        self.assertIsNone(memory.counter_delta(None, 100, direction="increase"))

    def test_swap_controls_and_available_host_swap_are_read_conservatively(self):
        with tempfile.TemporaryDirectory() as root:
            scope = os.path.join(root, "scope")
            proc = os.path.join(root, "proc")
            os.makedirs(scope)
            os.makedirs(proc)
            write(scope + "/memory.swap.max", "max\n")
            write(proc + "/meminfo", "SwapTotal: 2097152 kB\nSwapFree: 1048576 kB\n")
            self.assertEqual(memory.swap_limit(scope), "max")
            self.assertEqual(memory.swap_available_bytes(proc), MIB * 1024)
            write(proc + "/meminfo", "SwapTotal: 1024 kB\nSwapFree: 2048 kB\n")
            self.assertIsNone(memory.swap_available_bytes(proc))

    def test_anonymous_reclaim_requests_swap_without_changing_zswap_writeback(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.reclaim", "")
            write(path + "/memory.zswap.writeback", "0\n")
            self.assertEqual(memory.reclaim_anonymous(path, 32 * MIB), "memory.reclaim")
            self.assertEqual(
                Path(path, "memory.reclaim").read_text(),
                "%d swappiness=max\n" % (32 * MIB),
            )
            self.assertEqual(Path(path, "memory.zswap.writeback").read_text(), "0\n")

    def test_scope_counters_exclude_shmem_from_inactive_file(self):
        with tempfile.TemporaryDirectory() as path:
            write_scope(path)
            counters = memory.scope_counters(path)
        self.assertEqual(counters["reclaimable_bytes"], 600 * MIB)
        self.assertEqual(counters["workingset_refault_file"], 4)
        self.assertEqual(counters["pgmajfault"], 1)
        self.assertEqual(counters["swap_bytes"], 0)
        self.assertEqual(counters["zswap_bytes"], 0)

    def test_targeted_reclaim_requests_file_only_pages(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.reclaim", "")
            self.assertEqual(
                memory.reclaim_page_cache(path, 32 * MIB, 700 * MIB),
                "memory.reclaim",
            )
            self.assertEqual(
                Path(path, "memory.reclaim").read_text(),
                "%d swappiness=0\n" % (32 * MIB),
            )

    def test_unsupported_targeted_reclaim_restores_high_after_interruption(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.high", "max\n")
            write(path + "/memory.swap.current", "0\n")
            write(path + "/memory.swap.max", "max\n")
            real_write = memory._write_control

            def fail_reclaim(target, name, value):
                if name == "memory.reclaim":
                    raise OSError(errno.EOPNOTSUPP, "unsupported")
                return real_write(target, name, value)

            with (
                mock.patch.object(memory, "_write_control", side_effect=fail_reclaim),
                mock.patch.object(
                    memory.time, "sleep", side_effect=RuntimeError("stop")
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "stop"):
                    memory.reclaim_page_cache(path, 64 * MIB, 900 * MIB)
            self.assertEqual(Path(path, "memory.high").read_text(), "max\n")
            self.assertEqual(Path(path, "memory.swap.max").read_text(), "max\n")

    def test_fallback_refuses_when_swap_is_in_use(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.high", "max\n")
            write(path + "/memory.swap.current", "4096\n")
            write(path + "/memory.swap.max", "max\n")
            real_write = memory._write_control

            def fail_reclaim(target, name, value):
                if name == "memory.reclaim":
                    raise OSError(errno.EOPNOTSUPP, "unsupported")
                return real_write(target, name, value)

            with mock.patch.object(memory, "_write_control", side_effect=fail_reclaim):
                with self.assertRaisesRegex(OSError, "swap is in use"):
                    memory.reclaim_page_cache(path, 64 * MIB, 900 * MIB)
            self.assertEqual(Path(path, "memory.high").read_text(), "max\n")
            self.assertEqual(Path(path, "memory.swap.max").read_text(), "max\n")

    def test_fallback_aligns_high_to_kernel_page_size_before_restoring(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.high", "max\n")
            write(path + "/memory.swap.current", "0\n")
            write(path + "/memory.swap.max", "max\n")
            real_write = memory._write_control
            written = []

            def emulate_kernel(target, name, value):
                if name == "memory.reclaim":
                    raise OSError(errno.ENOENT, "unsupported")
                if name == "memory.high" and value != "max":
                    value = (int(value) // 4096) * 4096
                    written.append(value)
                return real_write(target, name, value)

            with (
                mock.patch.object(memory, "_write_control", side_effect=emulate_kernel),
                mock.patch.object(memory.time, "sleep"),
            ):
                self.assertEqual(
                    memory.reclaim_page_cache(path, 64 * MIB, 900 * MIB + 1),
                    "memory.high",
                )
            self.assertEqual(written, [900 * MIB + 4096])
            self.assertEqual(Path(path, "memory.high").read_text(), "max\n")
            self.assertEqual(Path(path, "memory.swap.max").read_text(), "max\n")

    def test_fallback_does_not_raise_an_existing_high_limit(self):
        with tempfile.TemporaryDirectory() as path:
            write(path + "/memory.high", "%d\n" % (700 * MIB))
            real_write = memory._write_control

            def fail_reclaim(target, name, value):
                if name == "memory.reclaim":
                    raise OSError(errno.ENOENT, "unsupported")
                return real_write(target, name, value)

            with mock.patch.object(memory, "_write_control", side_effect=fail_reclaim):
                with self.assertRaises(OSError):
                    memory.reclaim_page_cache(path, 64 * MIB, 800 * MIB)
            self.assertEqual(
                Path(path, "memory.high").read_text(), "%d\n" % (700 * MIB)
            )


class ReclaimAuthorizationTests(unittest.TestCase):
    def test_modes_and_force_veto_keep_hard_safety_and_holds_stronger(self):
        for mode in authorization.MODES:
            automatic = authorization.authorize(authorization.RECLAIM, mode)
            manual = authorization.authorize(authorization.MANUAL_RECLAIM, mode)
            self.assertEqual(automatic.verdict, "would" if mode == "observe" else "act")
            self.assertEqual((manual.verdict, manual.authority), ("act", "manual"))

        overridden = authorization.authorize(
            authorization.MANUAL_RECLAIM,
            "auto",
            authorization.Facts(vetoed="user veto", force_veto=True),
        )
        held = authorization.authorize(
            authorization.MANUAL_RECLAIM,
            "auto",
            authorization.Facts(vetoed="user veto", held="scope hold", force_veto=True),
        )
        protected = authorization.authorize(
            authorization.MANUAL_RECLAIM,
            "auto",
            authorization.Facts(
                vetoed="user veto", hard_safety="protected member", force_veto=True
            ),
        )
        self.assertEqual(overridden.verdict, "act")
        self.assertEqual((held.verdict, held.slot), ("keep", authorization.HOLD))
        self.assertEqual(
            (protected.verdict, protected.slot), ("keep", authorization.HARD_SAFETY)
        )


class DaemonReclaimTests(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.scope = "leftover/reclaim-test"
        self.path = self.cg.leaf(self.scope, [4242])
        write_scope(self.path)
        cfg = make_cfg(tmp(), mode="auto")
        cfg["mem"] = {
            "enabled": True,
            "reclaim": True,
            "reclaim_max": "2G",
            "reclaim_minimum": "16M",
            "min_headroom": "128M",
            "headroom_percent": 10,
            "reclaim_cooldown": 300,
            "idle_reclaim_grace": 300,
            "pressure_gate": 10,
            "pressure_ceiling": 60,
            "swap_reclaim": True,
            "swap_reclaim_adopt": False,
        }
        self.daemon = service.Daemon(cfg)
        self.daemon._infos = lambda pids: [
            {"pid": pid, "protected": "", "ptmx": False, "edges": []} for pid in pids
        ]
        self.uid_patch = mock.patch.object(
            service.inspect, "uid_of", return_value=os.getuid()
        )
        self.uid_patch.start()
        self.addCleanup(self.uid_patch.stop)
        self.own_patch = mock.patch.object(
            service.cgroup, "own_cgroup", return_value=None
        )
        self.own_patch.start()
        self.addCleanup(self.own_patch.stop)
        self.pressure_patch = mock.patch.object(
            service.memory,
            "pressure",
            side_effect=lambda path=None: (
                {"some_avg10": 20.0, "full_avg10": 1.0}
                if path is None
                else {"some_avg10": 0.0, "full_avg10": 0.0}
            ),
        )
        self.pressure_patch.start()
        self.addCleanup(self.pressure_patch.stop)

    def reclaim_and_apply(self, path, amount, _high_target):
        current = memory.scope_counters(path)["current_bytes"]
        stats = memory._stat(path)
        write_scope(
            path,
            current=current - amount,
            anon=stats["anon"],
            file=max(stats["shmem"], stats["file"] - amount),
        )
        return "memory.reclaim"

    def test_public_manual_command_checks_authority_and_records_before_after(self):
        with mock.patch.object(
            service.memory, "reclaim_page_cache", side_effect=self.reclaim_and_apply
        ):
            result = self.daemon.handle({"cmd": "reclaim", "scope": self.scope})
        self.assertEqual(result["status"], "reclaimed")
        self.assertEqual(result["method"], "memory.reclaim")
        self.assertGreater(result["requested_bytes"], 0)
        self.assertLess(result["current_after"], result["current_before"])
        self.assertEqual(self.daemon.reclaim_state[self.scope]["high_events"], 2)
        with open(self.daemon.store.log_path, encoding="utf-8") as stream:
            events = [json.loads(line) for line in stream]
        event = next(row for row in events if row.get("event") == "memory_reclaimed")
        self.assertEqual(event["current_before"], result["current_before"])
        self.assertEqual(event["current_after"], result["current_after"])

    def test_frozen_scope_reclaims_anon_and_reports_swap_destinations(self):
        write(self.path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {self.scope: {"source": "test"}}
        self.daemon.cfg["mem"]["reclaim_max"] = "1G"
        start = memory.scope_counters(self.path)

        def apply_file(target, amount, _high_target):
            write_scope(
                target,
                current=start["current_bytes"] - amount,
                anon=start["anon_bytes"],
                file=start["file_bytes"] - amount,
                swap=start["swap_bytes"],
                zswap=start["zswap_bytes"],
            )
            return "memory.reclaim"

        def apply_anon(target, amount):
            after_file = memory.scope_counters(target)
            write_scope(
                target,
                current=after_file["current_bytes"] - amount,
                anon=after_file["anon_bytes"] - amount,
                file=after_file["file_bytes"],
                swap=after_file["swap_bytes"] + amount,
                zswap=after_file["zswap_bytes"] + amount // 2,
            )
            return "memory.reclaim"

        with (
            mock.patch.object(
                service.memory, "swap_available_bytes", return_value=2 * 1024 * MIB
            ),
            mock.patch.object(
                service.memory, "reclaim_page_cache", side_effect=apply_file
            ),
            mock.patch.object(
                service.memory, "reclaim_anonymous", side_effect=apply_anon
            ) as anon_reclaim,
        ):
            result = self.daemon.handle({"cmd": "reclaim", "scope": self.scope})
        self.assertEqual(result["status"], "reclaimed")
        self.assertGreater(result["anonymous_requested_bytes"], 0)
        self.assertGreater(result["anonymous_reclaimed_bytes"], 0)
        self.assertEqual(
            result["swap_delta_bytes"], result["anonymous_reclaimed_bytes"]
        )
        self.assertEqual(result["zswap_delta_bytes"], result["swap_delta_bytes"] // 2)
        self.assertEqual(Path(self.path, "memory.zswap.writeback").read_text(), "1\n")
        anon_reclaim.assert_called_once()

    def test_adopt_requires_its_extra_anonymous_reclaim_opt_in(self):
        write(self.path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {self.scope: {"source": "test"}}
        self.daemon.cfg["mode"] = "adopt"
        with mock.patch.object(
            service.memory, "swap_available_bytes", return_value=2 * 1024 * MIB
        ):
            denied = self.daemon.reclaim_scope(self.scope, dry_run=True, now=1000)
            self.daemon.cfg["mem"]["swap_reclaim_adopt"] = True
            allowed = self.daemon.reclaim_scope(self.scope, dry_run=True, now=1000)
        self.assertEqual(denied["anonymous_requested_bytes"], 0)
        self.assertIn("adopt", denied["anonymous_reclaim_reason"])
        self.assertGreater(allowed["anonymous_requested_bytes"], 0)

    def test_frozen_scope_skips_idle_sampling_and_no_swap_blocks_only_anon(self):
        write(self.path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {self.scope: {"source": "test"}}
        with (
            mock.patch.object(self.daemon, "_reclaim_idle", side_effect=AssertionError),
            mock.patch.object(service.memory, "swap_available_bytes", return_value=0),
        ):
            result = self.daemon._reclaim_one(
                self.scope,
                self.path,
                1000,
                {"some_avg10": 20.0, "full_avg10": 0.0},
                dry_run=True,
                resource_class="leftover",
            )
        self.assertEqual(result["status"], "would")
        self.assertGreater(result["page_cache_requested_bytes"], 0)
        self.assertEqual(result["anonymous_requested_bytes"], 0)
        self.assertIn("swap and headroom", result["anonymous_reclaim_reason"])

    def test_vm_swap_requires_a_unit_cap_or_successful_save(self):
        scope = "vm-reclaim-test"
        path = self.cg.leaf(scope, [4244])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [{"unit": {"name": scope, "kind": "vm"}}]
        with mock.patch.object(
            service.memory, "swap_available_bytes", return_value=2 * 1024 * MIB
        ):
            guarded = self.daemon.reclaim_scope(scope, dry_run=True, now=1000)
            self.daemon.units[0]["mem"] = {"swap_max": "1G"}
            configured = self.daemon.reclaim_scope(scope, dry_run=True, now=1000)
            self.daemon.mark_vm_saved(scope)
            saved = self.daemon.reclaim_scope(scope, dry_run=True, now=1000)
        self.assertEqual(guarded["anonymous_requested_bytes"], 0)
        self.assertGreater(configured["anonymous_requested_bytes"], 0)
        self.assertGreater(saved["anonymous_requested_bytes"], 0)

    def test_vm_save_hook_uses_validated_arguments_without_a_shell(self):
        scope = "vm-reclaim-test"
        unit = {
            "unit": {"name": scope, "kind": "vm", "domain": "work vm"},
            "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
        }
        process = mock.Mock(returncode=0)
        process.communicate.return_value = ("saved\n", None)
        with mock.patch.object(
            service.subprocess, "Popen", return_value=process
        ) as popen:
            success, reason = self.daemon._run_runtime_hook(scope, unit, 1000)
        self.assertTrue(success)
        self.assertIn("succeeded", reason)
        self.assertIn(scope, self.daemon.saved_vm_scopes)
        self.assertEqual(popen.call_args.args[0], ["virsh", "managedsave", "work vm"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertNotIn("shell", popen.call_args.kwargs)

    def test_vm_save_hook_requires_configured_template_values(self):
        scope = "vm-reclaim-test"
        unit = {
            "unit": {"name": scope, "kind": "vm"},
            "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
        }
        with mock.patch.object(service.subprocess, "Popen") as popen:
            success, reason = self.daemon._run_runtime_hook(scope, unit, 1000)
        self.assertFalse(success)
        self.assertIn("unit.domain", reason)
        popen.assert_not_called()

    def test_runtime_hook_accepts_argv_and_derives_the_qemu_domain(self):
        scope = "vm-reclaim-test"
        self.cg.leaf(scope, [4244])
        unit = {
            "unit": {"name": scope, "kind": "vm", "class": "vm"},
            "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
        }
        process = mock.Mock(returncode=0)
        process.communicate.return_value = ("saved\n", None)
        with (
            mock.patch.object(
                service.inspect,
                "runtime_identity",
                return_value={"domain": "work-vm"},
            ),
            mock.patch.object(
                service.subprocess, "Popen", return_value=process
            ) as popen,
        ):
            success, reason = self.daemon._run_runtime_hook(scope, unit, 1000)

        self.assertTrue(success, reason)
        self.assertEqual(popen.call_args.args[0], ["virsh", "managedsave", "work-vm"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_runtime_hook_rejects_invalid_template_values_before_execution(self):
        scope = "vm-reclaim-test"
        unit = {
            "unit": {"name": scope, "kind": "vm", "class": "vm", "domain": "-unsafe"},
            "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
        }
        with mock.patch.object(service.subprocess, "Popen") as popen:
            success, reason = self.daemon._run_runtime_hook(scope, unit, 1000)

        self.assertFalse(success)
        self.assertIn("valid unit.domain", reason)
        popen.assert_not_called()

    def test_runtime_hook_rejects_command_strings(self):
        unit = {"mem": {"pause": "podman pause %(container)s"}}
        with mock.patch.object(service.subprocess, "Popen") as popen:
            success, reason = self.daemon._run_runtime_hook(
                "podman-test", unit, 1000, field="pause"
            )

        self.assertFalse(success)
        self.assertIn("explicit argv list", reason)
        popen.assert_not_called()

    def test_vm_save_hook_waits_for_idle_grace_even_when_taema_frozen(self):
        scope = "vm-save-grace"
        path = self.cg.leaf(scope, [4246])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        with (
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(False, "idle for 2s")
            ) as idle,
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
            mock.patch.object(service.memory, "reclaim_page_cache") as reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("idle grace", result["reason"])
        idle.assert_called_once()
        hook.assert_not_called()
        reclaim.assert_not_called()

    def test_vm_save_hook_is_blocked_by_management_client_dependency(self):
        scope = "vm-save-attached"
        path = self.cg.leaf(scope, [4250])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        self.daemon._infos = lambda pids: [
            {"pid": pid, "protected": "", "ptmx": False, "edges": [{"kind": "unix"}]}
            for pid in pids
        ]
        with (
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
            mock.patch.object(service.memory, "reclaim_page_cache") as reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("external dependency", result["reason"])
        hook.assert_not_called()
        reclaim.assert_not_called()

    def test_vm_save_hook_rechecks_dependencies_after_idle_grace(self):
        scope = "vm-save-new-attachment"
        path = self.cg.leaf(scope, [4251])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]

        def attach_during_grace(*_args):
            self.daemon._infos = lambda pids: [
                {
                    "pid": pid,
                    "protected": "",
                    "ptmx": False,
                    "edges": [{"kind": "unix"}],
                }
                for pid in pids
            ]
            return True, "idle for 300s"

        with (
            mock.patch.object(
                self.daemon, "_reclaim_idle", side_effect=attach_during_grace
            ),
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("safety check", result["reason"])
        hook.assert_not_called()

    def test_vm_save_hook_requires_explicit_stop_authority(self):
        scope = "vm-save-no-stop-authority"
        path = self.cg.leaf(scope, [4252])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {"name": scope, "kind": "vm", "domain": "test-vm"},
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        with (
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
            mock.patch.object(service.memory, "reclaim_page_cache") as reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("stop authority", result["reason"])
        hook.assert_not_called()
        reclaim.assert_not_called()

    def test_adopt_allows_save_hook_for_pair_authorized_leftover(self):
        scope = "leftover/vm-save-paired"
        unit = {"mem": {"save_state": ["virsh", "managedsave", "test-vm"]}}
        self.daemon.cfg["mode"] = "adopt"
        facts = authorization.Facts(
            scope=scope,
            leftover=True,
            pair_action="stop",
            pair_reason="user answered stop",
            pair_explicit=True,
        )
        with mock.patch.object(self.daemon, "_pair_scope_facts", return_value=facts):
            allowed, reason = self.daemon._runtime_hook_authority(
                scope, self.path, unit
            )
        self.assertTrue(allowed, reason)

    def test_vm_save_hook_failure_blocks_all_reclaim(self):
        scope = "vm-save-failure"
        path = self.cg.leaf(scope, [4247])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        with (
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(
                self.daemon,
                "_run_runtime_hook",
                return_value=(False, "VM save hook exited 1"),
            ),
            mock.patch.object(service.memory, "reclaim_page_cache") as file_reclaim,
            mock.patch.object(service.memory, "reclaim_anonymous") as anon_reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("save hook failed", result["reason"])
        file_reclaim.assert_not_called()
        anon_reclaim.assert_not_called()

    def test_swap_reclaim_opt_out_prevents_vm_save_hook(self):
        scope = "vm-save-opt-out"
        path = self.cg.leaf(scope, [4248])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.cfg["mem"]["swap_reclaim"] = False
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        with (
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
            mock.patch.object(
                service.memory, "reclaim_page_cache", return_value="memory.reclaim"
            ) as file_reclaim,
            mock.patch.object(service.memory, "reclaim_anonymous") as anon_reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "reclaimed")
        hook.assert_not_called()
        file_reclaim.assert_called_once()
        anon_reclaim.assert_not_called()

    def test_adopt_extra_opt_in_prevents_vm_save_hook(self):
        scope = "vm-save-adopt-opt-out"
        path = self.cg.leaf(scope, [4249])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.cfg["mode"] = "adopt"
        self.daemon.units = [
            {
                "unit": {"name": scope, "kind": "vm", "domain": "test-vm"},
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]
        with (
            mock.patch.object(self.daemon, "_run_runtime_hook") as hook,
            mock.patch.object(
                service.memory, "reclaim_page_cache", return_value="memory.reclaim"
            ),
            mock.patch.object(service.memory, "reclaim_anonymous") as anon_reclaim,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        self.assertEqual(result["status"], "reclaimed")
        hook.assert_not_called()
        anon_reclaim.assert_not_called()

    def test_successful_vm_save_hook_unlocks_anon_reclaim(self):
        scope = "vm-save-reclaim"
        path = self.cg.leaf(scope, [4245])
        write_scope(path)
        write(path + "/cgroup.freeze", "1\n")
        self.daemon.store.data["frozen_scopes"] = {scope: {"source": "test"}}
        self.daemon.units = [
            {
                "unit": {
                    "name": scope,
                    "kind": "vm",
                    "domain": "test-vm",
                    "stop_when_unneeded": True,
                },
                "mem": {"save_state": ["virsh", "managedsave", "%(domain)s"]},
            }
        ]

        def saved(target, _unit, _now):
            self.daemon.mark_vm_saved(target)
            return True, "VM save hook succeeded"

        with (
            mock.patch.object(
                service.memory, "swap_available_bytes", return_value=2 * 1024 * MIB
            ),
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(
                self.daemon, "_run_runtime_hook", side_effect=saved
            ) as hook,
            mock.patch.object(
                service.memory, "reclaim_page_cache", return_value="memory.reclaim"
            ),
            mock.patch.object(
                service.memory, "reclaim_anonymous", return_value="memory.reclaim"
            ) as anon,
        ):
            result = self.daemon.reclaim_scope(scope, now=1000)
        hook.assert_called_once()
        anon.assert_called_once()
        self.assertGreater(result["anonymous_requested_bytes"], 0)

    def test_automatic_pass_reclaims_only_after_idle_and_pressure_gates(self):
        self.daemon.last["reclaim"] = 1000
        self.daemon.cfg["mode"] = "adopt"
        with (
            mock.patch.object(
                service.memory,
                "snapshot",
                return_value={"scopes": [{"name": self.scope}]},
            ),
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(True, "idle")
            ),
            mock.patch.object(
                service.memory,
                "reclaim_page_cache",
                side_effect=self.reclaim_and_apply,
            ) as reclaim,
        ):
            results = self.daemon.reclaim_pass(now=2000)
        reclaim.assert_called_once()
        self.assertEqual(results[0]["status"], "reclaimed")

    def test_observe_automatic_pass_reports_would_without_reclaiming(self):
        self.daemon.cfg["mode"] = "observe"
        with (
            mock.patch.object(
                service.memory,
                "snapshot",
                return_value={"scopes": [{"name": self.scope}]},
            ),
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(True, "idle")
            ),
            mock.patch.object(service.memory, "reclaim_page_cache") as reclaim,
        ):
            results = self.daemon.reclaim_pass(now=2000)
        reclaim.assert_not_called()
        self.assertEqual(results[0]["status"], "would")

    def test_gc_memory_command_runs_both_passes_and_returns_bounded_memory_results(
        self,
    ):
        with (
            mock.patch.object(self.daemon, "gc_pass", return_value=[["idle", "empty"]]),
            mock.patch.object(
                self.daemon, "reclaim_pass", return_value=[{"scope": self.scope}]
            ) as reclaim,
        ):
            result = self.daemon.handle({"cmd": "gc", "memory": True, "dry_run": True})
        self.assertEqual(result["candidates"], [["idle", "empty"]])
        self.assertEqual(result["memory"], [{"scope": self.scope}])
        reclaim.assert_called_once_with(dry_run=True)

    def test_reclaim_timer_is_disabled_with_the_feature_and_uses_reloaded_interval(
        self,
    ):
        now = 10000.0
        self.daemon.cfg["mem"] = {"enabled": True, "reclaim": False}
        self.daemon.iv_adopt = self.daemon.iv_gc = self.daemon.iv_memory = 100000
        self.daemon.last = {key: now for key in ("adopt", "gc", "memory", "reclaim")}
        self.assertFalse(self.daemon.memory_reclaim_enabled())
        self.assertEqual(self.daemon.next_timeout(now), service.MAX_SLEEP)
        self.daemon.cfg["mem"]["reclaim"] = True
        self.daemon.iv_reclaim = 7
        self.daemon.last["reclaim"] = now - 2
        self.assertEqual(self.daemon.next_timeout(now), 5)

    def test_reclaim_pass_prunes_usage_for_scopes_removed_before_first_reclaim(self):
        self.daemon.reclaim_usage["leftover/gone"] = (10, 1.0)
        self.daemon.reclaim_idle_since["leftover/gone"] = 0.0
        with mock.patch.object(service.memory, "snapshot", return_value={"scopes": []}):
            self.assertEqual(self.daemon.reclaim_pass(now=10.0), [])
        self.assertNotIn("leftover/gone", self.daemon.reclaim_usage)
        self.assertNotIn("leftover/gone", self.daemon.reclaim_idle_since)

    def test_veto_blocks_manual_reclaim_until_explicit_override(self):
        self.daemon.store.add_veto("scope", self.scope)
        blocked = self.daemon.handle({"cmd": "reclaim", "scope": self.scope})
        self.assertEqual(blocked["status"], "skipped")
        self.assertIn("veto", blocked["reason"])
        with mock.patch.object(
            service.memory, "reclaim_page_cache", side_effect=self.reclaim_and_apply
        ):
            overridden = self.daemon.handle(
                {"cmd": "reclaim", "scope": self.scope, "force_veto": True}
            )
        self.assertEqual(overridden["status"], "reclaimed")
        with open(self.daemon.store.log_path, encoding="utf-8") as stream:
            self.assertIn('"event": "veto_override"', stream.read())

    def test_unknown_member_facts_and_hold_fail_closed_even_with_force_veto(self):
        self.daemon._infos = lambda _pids: []
        unknown = self.daemon.handle(
            {"cmd": "reclaim", "scope": self.scope, "force_veto": True}
        )
        self.assertIn("safety facts", unknown["reason"])
        self.daemon._infos = lambda pids: [
            {"pid": pid, "protected": "", "ptmx": False, "edges": []} for pid in pids
        ]
        self.daemon.handle(
            {
                "cmd": "feedback",
                "v": 2,
                "id": "reclaim-hold",
                "op": "hold",
                "scope": self.scope,
                "held": True,
                "reason": "work",
            }
        )
        held = self.daemon.handle(
            {"cmd": "reclaim", "scope": self.scope, "force_veto": True}
        )
        self.assertIn("held", held["reason"])

    def test_member_protection_edges_and_daemon_scope_are_hard_reclaim_blocks(self):
        for info, expected in (
            (
                {
                    "pid": 4242,
                    "protected": "protected comm",
                    "ptmx": False,
                    "edges": [],
                },
                "protected member",
            ),
            ({"pid": 4242, "protected": "", "ptmx": True, "edges": []}, "pty host"),
            (
                {
                    "pid": 4242,
                    "protected": "",
                    "ptmx": False,
                    "edges": [{"kind": "tcp"}],
                },
                "dependency edges",
            ),
            (
                {"pid": 4242, "protected": "", "ptmx": False, "edges": None},
                "edges are unknown",
            ),
        ):
            with self.subTest(expected=expected):
                self.daemon._infos = lambda _pids, info=info: [info]
                self.assertIn(
                    expected,
                    self.daemon._reclaim_safety_reason(self.scope, self.path, [4242]),
                )
        self.assertEqual(
            self.daemon._reclaim_safety_reason("manager/daemon", self.path, [4242]),
            "manager scope is never reclaimed",
        )
        with mock.patch.object(
            service.cgroup,
            "own_cgroup",
            return_value="/user/%d/leftover/reclaim-test/child" % os.getuid(),
        ):
            self.assertIn(
                "contains the daemon",
                self.daemon._reclaim_safety_reason(self.scope, self.path, [4242]),
            )

    def test_refault_marks_warm_and_extends_the_required_idle_grace(self):
        self.daemon.reclaim_state[self.scope] = {
            "last_at": 950.0,
            "warm": False,
            "refault_file": 4,
            "major_faults": 1,
            "high_events": 2,
        }
        stats = service.memory._stat(self.path)
        with open(
            os.path.join(self.path, "memory.stat"), "a", encoding="ascii"
        ) as target:
            target.write("workingset_refault_file 5\n")
        self.assertTrue(self.daemon._reclaim_warm(self.scope, self.path, 1000.0, 300.0))
        self.assertEqual(self.daemon.reclaim_state[self.scope]["warm_until"], 1600.0)
        self.daemon.reclaim_usage[self.scope] = (100, 590.0)
        self.daemon.reclaim_idle_since[self.scope] = 0.0
        with mock.patch.object(service.engine, "_cpu_usage", return_value=100):
            idle, reason = self.daemon._reclaim_idle(
                self.scope, self.path, 599.0, warm=True, grace=300.0
            )
        self.assertFalse(idle)
        self.assertIn("needs 600s (warm scope)", reason)
        self.assertEqual(stats["workingset_refault_file"], 4)

    def test_repeated_guard_retries_preserve_the_full_idle_cpu_sample(self):
        self.daemon.cfg["mem"]["idle_reclaim_grace"] = 0
        self.daemon.cfg["experimental"] = {"guard": True}
        self.daemon.cfg["guard"] = {
            "enabled": True,
            "cooldown": 0,
            "available_floor": 0,
            "psi_some": "150ms/2s",
            "psi_full": "50ms/2s",
            "freeze_in_adopt": False,
        }
        now = [1000.0]
        reclaim_times = []
        page_cache_results = []
        real_guard_reclaim = self.daemon._guard_reclaim_step

        def guard_reclaim(stage):
            if stage == "page_cache":
                result = real_guard_reclaim(stage)
                page_cache_results.append(result)
                return result
            return {"performed": 0, "bytes_freed": 0, "scopes": [], "results": []}

        def reclaim(path, amount, high_target):
            reclaim_times.append(now[0])
            return self.reclaim_and_apply(path, amount, high_target)

        with (
            mock.patch.object(service.engine, "_cpu_usage", return_value=100),
            mock.patch.object(
                service.memory, "reclaim_page_cache", side_effect=reclaim
            ),
            mock.patch.object(
                self.daemon, "_guard_reclaim_step", side_effect=guard_reclaim
            ),
            mock.patch.object(
                self.daemon,
                "_guard_pressure_high",
                return_value=True,
            ),
            mock.patch.object(
                self.daemon,
                "_guard_pressure_now_high",
                return_value=True,
            ),
            mock.patch.object(self.daemon, "_guard_floor", return_value=(100, 50)),
            mock.patch.object(
                self.daemon,
                "_guard_freeze_step",
                return_value={"performed": 0, "bytes_freed": 0, "scopes": []},
            ),
            mock.patch.object(
                self.daemon,
                "_guard_stop_step",
                return_value={"performed": 0, "bytes_freed": 0, "scopes": []},
            ),
            mock.patch.object(service.time, "time", side_effect=lambda: now[0]),
        ):
            for second in range(6):
                now[0] = 1000.0 + second
                self.daemon.guard_pass("retry")
                if second < 5:
                    self.assertEqual(reclaim_times, [])

        self.assertEqual(reclaim_times, [1005.0], page_cache_results)

    def test_memory_high_event_growth_marks_scope_warm(self):
        self.daemon.reclaim_state[self.scope] = {
            "last_at": 950.0,
            "warm": False,
            "refault_file": 4,
            "major_faults": 1,
            "high_events": 2,
        }
        write(self.path + "/memory.events", "low 0\nhigh 3\nmax 0\nome 0\n")
        self.assertTrue(self.daemon._reclaim_warm(self.scope, self.path, 1000.0, 300.0))
        self.assertEqual(self.daemon.reclaim_state[self.scope]["warm_until"], 1600.0)

    def test_warm_state_expires_after_twice_cooldown(self):
        self.daemon.reclaim_state[self.scope] = {
            "last_at": 950.0,
            "warm": True,
            "warm_until": 1600.0,
            "refault_file": 5,
            "major_faults": 1,
            "high_events": 2,
        }
        self.assertFalse(
            self.daemon._reclaim_warm(self.scope, self.path, 1600.0, 300.0)
        )
        self.assertFalse(self.daemon.reclaim_state[self.scope]["warm"])
        self.assertIsNone(self.daemon.reclaim_state[self.scope]["warm_until"])
        self.daemon.reclaim_usage[self.scope] = (100, 1000.0)
        self.daemon.reclaim_idle_since[self.scope] = 0.0
        with mock.patch.object(service.engine, "_cpu_usage", return_value=100):
            idle, _reason = self.daemon._reclaim_idle(
                self.scope, self.path, 1600.0, warm=False, grace=300.0
            )
        self.assertTrue(idle)

    def test_warm_suppression_blocks_manual_and_automatic_requests_twice_cooldown(self):
        self.daemon.reclaim_state[self.scope] = {
            "last_at": 950.0,
            "warm": True,
            "warm_until": 1600.0,
            "refault_file": 5,
            "major_faults": 1,
        }
        self.daemon._infos = lambda pids: [
            {"pid": pid, "protected": "", "ptmx": False, "edges": []} for pid in pids
        ]
        with mock.patch.object(service.memory, "scope_counters", return_value=None):
            for manual in (False, True):
                result = self.daemon._reclaim_one(
                    self.scope,
                    self.path,
                    1200.0,
                    {"some_avg10": 20.0, "full_avg10": 0.0},
                    manual=manual,
                    resource_class="leftover",
                )
                self.assertEqual(result["status"], "skipped")
                self.assertIn("warm; reclaim suppressed for 400s", result["reason"])

    def test_bundled_podman_scope_uses_shipped_unit_facts_for_container_class(self):
        scope = "app-podman-deadbeef"
        path = self.cg.leaf(scope, [4243])
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
        self.assertEqual(self.daemon._reclaim_class(scope, path), "container")

    def test_full_pressure_ceiling_blocks_reclaim(self):
        with mock.patch.object(
            service.memory,
            "pressure",
            side_effect=lambda path=None: (
                {"some_avg10": 20.0, "full_avg10": 61.0}
                if path is None
                else {"some_avg10": 0.0, "full_avg10": 0.0}
            ),
        ):
            result = self.daemon.handle({"cmd": "reclaim", "scope": self.scope})
        self.assertIn("exceeds", result["reason"])

    def test_protocol_rejects_invalid_manual_reclaim_arguments(self):
        valid = {
            "v": 2,
            "id": 1,
            "cmd": "reclaim",
            "args": {"scope": self.scope, "force_veto": True},
        }
        self.assertEqual(
            protocol.decode_v2(valid),
            {"cmd": "reclaim", "scope": self.scope, "force_veto": True},
        )
        for bad_args in (
            {"scope": "", "force_veto": True},
            {"scope": "x" * 97},
            {"scope": "scope-x", "force_veto": "yes"},
            {"scope": "scope-x", "unknown": True},
        ):
            with self.subTest(args=bad_args):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.decode_v2({**valid, "args": bad_args})


class ReclaimCliTests(unittest.TestCase):
    def test_memory_reclaim_cli_uses_daemon_and_emits_json(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            path = cg.leaf("leftover/cli-target", [4242])
            cfg = make_cfg(state)
            result = {
                "scope": "leftover/cli-target",
                "status": "would",
                "requested_bytes": 64 * MIB,
                "page_cache_requested_bytes": 32 * MIB,
                "anonymous_requested_bytes": 32 * MIB,
                "anonymous_reclaim_reason": None,
                "methods": ["memory.reclaim"],
                "swap_delta_bytes": 0,
                "zswap_delta_bytes": 0,
            }
            output = io.StringIO()
            with (
                mock.patch.object(commands, "_load", return_value=(cfg, None, [])),
                mock.patch.object(commands.cgroup, "resolve", return_value=path),
                mock.patch.object(commands, "ask", return_value=result) as ask,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                code = commands.main(["memory", "reclaim", "target", "--json"])
            self.assertEqual(code, 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value["schema"], "taema.memory-reclaim.v1")
            self.assertTrue(matches(value, CLI_SCHEMA, CLI_SCHEMA))
            self.assertEqual(ask.call_args.args[1]["cmd"], "reclaim")
            self.assertEqual(ask.call_args.args[1]["scope"], "leftover/cli-target")

    def test_force_veto_requires_confirmation_and_is_sent_as_an_explicit_override(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            path = cg.leaf("leftover/cli-target", [4242])
            cfg = make_cfg(state)
            store = service.knowledge.Store(state, {})
            store.add_veto("scope", "leftover/cli-target")
            with (
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands.cgroup, "resolve", return_value=path),
                mock.patch.object(
                    commands, "ask", return_value={"status": "reclaimed"}
                ) as ask,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = commands.main(["memory", "reclaim", "target", "--force-veto"])
            self.assertEqual(code, 1)
            ask.assert_not_called()
            with (
                mock.patch.object(commands, "_load", return_value=(cfg, store, [])),
                mock.patch.object(commands.cgroup, "resolve", return_value=path),
                mock.patch.object(
                    commands, "ask", return_value={"status": "reclaimed"}
                ) as ask,
                redirect_stdout(io.StringIO()),
            ):
                code = commands.main(
                    ["memory", "reclaim", "target", "--force-veto", "--yes"]
                )
            self.assertEqual(code, 0)
            self.assertIs(ask.call_args.args[1]["force_veto"], True)

    def test_gc_memory_option_requests_daemon_reclaim(self):
        with tempfile.TemporaryDirectory() as state:
            cfg = make_cfg(state)
            output = io.StringIO()
            with (
                mock.patch.object(commands, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    commands, "ask", return_value={"candidates": [], "memory": []}
                ) as ask,
                redirect_stdout(output),
            ):
                code = commands.main(["gc", "--memory", "--json"])
            self.assertEqual(code, 0)
            self.assertIs(ask.call_args.args[1]["memory"], True)


class LivePageCacheReclaim(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("TAEMA_LIVE_RECLAIM") == "1",
        "set TAEMA_LIVE_RECLAIM=1 to use an isolated delegated cgroup",
    )
    def test_reclaims_only_a_disposable_child_in_delegated_subtree(self):
        base = service.cgroup.base()
        if not os.path.isfile(os.path.join(base, "cgroup.subtree_control")):
            self.skipTest("delegated cgroup v2 subtree is unavailable")
        parent = os.path.join(base, "leftover")
        if not os.path.isdir(parent):
            self.skipTest("delegated leftover subtree is unavailable")
        name = "taema-live-reclaim-%d" % os.getpid()
        path = os.path.join(parent, name)
        work_root = os.environ.get("TAEMA_LIVE_RECLAIM_DIR", "/var/tmp")
        if not os.path.isdir(work_root) or not os.access(work_root, os.W_OK):
            self.skipTest(
                "a writable durable directory is required for page-cache input"
            )
        process = None
        try:
            os.mkdir(path)
        except OSError as error:
            self.skipTest("cannot create isolated delegated cgroup: %s" % error)
        try:
            for directory in (path, parent, base):
                for control, minimum in (
                    ("memory.max", 320 * MIB),
                    ("memory.high", 320 * MIB),
                ):
                    try:
                        value = Path(directory, control).read_text().strip()
                    except OSError:
                        continue
                    if value != "max" and int(value) < minimum:
                        self.skipTest(
                            "ancestor %s is below the live-test memory size" % control
                        )
            if (
                not Path(path, "memory.current").exists()
                or not Path(path, "memory.stat").exists()
            ):
                self.skipTest(
                    "memory controller is unavailable in the delegated cgroup"
                )
            with tempfile.TemporaryDirectory(
                prefix="taema-reclaim-", dir=work_root
            ) as files:
                source = os.path.join(files, "page-cache.bin")
                gate = os.path.join(files, "start")
                ready = os.path.join(files, "ready")
                done = os.path.join(files, "done")
                script = (
                    "import os,sys,time\n"
                    "source,gate,ready,done=sys.argv[1:]\n"
                    "while not os.path.exists(gate): time.sleep(.01)\n"
                    "with open(source,'wb') as out:\n"
                    " chunk=b'x'*(1024*1024)\n"
                    " for _ in range(192): out.write(chunk)\n"
                    " out.flush(); os.fsync(out.fileno())\n"
                    "with open(source,'rb') as inp:\n"
                    " while inp.read(4*1024*1024): pass\n"
                    "open(ready,'w').close()\n"
                    "while not os.path.exists(done): time.sleep(.01)\n"
                )
                process = subprocess.Popen(
                    [sys.executable, "-c", script, source, gate, ready, done]
                )
                if not service.cgroup.move(process.pid, path):
                    self.skipTest("the worker could not enter the isolated cgroup")
                Path(gate).touch()
                deadline = time.monotonic() + 60
                while not os.path.exists(ready) and time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("page-cache worker exited before preparing its file")
                    time.sleep(0.05)
                if not os.path.exists(ready):
                    self.fail("page-cache worker did not finish within 60 seconds")

                before = memory.scope_counters(path)
                if before is None or before.get("reclaimable_bytes") is None:
                    self.skipTest("kernel does not expose reclaimable scope counters")
                amount = memory.page_cache_budget(
                    before["current_bytes"],
                    before.get("anon_bytes"),
                    before["reclaimable_bytes"],
                    memory.ReclaimBounds(2 * 1024**3, 128 * MIB, 10, 16 * MIB),
                )
                if amount < 16 * MIB:
                    self.skipTest("worker did not create enough reclaimable page cache")
                memory.reclaim_page_cache(
                    path, amount, before["current_bytes"] - amount
                )
                after = memory.scope_counters(path)
                self.assertLess(after["reclaimable_bytes"], before["reclaimable_bytes"])
        except OSError as error:
            self.skipTest("kernel refused isolated live reclaim: %s" % error)
        finally:
            if process is not None:
                try:
                    Path(done).touch()
                except (NameError, OSError):
                    pass
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            try:
                os.rmdir(path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
