"""System diagnostics use fake cgroup and process trees and remain read-only."""

import getpass
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from taema import doctor, protocol
from taema.cli import commands, view
from taema.config import policy
from taema.core import cgroup, process
from taema.daemon import service
from taema.store import db, knowledge
from tests.test_ipc_v2 import matches
from tests.test_phase0 import FakeCg, make_cfg
from tests.test_phase2 import FakeProc


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "cli" / "read-v1.json").read_text())


class DoctorChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system_root = os.path.join(self.temp.name, "system")
        self.state_dir = os.path.join(self.temp.name, "state")
        os.makedirs(self.state_dir)
        self.uid = os.getuid()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.proc = FakeProc()
        self.addCleanup(self.proc.stop)
        self.proc.add(4242, 1, comm="browser")
        self.cg.leaf("scope-browser", [4242])
        self.base = cgroup.base(self.uid)
        self.write(cgroup.CG + "/cgroup.controllers", "cpu io memory pids\n")
        self.write(self.base + "/cgroup.controllers", "cpu io memory pids\n")
        self.write(self.base + "/cgroup.subtree_control", "+cpu +io +memory +pids\n")
        for name, value in (
            ("memory.current", "0\n"),
            (
                "memory.stat",
                "anon 0\nfile 0\ninactive_file 0\nshmem 0\nslab 0\n",
            ),
            ("memory.peak", "0\n"),
            ("memory.reclaim", ""),
            ("memory.low", "0\n"),
            ("memory.oom.group", "0\n"),
            ("memory.high", "max\n"),
            ("memory.low", "0\n"),
            ("memory.max", "max\n"),
            ("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"),
            ("memory.events.local", "oom 0\noom_kill 0\n"),
            ("memory.oom.group", "1\n"),
            ("memory.pressure", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
            ("cgroup.freeze", "0\n"),
            ("cpu.idle", "0\n"),
            ("cpu.weight", "100\n"),
            ("io.weight", "default 100\n"),
            ("memory.swap.current", "0\n"),
            ("memory.swap.max", "max\n"),
            ("memory.zswap.current", "0\n"),
        ):
            self.write(self.base + "/" + name, value)

        self.user = getpass.getuser()
        system_gid = os.getgid()
        self.group_gid = system_gid + 10000
        self.write(
            self.system_root + "/etc/passwd",
            "%s:x:%d:%d:Test User:/home/%s:/bin/sh\n"
            % (self.user, self.uid, system_gid, self.user),
        )
        self.write(
            self.system_root + "/etc/group",
            "taema:x:%d:%s\n" % (self.group_gid, self.user),
        )
        helper = self.system_root + policy.HELPER
        self.write(helper, "#!/bin/sh\n# oom-record oom-restore\nexit 0\n")
        os.chmod(helper, 0o755)
        self.write(
            self.system_root + "/etc/sudoers.d/taema",
            "%%taema ALL=(root) NOPASSWD: %s\n" % policy.HELPER,
        )
        service_dir = self.system_root + "/etc/sv/taema"
        self.write(service_dir + "/run", "#!/bin/sh\nexit 0\n")
        os.chmod(service_dir + "/run", 0o755)
        os.makedirs(service_dir + "/supervise")
        active_parent = self.system_root + "/var/service"
        os.makedirs(active_parent)
        os.symlink("../../etc/sv/taema", active_parent + "/taema")
        self.write(self.system_root + "/sys/module/zswap/parameters/enabled", "Y\n")
        self.write(self.system_root + "/proc/self/oom_score_adj", "0\n")
        self.write(
            self.system_root + "/proc/swaps",
            "Filename\tType\tSize\tUsed\tPriority\n/swapfile\tfile\t1048576\t0\t-2\n",
        )
        self.write(self.system_root + "/proc/self/oom_score_adj", "0\n")
        os.makedirs(self.system_root + "/sys/block", exist_ok=True)

        self.cfg = make_cfg(self.state_dir, mode="auto")
        self.cfg["paths"]["socket"] = self.state_dir + "/taema.sock"
        self.cfg["paths"]["socket_fallback"] = self.state_dir + "/fallback.sock"
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(self.cfg["paths"]["socket"])
        os.chmod(self.cfg["paths"]["socket"], 0o600)
        self.addCleanup(self.socket.close)
        self.store = knowledge.Store(self.state_dir, {})

    def write(self, path, value):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as output:
            output.write(value)

    def report(self, **kwargs):
        store = kwargs.pop("store", self.store)
        units = kwargs.pop("units", [])
        group_ids = kwargs.pop("group_ids", [self.group_gid])
        # A fixed backend: probing the real one makes the all-ok report
        # depend on the machine having desktop notification tooling.
        notify = kwargs.pop(
            "notify", {"backend": "scripted", "capabilities": ["actions", "body"]}
        )
        return doctor.diagnose(
            self.cfg,
            store,
            units,
            system_root=self.system_root,
            uid=self.uid,
            group_ids=group_ids,
            notify=notify,
            **kwargs,
        )

    def check(self, report, name):
        return next(item for item in report["checks"] if item["name"] == name)

    def test_complete_report_checks_fake_process_tree_and_has_one_line_fixes(self):
        class WritableTriggerProbe:
            metrics = ("some", "full")

            def open_triggers(self, _path, _settings):
                return []

            def close(self):
                pass

        with mock.patch.object(
            doctor.pressure_guard,
            "PsiTriggerMonitor",
            return_value=WritableTriggerProbe(),
        ):
            report = self.report()
        self.assertEqual(report["schema"], "taema.doctor.v1")
        self.assertEqual(report["status"], "ok")
        self.assertTrue(all(item["status"] == "ok" for item in report["checks"]))
        self.assertTrue(all(item["fix"] for item in report["checks"]))
        self.assertIn("eligible apps", self.check(report, "adopt behavior")["message"])
        self.assertIn("[ok] delegation", doctor.render(report))
        self.assertEqual(process.uid_of(4242), self.uid)

    def test_missing_cpu_weight_fallback_is_reported(self):
        os.unlink(self.base + "/cpu.weight")
        report = self.report()
        fallback = self.check(report, "CPU weight fallback")
        self.assertEqual(fallback["status"], "warn")
        self.assertIn("cpu.weight", fallback["message"])

    def test_swap_zswap_and_zram_advice_is_read_only_and_reports_devices(self):
        os.makedirs(self.system_root + "/sys/block/zram0")
        self.write(self.system_root + "/sys/module/zswap/parameters/enabled", "N\n")
        report = self.report()
        swap = self.check(report, "swap devices")
        zram = self.check(report, "zram devices")
        zswap = self.check(report, "zswap")
        self.assertIn("/swapfile", swap["message"])
        self.assertIn("zram0", zram["message"])
        self.assertEqual(zswap["status"], "warn")
        self.assertIn("sudo sh -c", zswap["fix"])
        self.assertIn("zswap.enabled=1", zswap["fix"])
        self.assertIn("uncompressed", zswap["fix"])
        self.assertEqual(
            Path(self.system_root + "/sys/module/zswap/parameters/enabled").read_text(),
            "N\n",
        )

    def test_no_swap_is_reported_without_triggering_system_changes(self):
        self.write(
            self.system_root + "/proc/swaps",
            "Filename\tType\tSize\tUsed\tPriority\n",
        )
        report = self.report()
        swap = self.check(report, "swap devices")
        self.assertEqual(swap["status"], "warn")
        self.assertIn("no active swap", swap["message"])

    def test_unknown_keys_and_parse_errors_are_reported(self):
        self.cfg["paths"]["not_a_setting"] = True
        report = self.report()
        config = self.check(report, "configuration")
        self.assertEqual(config["status"], "warn")
        self.assertIn("paths.not_a_setting", config["message"])

        report = self.report(config_error="invalid TOML at line 2")
        config = self.check(report, "configuration")
        self.assertEqual(config["status"], "fail")
        self.assertIn("invalid TOML", config["message"])
        report = self.report(units_error="units/browser.toml: invalid value")
        self.assertEqual(self.check(report, "unit files")["status"], "fail")

    def test_group_helper_and_runit_checks_report_repairs(self):
        self.write(
            self.system_root + "/etc/group",
            "taema:x:%d:someone-else\n" % (os.getgid() + 10000),
        )
        report = self.report()
        self.assertEqual(self.check(report, "group membership")["status"], "warn")
        self.assertIn("usermod -aG", self.check(report, "group membership")["fix"])

        self.write(
            self.system_root + "/etc/group",
            "taema:x:%d:%s\n" % (self.group_gid, self.user),
        )
        report = self.report(group_ids=[])
        self.assertEqual(self.check(report, "group membership")["status"], "warn")
        self.assertIn("Log out", self.check(report, "group membership")["fix"])

        os.unlink(self.system_root + policy.HELPER)
        report = self.report()
        self.assertEqual(self.check(report, "sudo helper")["status"], "fail")
        self.assertIn("Reinstall", self.check(report, "sudo helper")["fix"])

        os.symlink(
            "../../etc/sv/taema",
            self.system_root + "/var/service/disabled-taema",
        )
        os.unlink(self.system_root + "/var/service/taema")
        report = self.report()
        self.assertEqual(self.check(report, "runit service")["status"], "warn")

    def test_unreadable_sudoers_uses_noninteractive_permission_listing(self):
        os.chmod(self.system_root + "/etc/sudoers.d/taema", 0)
        with mock.patch.object(
            doctor.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="Options: !authenticate\nMatched: /usr/libexec/taema/taema-attach",
                stderr="",
            ),
        ) as run:
            report = self.report()
        self.assertEqual(self.check(report, "sudo helper")["status"], "ok")
        self.assertEqual(run.call_args.args[0][:3], ["sudo", "-n", "-ll"])

        with mock.patch.object(doctor.subprocess, "run", side_effect=FileNotFoundError):
            report = self.report()
        self.assertEqual(self.check(report, "sudo helper")["status"], "warn")

    def test_cgroup_delegation_and_kernel_features_can_be_missing(self):
        os.unlink(self.base + "/memory.reclaim")
        self.write(self.base + "/cgroup.controllers", "cpu pids\n")
        report = self.report()
        self.assertEqual(self.check(report, "delegation")["status"], "warn")
        self.assertEqual(self.check(report, "memory reclaim")["status"], "warn")
        self.assertEqual(self.check(report, "memory accounting")["status"], "warn")
        group_control = self.check(report, "memory OOM group kill")
        self.assertEqual(group_control["status"], "warn")
        self.assertIn("memory controller is unavailable", group_control["message"])
        self.assertIn("per-process OOM score adjustment", group_control["fix"])

        shutil.rmtree(self.base)
        report = self.report()
        self.assertEqual(self.check(report, "delegation")["status"], "fail")
        self.assertEqual(self.check(report, "cgroup v2")["status"], "ok")

        os.unlink(cgroup.CG + "/cgroup.controllers")
        report = self.report()
        self.assertEqual(self.check(report, "cgroup v2")["status"], "fail")

    def test_doctor_reports_memory_features_and_named_fallbacks(self):
        report = self.report()
        names = {item["name"] for item in report["checks"]}
        self.assertTrue(
            {
                "memory accounting",
                "memory.stat breakdown",
                "memory peak usage",
                "memory pressure",
                "guard PSI triggers",
                "memory reclaim",
                "memory low reservation",
                "memory OOM group kill",
                "memory soft cap",
                "memory low protection",
                "memory hard cap",
                "memory OOM group",
                "swap accounting",
                "zswap accounting",
                "memory OOM events",
                "memory high events",
                "memory max events",
                "OOM score adjustment",
                "OOM restore helper",
            }
            <= names
        )
        self.assertEqual(self.check(report, "memory peak usage")["status"], "ok")
        self.assertEqual(self.check(report, "memory low reservation")["status"], "ok")
        self.assertEqual(self.check(report, "memory OOM group kill")["status"], "ok")
        self.assertEqual(self.check(report, "memory.stat breakdown")["status"], "ok")
        self.assertEqual(self.check(report, "memory high events")["status"], "ok")
        self.assertEqual(self.check(report, "memory max events")["status"], "ok")
        self.assertEqual(self.check(report, "memory OOM group")["status"], "ok")
        self.assertEqual(self.check(report, "OOM score adjustment")["status"], "ok")
        self.assertEqual(self.check(report, "OOM restore helper")["status"], "ok")
        psi_triggers = self.check(report, "guard PSI triggers")
        self.assertEqual(psi_triggers["status"], "warn")
        self.assertIn("no writable PSI trigger source", psi_triggers["message"])

        os.unlink(self.base + "/memory.peak")
        os.unlink(self.base + "/memory.low")
        os.unlink(self.base + "/memory.oom.group")
        os.unlink(self.base + "/memory.pressure")
        os.unlink(self.base + "/memory.reclaim")
        self.write(
            self.system_root + "/proc/pressure/memory",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        report = self.report()
        self.assertIn("samples max", self.check(report, "memory peak usage")["message"])
        self.assertEqual(self.check(report, "memory low reservation")["status"], "warn")
        self.assertIn(
            "memory.low",
            self.check(report, "memory low reservation")["message"],
        )
        group_control = self.check(report, "memory OOM group kill")
        self.assertEqual(group_control["status"], "warn")
        self.assertIn("memory.oom.group", group_control["message"])
        self.assertIn("per-process OOM score adjustment", group_control["fix"])
        self.assertIn(
            "host PSI fallback", self.check(report, "memory pressure")["message"]
        )
        self.assertIn(
            "host-wide PSI",
            self.check(report, "memory pressure")["fix"],
        )
        self.assertIn(
            "memory.high pulse", self.check(report, "memory reclaim")["message"]
        )

        os.unlink(self.base + "/memory.zswap.current")
        report = self.report()
        self.assertIn("swap use", self.check(report, "zswap accounting")["message"])

    def test_missing_memory_breakdown_low_high_events_and_oom_restore_are_named(self):
        self.write(self.base + "/memory.stat", "anon 0\nfile 0\n")
        os.unlink(self.base + "/memory.low")
        self.write(self.base + "/memory.events", "oom 0\noom_kill 0\n")
        os.unlink(self.base + "/memory.oom.group")
        os.unlink(self.system_root + "/proc/self/oom_score_adj")
        self.write(self.system_root + policy.HELPER, "#!/bin/sh\nexit 0\n")
        report = self.report()
        self.assertEqual(self.check(report, "memory.stat breakdown")["status"], "warn")
        self.assertIn(
            "inactive_file", self.check(report, "memory.stat breakdown")["message"]
        )
        self.assertEqual(self.check(report, "memory low protection")["status"], "warn")
        self.assertEqual(self.check(report, "memory high events")["status"], "warn")
        self.assertEqual(self.check(report, "memory max events")["status"], "warn")
        self.assertEqual(self.check(report, "memory OOM group")["status"], "warn")
        self.assertEqual(self.check(report, "OOM score adjustment")["status"], "warn")
        self.assertEqual(self.check(report, "OOM restore helper")["status"], "warn")
        self.assertNotEqual(report["status"], "fail")

    def test_process_oom_score_adjustment_is_read_only_and_validated(self):
        path = self.system_root + "/proc/self/oom_score_adj"
        original = Path(path).read_text()
        report = self.report()
        check = self.check(report, "process OOM score adjustment")
        self.assertEqual(check["status"], "ok")
        self.assertIn("readable and valid", check["message"])
        self.assertEqual(Path(path).read_text(), original)

        for value in ("bad\n", "1001\n", "-1001\n"):
            with self.subTest(value=value):
                self.write(path, value)
                check = self.check(self.report(), "process OOM score adjustment")
                self.assertEqual(check["status"], "warn")
                self.assertIn("invalid", check["message"])

    def test_process_oom_score_adjustment_warns_when_absent_or_unreadable(self):
        path = self.system_root + "/proc/self/oom_score_adj"
        os.unlink(path)
        check = self.check(self.report(), "process OOM score adjustment")
        self.assertEqual(check["status"], "warn")
        self.assertIn("absent or unreadable", check["message"])

        self.write(path, "0\n")
        original_read = doctor._read

        def read_unless_score_is_unreadable(candidate):
            if candidate == path:
                return None
            return original_read(candidate)

        with mock.patch.object(
            doctor, "_read", side_effect=read_unless_score_is_unreadable
        ):
            check = self.check(self.report(), "process OOM score adjustment")
        self.assertEqual(check["status"], "warn")
        self.assertIn("absent or unreadable", check["message"])

    def test_memory_oom_group_reports_support_and_optional_fallback(self):
        name = "memory OOM group kill"
        control = self.base + "/memory.oom.group"
        check = self.check(self.report(), name)
        self.assertEqual(check["status"], "ok")
        self.assertIn("supported", check["message"])

        os.unlink(control)
        check = self.check(self.report(), name)
        self.assertEqual(check["status"], "warn")
        self.assertIn("memory.oom.group", check["message"])
        self.assertIn("per-process OOM score adjustment", check["fix"])

        self.write(control, "0\n")
        original_read = doctor._read

        def read_unless_group_control_is_unreadable(candidate):
            if candidate == control:
                return None
            return original_read(candidate)

        with mock.patch.object(
            doctor, "_read", side_effect=read_unless_group_control_is_unreadable
        ):
            check = self.check(self.report(), name)
        self.assertEqual(check["status"], "warn")
        self.assertIn("unreadable", check["message"])

    def test_doctor_does_not_probe_memory_when_disabled(self):
        self.cfg["mem"] = {"enabled": False}
        with mock.patch.object(doctor.memory, "_read", side_effect=AssertionError):
            report = self.report()
        for name in (
            "memory accounting",
            "memory.stat breakdown",
            "memory peak usage",
            "memory pressure",
            "memory OOM group kill",
            "guard PSI triggers",
            "memory low protection",
            "memory OOM group",
            "memory OOM events",
            "memory high events",
            "memory max events",
        ):
            self.assertIn("disabled", self.check(report, name)["message"])
        self.assertIn("enabled", self.check(report, "zswap")["message"])
        self.assertIn("/swapfile", self.check(report, "swap devices")["message"])

    def test_doctor_reports_writable_host_psi_fallback_after_cgroup_denial(self):
        cgroup_path = self.base + "/memory.pressure"
        proc_path = self.system_root + "/proc/pressure/memory"

        class FakeMonitor:
            def __init__(self):
                self.metrics = ()

            def open_triggers(self, path, _settings):
                if path == cgroup_path:
                    return [
                        "some: PermissionError: cgroup trigger is not writable",
                        "full: PermissionError: cgroup trigger is not writable",
                    ]
                self.metrics = ("some", "full")
                return []

            def close(self):
                self.metrics = ()

        with mock.patch.object(doctor.pressure_guard, "PsiTriggerMonitor", FakeMonitor):
            check = doctor._guard_psi_trigger_check(
                self.cfg, self.base, self.system_root
            )
        self.assertEqual(check["status"], "ok")
        self.assertIn("writable PSI trigger source=host-proc", check["message"])
        self.assertIn(proc_path, check["message"])
        self.assertIn("delegated trigger unavailable", check["message"])

    def test_foreign_process_and_insecure_socket_fail_safely(self):
        with mock.patch.object(doctor.process, "uid_of", return_value=self.uid + 1):
            report = self.report()
        ownership = self.check(report, "process ownership")
        self.assertEqual(ownership["status"], "fail")
        self.assertIn("4242", ownership["message"])

        os.chmod(self.cfg["paths"]["socket"], 0o644)
        report = self.report()
        self.assertEqual(self.check(report, "socket")["status"], "fail")
        os.chmod(self.cfg["paths"]["socket"], 0o700)
        report = self.report()
        self.assertEqual(self.check(report, "socket")["status"], "ok")
        os.unlink(self.cfg["paths"]["socket"])
        report = self.report()
        self.assertEqual(self.check(report, "socket")["status"], "warn")

    def test_store_schema_recovery_and_hold_states_are_reported(self):
        with mock.patch.object(self.store, "recovery", {"source": "backup.json"}):
            report = self.report()
        self.assertEqual(self.check(report, "store recovery")["status"], "warn")

        with mock.patch.object(self.store, "hold_reason", return_value="maintenance"):
            report = self.report()
        self.assertEqual(self.check(report, "mode and hold")["status"], "warn")

        connection = sqlite3.connect(self.store.path)
        connection.execute("PRAGMA user_version = %d" % (db.SCHEMA_VERSION + 1))
        connection.close()
        report = self.report(store=None)
        self.assertEqual(self.check(report, "store integrity")["status"], "fail")

        Path(self.store.path).write_bytes(b"not sqlite")
        report = self.report(store=None)
        self.assertEqual(self.check(report, "store integrity")["status"], "fail")
        self.assertEqual(
            self.check(self.report(store_error="database locked"), "store recovery")[
                "status"
            ],
            "warn",
        )

    def test_zswap_disabled_and_root_mode_are_visible(self):
        self.write(self.system_root + "/sys/module/zswap/parameters/enabled", "N\n")
        report = self.report()
        self.assertEqual(self.check(report, "zswap")["status"], "warn")
        report = doctor.diagnose(
            self.cfg, self.store, [], system_root=self.system_root, uid=0
        )
        self.assertEqual(self.check(report, "group membership")["status"], "fail")

    def test_cli_uses_daemon_result_and_local_fallback_with_json_schema(self):
        expected = self.report()
        args = SimpleNamespace(json=True, jsonl=False, quiet=False, config=None)
        output = io.StringIO()
        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=expected) as ask,
            redirect_stdout(output),
        ):
            self.assertEqual(commands.cmd_doctor(args), 0)
        self.assertEqual(ask.call_args.args[1], {"cmd": "doctor"})
        self.assertTrue(matches(json.loads(output.getvalue()), SCHEMA, SCHEMA))

        local = {"schema": "taema.doctor.v1", "status": "warn", "checks": []}
        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(commands.knowledge, "Store", return_value=self.store),
            mock.patch.object(commands.policy, "load_units", return_value=[]),
            mock.patch.object(doctor, "diagnose", return_value=local) as diagnose,
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 0)
        diagnose.assert_called_once()

    def test_cli_reports_bad_config_without_contacting_daemon(self):
        args = SimpleNamespace(
            json=False, jsonl=False, quiet=False, config="broken.toml"
        )
        report = {"schema": "taema.doctor.v1", "status": "fail", "checks": []}
        with (
            mock.patch.object(
                commands.policy,
                "load_config",
                side_effect=[ValueError("bad config"), self.cfg],
            ),
            mock.patch.object(commands, "ask") as ask,
            mock.patch.object(doctor, "diagnose", return_value=report) as diagnose,
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 1)
        ask.assert_not_called()
        self.assertEqual(
            diagnose.call_args.kwargs["config_error"].args[0], "bad config"
        )

    def test_cli_local_fallback_reports_unit_and_store_load_errors(self):
        args = SimpleNamespace(json=False, jsonl=False, quiet=False, config=None)
        report = {"schema": "taema.doctor.v1", "status": "fail", "checks": []}
        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(commands.knowledge, "Store", return_value=self.store),
            mock.patch.object(
                commands.policy, "load_units", side_effect=ValueError("bad unit TOML")
            ),
            mock.patch.object(doctor, "diagnose", return_value=report) as diagnose,
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 1)
        self.assertEqual(str(diagnose.call_args.kwargs["units_error"]), "bad unit TOML")

        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(
                commands.knowledge, "Store", side_effect=OSError("bad store")
            ),
            mock.patch.object(commands.policy, "load_units", return_value=[]),
            mock.patch.object(doctor, "diagnose", return_value=report) as diagnose,
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 1)
        self.assertEqual(str(diagnose.call_args.kwargs["store_error"]), "bad store")

    def test_daemon_and_protocol_serve_the_same_doctor_report(self):
        self.assertEqual(
            protocol.decode_v2({"v": 2, "id": 1, "cmd": "doctor", "args": {}}),
            {"cmd": "doctor"},
        )
        with tempfile.TemporaryDirectory() as state_dir:
            daemon = service.Daemon(make_cfg(state_dir))
            expected = {"schema": "taema.doctor.v1", "status": "ok", "checks": []}
            with mock.patch.object(
                doctor, "diagnose", return_value=expected
            ) as diagnose:
                self.assertEqual(daemon.handle({"cmd": "doctor"}), expected)
            diagnose.assert_called_once_with(daemon.cfg, daemon.store, daemon.units)


class DoctorFix(DoctorChecks):
    """`taema doctor --fix` repairs what it safely can (issue #75)."""

    def test_fix_flags_registered(self):
        from taema.cli import registry

        entry = next(item for item in registry.COMMANDS if item["name"] == "doctor")
        flags = {names[0] for names, _ in entry.get("arguments", ())}
        self.assertIn("--fix", flags)
        self.assertIn("--sudo", flags)

    def test_fix_runs_repair_and_reports(self):
        fixes = [
            {"name": "state dir", "status": "fixed", "message": "created it"},
            {
                "name": "controllers",
                "status": "needs-root",
                "message": "cannot write subtree_control",
                "command": "sudo sh -c 'echo +memory > /sys/fs/cgroup/subtree'",
            },
        ]
        args = SimpleNamespace(
            json=False, jsonl=False, quiet=False, config=None, fix=True, sudo=False
        )
        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(commands.knowledge, "Store", return_value=self.store),
            mock.patch.object(commands.policy, "load_units", return_value=[]),
            mock.patch.object(
                doctor,
                "diagnose",
                return_value={
                    "schema": "taema.doctor.v1",
                    "status": "ok",
                    "checks": [],
                },
            ),
            mock.patch.object(doctor, "repair", return_value=fixes) as repair,
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 1)
        repair.assert_called_once()
        self.assertFalse(repair.call_args.kwargs["sudo"])

        with (
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(commands.knowledge, "Store", return_value=self.store),
            mock.patch.object(commands.policy, "load_units", return_value=[]),
            mock.patch.object(
                doctor,
                "diagnose",
                return_value={
                    "schema": "taema.doctor.v1",
                    "status": "ok",
                    "checks": [],
                },
            ),
            mock.patch.object(
                doctor,
                "repair",
                return_value=[
                    {"name": "state dir", "status": "fixed", "message": "created it"}
                ],
            ),
            mock.patch.object(view, "emit"),
        ):
            self.assertEqual(commands.cmd_doctor(args), 0)

    def test_fix_creates_missing_dirs_and_repairs_perms(self):
        self.cfg["paths"]["state_dir"] = os.path.join(self.temp.name, "new-state")
        self.cfg["paths"]["hooks_dir"] = os.path.join(self.temp.name, "new-hooks")
        config_dir = os.path.join(self.temp.name, "new-config")
        with mock.patch.object(policy, "user_config_dir", return_value=config_dir):
            fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
            again = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["state dir"]["status"], "fixed")
        self.assertEqual(by_name["hooks dir"]["status"], "fixed")
        self.assertEqual(by_name["config dir"]["status"], "fixed")
        self.assertEqual(
            stat.S_IMODE(os.stat(self.cfg["paths"]["state_dir"]).st_mode), 0o700
        )
        self.assertTrue(all(item["status"] == "skipped" for item in again))

        os.chmod(self.cfg["paths"]["state_dir"], 0o755)
        with mock.patch.object(policy, "user_config_dir", return_value=config_dir):
            fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["state dir"]["status"], "fixed")
        self.assertIn("0700", by_name["state dir"]["message"])
        self.assertEqual(
            stat.S_IMODE(os.stat(self.cfg["paths"]["state_dir"]).st_mode), 0o700
        )

    def test_fix_enables_controllers_or_reports_root(self):
        from taema.core import cgroup as cgroup_mod

        control = cgroup_mod.base(os.getuid()) + "/cgroup.subtree_control"
        self.write(control, "+cpu +pids\n")
        fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["controllers"]["status"], "fixed")
        content = Path(control).read_text()
        self.assertIn("+io", content)
        self.assertIn("+memory", content)

        again = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in again}
        self.assertEqual(by_name["controllers"]["status"], "skipped")

        self.write(control, "+cpu +pids\n")
        os.chmod(control, 0o444)
        try:
            fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        finally:
            os.chmod(control, 0o644)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["controllers"]["status"], "needs-root")
        self.assertIn("subtree_control", " ".join(by_name["controllers"]["command"]))

    def test_fix_sudo_runs_root_commands(self):
        from taema.core import cgroup as cgroup_mod

        control = cgroup_mod.base(os.getuid()) + "/cgroup.subtree_control"
        self.write(control, "+cpu +pids\n")
        os.chmod(control, 0o444)
        calls = []
        try:
            fixes = doctor.repair(
                self.cfg,
                self.store,
                system_root=self.system_root,
                sudo=True,
                runner=lambda argv: calls.append(argv) or SimpleNamespace(returncode=0),
            )
        finally:
            os.chmod(control, 0o644)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["controllers"]["status"], "fixed")
        self.assertTrue(calls)
        self.assertIn("subtree_control", " ".join(calls[0]))

    def test_fix_migrates_legacy_store_and_prunes_stale(self):
        fresh = os.path.join(self.temp.name, "mig-state")
        os.makedirs(fresh)
        with open(os.path.join(fresh, "knowledge.json"), "w", encoding="utf-8") as out:
            json.dump({"exes": {}}, out)
        for day in ("20200101", "20200102", "20200103", "20200104", "20200105"):
            Path(os.path.join(fresh, "state-export-%s.json" % day)).write_text("{}\n")
        runtime = os.path.join(self.temp.name, "runtime")
        os.makedirs(os.path.join(runtime, "taema"))
        hold_marker = os.path.join(runtime, "taema", "HOLD")
        Path(hold_marker).write_text(json.dumps({"held": False}))
        cfg = dict(self.cfg)
        cfg["paths"] = dict(self.cfg["paths"], state_dir=fresh)
        config_dir = os.path.join(self.temp.name, "mig-config")
        with (
            mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}),
            mock.patch.object(policy, "user_config_dir", return_value=config_dir),
        ):
            fixes = doctor.repair(cfg, None, system_root=self.system_root)
            again = doctor.repair(cfg, None, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["store migration"]["status"], "fixed")
        self.assertTrue(os.path.isfile(os.path.join(fresh, "state.db")))
        remaining = sorted(
            name for name in os.listdir(fresh) if name.startswith("state-export-")
        )
        self.assertEqual(
            remaining,
            [
                "state-export-20200103.json",
                "state-export-20200104.json",
                "state-export-20200105.json",
            ],
        )
        self.assertFalse(os.path.exists(hold_marker))
        by_name = {item["name"]: item for item in again}
        self.assertEqual(by_name["store migration"]["status"], "skipped")
        self.assertEqual(by_name["stale flags"]["status"], "skipped")

    def test_fix_second_run_changes_nothing(self):
        config_home = os.path.join(self.temp.name, "idem-xdg")
        runtime = os.path.join(self.temp.name, "idem-runtime")
        os.makedirs(runtime)
        with (
            mock.patch.dict(
                os.environ,
                {"XDG_CONFIG_HOME": config_home, "XDG_RUNTIME_DIR": runtime},
            ),
            mock.patch.object(policy, "user_config_dir", return_value=config_home),
        ):
            first = doctor.repair(self.cfg, self.store, system_root=self.system_root)
            second = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        self.assertTrue(first)
        self.assertFalse(
            [item for item in first if item["status"] in ("fail", "needs-root")]
        )
        self.assertTrue(
            all(item["status"] == "skipped" for item in second),
            [item for item in second if item["status"] != "skipped"],
        )

    def test_fix_end_to_end_reports_each_repair(self):
        config_home = os.path.join(self.temp.name, "e2e-xdg")
        runtime = os.path.join(self.temp.name, "e2e-runtime")
        os.makedirs(runtime)
        # Diagnose against the fixture root: group, helper, service, and
        # cgroup checks read the live machine, which containers may lack.
        # Repair keeps running against the same fixtures.
        real_diagnose = doctor.diagnose
        args = SimpleNamespace(
            json=False, jsonl=False, quiet=False, config=None, fix=True, sudo=False
        )
        with (
            mock.patch.dict(
                os.environ,
                {"XDG_CONFIG_HOME": config_home, "XDG_RUNTIME_DIR": runtime},
            ),
            mock.patch.object(policy, "user_config_dir", return_value=config_home),
            mock.patch.object(commands.policy, "load_config", return_value=self.cfg),
            mock.patch.object(commands, "ask", return_value=None),
            mock.patch.object(commands.knowledge, "Store", return_value=self.store),
            mock.patch.object(commands.policy, "load_units", return_value=[]),
            mock.patch.object(view, "emit") as emit,
            mock.patch.object(
                doctor,
                "diagnose",
                side_effect=lambda cfg, store=None, units=None, **kw: real_diagnose(
                    cfg, store, units, system_root=self.system_root, **kw
                ),
            ),
        ):
            self.assertEqual(commands.cmd_doctor(args), 0)
        models = [call.args[0] for call in emit.call_args_list]
        repair_report = next(
            item for item in models if item.get("schema") == "taema.doctor.repair.v1"
        )
        names = {item["name"] for item in repair_report["fixes"]}
        self.assertTrue(
            {
                "state dir",
                "config dir",
                "hooks dir",
                "controllers",
                "agent autostart",
                "store migration",
                "stale flags",
            }
            <= names
        )

    def test_fix_installs_agent_autostart(self):
        source = (
            self.system_root + "/usr/share/examples/taema/autostart/taema-agent.desktop"
        )
        body = "[Desktop Entry]\nName=taema session agent\nExec=taema agent\n"
        self.write(source, body)
        config_home = os.path.join(self.temp.name, "xdg")
        dest = os.path.join(config_home, "autostart", "taema-agent.desktop")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config_home}):
            fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
            again = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["agent autostart"]["status"], "fixed")
        self.assertEqual(Path(dest).read_text(), body)
        by_name = {item["name"]: item for item in again}
        self.assertEqual(by_name["agent autostart"]["status"], "skipped")

        self.write(dest, "customized by user\n")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config_home}):
            fixes = doctor.repair(self.cfg, self.store, system_root=self.system_root)
        by_name = {item["name"]: item for item in fixes}
        self.assertEqual(by_name["agent autostart"]["status"], "skipped")
        self.assertEqual(Path(dest).read_text(), "customized by user\n")


if __name__ == "__main__":
    unittest.main()
