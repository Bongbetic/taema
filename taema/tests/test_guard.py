"""Pressure guard parsing, PSI notification, and ordered daemon actions."""

import json
import os
import tempfile
import time
from contextlib import ExitStack, nullcontext
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from taema import doctor
from taema.cli import view
from taema.config import policy
from taema.daemon import service
from taema.governor import guard
from taema.model import authorization
from tests.test_phase0 import FakeCg, make_cfg, tmp


class GuardPolicyTests(unittest.TestCase):
    def test_psi_trigger_parses_supported_durations_and_rejects_bad_windows(self):
        self.assertEqual(
            guard.psi_trigger("some", "150ms/2s"), ("some", 150000, 2000000)
        )
        self.assertEqual(guard.psi_threshold_percent("50ms/2s", "full"), 2.5)
        for setting in ("0ms/2s", "2ms/1s", "2s/2s", "1ms/12s", "invalid"):
            with self.subTest(setting=setting), self.assertRaises(ValueError):
                guard.psi_trigger("some", setting)

    def test_available_floor_tracks_earlyoom_or_uses_conservative_default(self):
        self.assertEqual(
            guard.floor_percent(
                "auto", earlyoom_present=False, earlyoom_memory_percent=None
            ),
            12,
        )
        self.assertEqual(
            guard.floor_percent(
                "auto", earlyoom_present=True, earlyoom_memory_percent=8
            ),
            12,
        )
        self.assertEqual(
            guard.available_floor_bytes(
                1000, "auto", earlyoom_present=True, earlyoom_memory_percent=8
            ),
            120,
        )
        self.assertEqual(guard.available_floor_bytes(1000, 7.5), 75)

    def test_pressure_helpers_handle_invalid_inputs_and_proc_meminfo(self):
        with self.assertRaises(ValueError):
            guard.psi_trigger("host", "150ms/2s")
        with self.assertRaises(ValueError):
            guard.psi_trigger("some", None)
        with self.assertRaises(ValueError):
            guard.floor_percent(
                True, earlyoom_present=False, earlyoom_memory_percent=None
            )
        self.assertEqual(
            guard.floor_percent(
                "auto", earlyoom_present=True, earlyoom_memory_percent=float("nan")
            ),
            14,
        )
        self.assertIsNone(guard.available_floor_bytes(-1))

        with tempfile.TemporaryDirectory() as root:
            Path(root, "meminfo").write_text(
                "MemTotal: 100 kB\nMemAvailable: 20 kB\n"
                "Malformed\nOther: nope kB\nOther: -1 kB\n"
            )
            self.assertEqual(guard.host_memory(root), (20 * 1024, 100 * 1024))
            self.assertEqual(
                guard.host_memory(os.path.join(root, "missing")), (None, None)
            )

    def test_earlyoom_parser_handles_combined_options_and_bad_thresholds(self):
        options = guard.earlyoom_options(
            ("earlyoom", "--prefer=^node$", "-m8", "-M1024", "-s5")
        )
        self.assertEqual(
            dict(options), {"-M": "1024", "-m": "8", "-s": "5", "--prefer": "^node$"}
        )
        handler = guard.OomHandler(
            "earlyoom",
            1,
            ("earlyoom",),
            (("-M", "invalid"), ("-m", "not-a-number")),
        )
        self.assertEqual(guard.earlyoom_memory_percent(handler, 8 * 1024 * 1024), 10)
        self.assertEqual(
            guard.display_earlyoom(guard.OomHandler("earlyoom", 1, ("earlyoom",))),
            "-m 10 (default)% -s 10 (default)%",
        )

    def test_handler_detection_uses_comm_when_cmdline_is_unreadable(self):
        with tempfile.TemporaryDirectory() as proc_root:
            pid = os.path.join(proc_root, "23")
            os.makedirs(pid)
            Path(pid, "comm").write_text("nohang\n")
            self.assertEqual(guard._read_comm(proc_root, "missing"), "")
            found = guard.detect_oom_handlers(proc_root)
        self.assertEqual(found["nohang"][0].argv, ())

    def test_psi_monitor_reports_injected_pressure_fd(self):
        read_fd, write_fd = os.pipe()
        monitor = guard.PsiTriggerMonitor()
        try:
            monitor.watch_fd("some", read_fd)
            os.write(write_fd, b"pressure")
            self.assertEqual(monitor.poll(), ["some"])
        finally:
            monitor.close()
            os.close(write_fd)

    def test_psi_monitor_writes_kernel_triggers_and_handles_partial_write(self):
        good_read, good_write = os.pipe()
        bad_read, bad_write = os.pipe()
        monitor = guard.PsiTriggerMonitor()
        writes = []

        def fake_write(_fd, payload):
            writes.append(payload)
            return len(payload) if len(writes) == 1 else 1

        with (
            mock.patch.object(guard.os, "open", side_effect=[good_read, bad_read]),
            mock.patch.object(guard.os, "write", side_effect=fake_write),
        ):
            self.assertEqual(
                monitor.open_triggers("/fake/memory.pressure", {"some": "150ms/2s"}), []
            )
            failures = monitor.open_triggers(
                "/fake/memory.pressure", {"full": "50ms/2s"}
            )

        self.assertTrue(writes[0].endswith(b"\0"))
        self.assertEqual(monitor.metrics, ("some",))
        self.assertEqual(len(failures), 1)
        self.assertIn("incomplete PSI trigger write", failures[0])
        monitor.close()
        os.close(good_write)
        os.close(bad_write)

    def test_oom_handler_detection_parses_earlyoom_settings(self):
        with tempfile.TemporaryDirectory() as proc_root:
            pid = os.path.join(proc_root, "77")
            os.makedirs(pid)
            Path(pid, "comm").write_text("earlyoom\n")
            Path(pid, "cmdline").write_bytes(
                b"\0".join(
                    (
                        b"/usr/bin/earlyoom",
                        b"-m",
                        b"8",
                        b"-s",
                        b"15",
                        b"--prefer",
                        b"node",
                        b"",
                    )
                )
            )
            found = guard.detect_oom_handlers(proc_root)
        self.assertEqual(len(found["earlyoom"]), 1)
        self.assertEqual(found["earlyoom"][0].option("-m"), "8")
        self.assertEqual(found["earlyoom"][0].option("--prefer"), "node")

    def test_guard_config_validates_switches_floor_cooldown_and_triggers(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "taema.toml")
            path.write_text(
                "[experimental]\nguard = false\n"
                "[guard]\nenabled = false\navailable_floor = 8.5\n"
                'psi_some = "100ms/2s"\npsi_full = "25ms/2s"\n'
                "cooldown = 3.5\nfreeze_in_adopt = true\n"
            )
            cfg = policy._load_files([str(path)])
            self.assertFalse(cfg["experimental"]["guard"])
            self.assertFalse(cfg["guard"]["enabled"])
            self.assertEqual(cfg["guard"]["available_floor"], 8.5)
            self.assertEqual(cfg["guard"]["cooldown"], 3.5)

            for setting, value, expected in (
                ("available_floor", "101", "between 0 and 100"),
                ("cooldown", "-1", "non-negative number"),
                ("psi_some", '"1ms/1s"', "PSI trigger duration"),
                ("freeze_in_adopt", '"yes"', "must be a boolean"),
            ):
                path.write_text("[guard]\n%s = %s\n" % (setting, value))
                with (
                    self.subTest(setting=setting),
                    self.assertRaisesRegex(ValueError, expected),
                ):
                    policy._load_files([str(path)])


class GuardDaemonTests(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.state_dir = tmp()
        cfg = make_cfg(self.state_dir, mode="auto")
        cfg["experimental"] = {"guard": True}
        cfg["guard"] = {
            "enabled": True,
            "cooldown": 10,
            "available_floor": 0,
            "psi_some": "150ms/2s",
            "psi_full": "50ms/2s",
            "freeze_in_adopt": False,
        }
        self.daemon = service.Daemon(cfg)
        self.addCleanup(self.daemon.sel.close)

    def test_guard_runs_ladder_in_order_and_finishes_when_pressure_clears(self):
        pressure = {"high": True}
        steps = []

        def action(name):
            steps.append(name)
            if name == "freeze":
                pressure["high"] = False
            return {"performed": 1, "bytes_freed": 1024, "scopes": [name]}

        self.daemon.cfg["guard"]["cooldown"] = 0
        with (
            mock.patch.object(
                self.daemon,
                "_guard_pressure_high",
                side_effect=lambda: pressure["high"],
            ),
            mock.patch.object(self.daemon, "_guard_floor", return_value=(100, 50)),
            mock.patch.object(
                self.daemon,
                "_guard_reclaim_step",
                side_effect=lambda stage: action(stage),
            ),
            mock.patch.object(
                self.daemon, "_guard_freeze_step", side_effect=lambda: action("freeze")
            ),
            mock.patch.object(
                self.daemon, "_guard_stop_step", side_effect=lambda: action("stop")
            ),
        ):
            result = self.daemon.guard_pass("some")

        self.assertEqual(steps, ["page_cache", "freeze"])
        self.assertFalse(result["active"])
        self.assertEqual(result["last_trigger"], "some")
        self.assertEqual(result["last_bytes_freed"], 2048)
        with open(self.daemon.store.log_path, encoding="utf-8") as source:
            events = [json.loads(line) for line in source]
        finished = next(
            item for item in events if item.get("event") == "guard_finished"
        )
        self.assertEqual(finished["trigger"], "some")
        self.assertEqual(
            [item["step"] for item in finished["steps"]], ["page_cache", "freeze"]
        )
        self.assertGreaterEqual(finished["duration_ms"], 0)

    def test_guard_closes_episode_when_pressure_clears_before_retry(self):
        self.daemon.guard_state.update(
            active=True,
            trigger="full",
            triggers=["full"],
            started_at=time.time() - 1,
            steps=[{"step": "page_cache", "bytes_freed": 3}],
            bytes_freed=3,
            retry_at=time.time() + 10,
        )
        with mock.patch.object(self.daemon, "_guard_pressure_high", return_value=False):
            result = self.daemon.guard_pass("retry")
        self.assertFalse(result["active"])
        self.assertEqual(result["last_trigger"], "full")
        self.assertEqual(result["last_bytes_freed"], 3)

    def test_disabling_guard_closes_an_active_episode(self):
        self.daemon.guard_state.update(
            active=True,
            trigger="available",
            triggers=["available"],
            steps=[],
            bytes_freed=0,
        )
        self.daemon.cfg["experimental"]["guard"] = False
        result = self.daemon.guard_pass("retry")
        self.assertFalse(result["active"])
        with open(self.daemon.store.log_path, encoding="utf-8") as source:
            events = [json.loads(line) for line in source]
        finished = next(
            item for item in events if item.get("event") == "guard_finished"
        )
        self.assertEqual(finished["outcome"], "guard disabled")

    def test_guard_respects_step_cooldown_without_blocking_later_steps(self):
        pressure = {"high": True}
        self.daemon.cfg["guard"]["cooldown"] = 10
        self.daemon.guard_last_steps["page_cache"] = time.monotonic()
        with (
            mock.patch.object(
                self.daemon,
                "_guard_pressure_high",
                side_effect=lambda: pressure["high"],
            ),
            mock.patch.object(self.daemon, "_guard_floor", return_value=(100, 50)),
            mock.patch.object(self.daemon, "_guard_reclaim_step") as reclaim,
            mock.patch.object(
                self.daemon,
                "_guard_freeze_step",
                side_effect=lambda: (
                    pressure.update(high=False)
                    or {"performed": 1, "bytes_freed": 0, "scopes": ["leftover/a"]}
                ),
            ),
            mock.patch.object(self.daemon, "_guard_stop_step") as stop,
        ):
            result = self.daemon.guard_pass("retry")
        reclaim.assert_not_called()
        stop.assert_not_called()
        self.assertFalse(result["active"])
        self.assertEqual(result["steps"][0]["step"], "freeze")

    def test_psi_and_available_floor_pressure_feed_collector_queue(self):
        read_fd, write_fd = os.pipe()
        monitor = guard.PsiTriggerMonitor()
        monitor.watch_fd("some", read_fd)
        self.daemon.pressure_monitor = monitor
        self.addCleanup(monitor.close)
        os.write(write_fd, b"pressure")
        self.daemon._collect_pressure_events()
        with mock.patch.object(self.daemon, "_guard_floor", return_value=(10, 20)):
            self.daemon._collect_available_floor_event(now=1.0)
        os.close(write_fd)
        self.assertIn(service.PressureHigh("some"), self.daemon.collector_events)
        self.assertIn(service.PressureHigh("available"), self.daemon.collector_events)

    def test_guard_floor_uses_earlyoom_threshold_and_caches_handler_scan(self):
        self.daemon.cfg["guard"]["available_floor"] = "auto"
        handler = guard.OomHandler(
            "earlyoom", 77, ("earlyoom", "-m", "8"), (("-m", "8"),)
        )
        handlers = {"earlyoom": (handler,), "nohang": (), "systemd-oomd": ()}
        with (
            mock.patch.object(
                service.pressure_guard, "host_memory", return_value=(300, 1000)
            ),
            mock.patch.object(
                service.pressure_guard, "detect_oom_handlers", return_value=handlers
            ) as detect,
        ):
            self.assertEqual(self.daemon._guard_floor(), (300, 120))
            self.assertEqual(self.daemon._guard_floor(), (300, 120))
            self.daemon._guard_handlers(now=self.daemon.oom_handlers_checked_at + 31)
        self.assertEqual(detect.call_count, 2)

    def test_guard_floor_fails_closed_when_runtime_setting_is_invalid(self):
        with (
            mock.patch.object(
                service.pressure_guard, "host_memory", return_value=(50, 100)
            ),
            mock.patch.object(
                service.pressure_guard,
                "available_floor_bytes",
                side_effect=ValueError("bad floor"),
            ),
        ):
            self.assertEqual(self.daemon._guard_floor(), (50, None))

    def test_missing_pressure_trigger_files_are_reported_once(self):
        self.daemon._sync_pressure_monitor()
        self.assertIsNone(self.daemon.pressure_monitor)
        self.assertEqual(len(self.daemon.pressure_watch_failures), 2)
        first = self.daemon.pressure_watch_signature
        self.daemon._sync_pressure_monitor()
        self.assertEqual(self.daemon.pressure_watch_signature, first)
        with open(self.daemon.store.log_path, encoding="utf-8") as source:
            events = [json.loads(line) for line in source]
        self.assertEqual(
            sum(item.get("event") == "guard_trigger_unavailable" for item in events), 2
        )

    def test_pressure_monitor_registers_collects_and_closes_with_guard(self):
        read_fd, write_fd = os.pipe()

        class FakeMonitor:
            metrics = ("some",)

            closed = False

            def fileno(self):
                return read_fd

            def open_triggers(self, _path, _settings):
                return []

            def poll(self):
                return ["some"]

            def close(self):
                if not self.closed:
                    self.closed = True
                    os.close(read_fd)

        monitor = FakeMonitor()
        self.addCleanup(lambda: os.close(write_fd))
        with mock.patch.object(
            service.pressure_guard, "PsiTriggerMonitor", return_value=monitor
        ):
            self.daemon._sync_pressure_monitor()
            self.assertIs(self.daemon.pressure_monitor, monitor)
            self.daemon._collect_pressure_events()
            self.assertIn(service.PressureHigh("some"), self.daemon.collector_events)

            self.daemon.cfg["experimental"]["guard"] = False
            self.daemon._sync_pressure_monitor()

        self.assertIsNone(self.daemon.pressure_monitor)
        with self.assertRaises(KeyError):
            self.daemon.sel.get_key(read_fd)

    def test_pressure_monitor_registration_and_poll_failures_fall_back_cleanly(self):
        read_fd, write_fd = os.pipe()

        class FakeMonitor:
            metrics = ("some",)
            closed = False

            def fileno(self):
                return read_fd

            def open_triggers(self, _path, _settings):
                return []

            def poll(self):
                raise OSError("trigger fd disappeared")

            def close(self):
                if not self.closed:
                    self.closed = True
                    os.close(read_fd)

        monitor = FakeMonitor()
        self.addCleanup(lambda: os.close(write_fd))
        with (
            mock.patch.object(
                service.pressure_guard, "PsiTriggerMonitor", return_value=monitor
            ),
            mock.patch.object(self.daemon.sel, "register", side_effect=OSError("full")),
        ):
            self.daemon._sync_pressure_monitor()
        self.assertIsNone(self.daemon.pressure_monitor)
        self.assertIn(
            "selector registration failed", self.daemon.pressure_watch_failures[-1]
        )

        self.daemon.pressure_monitor = monitor
        self.daemon._collect_pressure_events()
        self.assertIsNone(self.daemon.pressure_monitor)
        with open(self.daemon.store.log_path, encoding="utf-8") as source:
            events = [json.loads(line) for line in source]
        self.assertTrue(
            any("trigger fd disappeared" in item.get("reason", "") for item in events)
        )

    def test_guard_pressure_rechecks_floor_psi_and_trigger_window(self):
        with mock.patch.object(self.daemon, "_guard_enabled", return_value=False):
            self.assertFalse(self.daemon._guard_pressure_high())

        with mock.patch.object(self.daemon, "_guard_enabled", return_value=True):
            self.daemon.guard_trigger_until = time.monotonic() + 1
            self.assertTrue(self.daemon._guard_pressure_high())
            self.daemon.guard_trigger_until = 0
            with (
                mock.patch.object(self.daemon, "_guard_floor", return_value=(10, 20)),
                mock.patch.object(service.memory, "pressure", return_value={}),
            ):
                self.assertTrue(self.daemon._guard_pressure_high())
            with (
                mock.patch.object(self.daemon, "_guard_floor", return_value=(100, 20)),
                mock.patch.object(
                    service.memory,
                    "pressure",
                    return_value={"some_avg10": 7.5, "full_avg10": 0},
                ),
            ):
                self.assertTrue(self.daemon._guard_pressure_high())
            self.daemon.cfg["guard"]["psi_some"] = "invalid"
            with (
                mock.patch.object(self.daemon, "_guard_floor", return_value=(100, 20)),
                mock.patch.object(
                    service.memory, "pressure", return_value={"some_avg10": 1}
                ),
            ):
                self.assertFalse(self.daemon._guard_pressure_high())

    def test_available_floor_sampling_obeys_interval_and_episode_retry_time(self):
        with mock.patch.object(self.daemon, "_guard_floor", return_value=(10, 20)):
            self.daemon._collect_available_floor_event(now=0.5)
            self.assertEqual(list(self.daemon.collector_events), [])
            self.daemon._collect_available_floor_event(now=1.0)
            self.assertEqual(
                list(self.daemon.collector_events), [service.PressureHigh("available")]
            )

            self.daemon.collector_events.clear()
            self.daemon._collector_event_set.clear()
            self.daemon.guard_state.update(active=True, retry_at=5.0)
            self.daemon._collect_available_floor_event(now=2.0)
            self.assertEqual(list(self.daemon.collector_events), [])
            self.daemon._collect_available_floor_event(now=5.0)
        self.assertEqual(
            list(self.daemon.collector_events), [service.PressureHigh("retry")]
        )

    def test_guard_pass_merges_triggers_and_schedules_a_retry_when_pressure_persists(
        self,
    ):
        self.daemon.cfg["guard"]["cooldown"] = "invalid"
        self.daemon.cfg["guard"]["psi_full"] = "invalid"
        availability = iter((100, 100, 110) * 10)
        action_result = {
            "performed": 0,
            "bytes_freed": 0,
            "scopes": [],
            "reason": "not eligible",
        }
        with (
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(
                self.daemon,
                "_guard_floor",
                side_effect=lambda: (next(availability), 20),
            ),
            mock.patch.object(
                self.daemon, "_guard_reclaim_step", return_value=action_result
            ),
            mock.patch.object(
                self.daemon, "_guard_freeze_step", return_value=action_result
            ),
            mock.patch.object(
                self.daemon, "_guard_stop_step", return_value=action_result
            ),
            mock.patch.object(
                service.pressure_guard,
                "psi_trigger",
                side_effect=ValueError("bad trigger"),
            ),
        ):
            first = self.daemon.guard_pass("full")
            self.daemon.guard_last_steps.clear()
            second = self.daemon.guard_pass("some")

        self.assertTrue(first["active"])
        self.assertEqual(second["triggers"], ["full", "some"])
        self.assertEqual(len(second["steps"]), 8)
        self.assertTrue(all(step["status"] == "skipped" for step in second["steps"]))
        self.assertGreater(second["bytes_freed"], 0)
        self.assertGreater(second["retry_at"], time.time())

    def test_pressure_event_dispatch_and_timeout_schedule_guard_retry(self):
        self.daemon.queue_collector_event(service.PressureHigh("full"))
        with mock.patch.object(self.daemon, "guard_pass") as guard_pass:
            self.daemon.drain_collector_events()
        guard_pass.assert_called_once_with("full")

        self.daemon.guard_state.update(active=True, retry_at=time.time() + 5)
        self.daemon.last_guard_check = time.time()
        with mock.patch.object(self.daemon, "_guard_enabled", return_value=True):
            self.assertLessEqual(self.daemon.next_timeout(), 1.0)

        self.daemon.collector_events.clear()
        self.daemon._collector_event_set.clear()
        self.daemon.guard_state["retry_at"] = 199.0
        self.daemon.last.update({key: 200.0 for key in self.daemon.last})
        with (
            mock.patch.object(service.time, "time", return_value=200.0),
            mock.patch.object(
                self.daemon.store.db, "write_available", return_value=True
            ),
            mock.patch.object(self.daemon, "guarded", side_effect=lambda fn: fn()),
            mock.patch.object(self.daemon, "poll_config_reload"),
            mock.patch.object(self.daemon, "_sync_pressure_monitor"),
            mock.patch.object(self.daemon, "check_socket"),
            mock.patch.object(self.daemon.store, "apply_feedback"),
            mock.patch.object(self.daemon, "toggle_hold"),
            mock.patch.object(self.daemon, "thaw_held_scopes"),
            mock.patch.object(self.daemon, "run_deadlines"),
            mock.patch.object(self.daemon, "_collect_available_floor_event"),
            mock.patch.object(self.daemon, "_run_listener_wake_if_due"),
            mock.patch.object(self.daemon, "_write_summary_if_dirty"),
            mock.patch.object(self.daemon, "guard_pass") as retry_pass,
        ):
            self.daemon.tick()
        retry_pass.assert_called_once_with("retry")

    def test_guard_pass_returns_without_starting_an_episode_after_pressure_clears(self):
        with mock.patch.object(self.daemon, "_guard_pressure_high", return_value=False):
            self.assertIsNone(self.daemon.guard_pass("retry"))

    def test_guard_reclaim_visits_largest_page_cache_first_and_only_frozen_anon(self):
        paths = {
            "leftover/small": "/fake/small",
            "app-background": "/fake/background",
            "app-foreground": "/fake/foreground",
            "leftover/frozen": "/fake/frozen",
        }
        classes = {
            "leftover/small": "leftover",
            "app-background": "background",
            "app-foreground": "foreground",
            "leftover/frozen": "leftover",
        }
        counters = {
            "/fake/small": {"reclaimable_bytes": 100, "anon_bytes": 30},
            "/fake/background": {"reclaimable_bytes": 300, "anon_bytes": 60},
            "/fake/foreground": {"reclaimable_bytes": 900, "anon_bytes": 90},
            "/fake/frozen": {"reclaimable_bytes": 200, "anon_bytes": 500},
        }
        managed = {"leftover/frozen": {"source": "auto"}}
        self.daemon.store.data["frozen_scopes"] = managed

        def reclaim(scope, _path, _now, _pressure, **kwargs):
            field = (
                "file_reclaimed_bytes"
                if kwargs["stage"] == "page_cache"
                else "anonymous_reclaimed_bytes"
            )
            return {
                "scope": scope,
                "status": "reclaimed",
                field: counters[paths[scope]][
                    "reclaimable_bytes"
                    if field == "file_reclaimed_bytes"
                    else "anon_bytes"
                ],
            }

        with (
            mock.patch.object(self.daemon, "_memory_paths", return_value=paths),
            mock.patch.object(
                self.daemon,
                "_reclaim_class",
                side_effect=lambda scope, _path: classes[scope],
            ),
            mock.patch.object(self.daemon, "_freeze_value", return_value="1"),
            mock.patch.object(
                service.memory,
                "scope_counters",
                side_effect=lambda path: counters[path],
            ),
            mock.patch.object(service.memory, "pressure", return_value={}),
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(
                self.daemon, "_reclaim_one", side_effect=reclaim
            ) as reclaim_one,
        ):
            page_cache = self.daemon._guard_reclaim_step("page_cache")
            anon = self.daemon._guard_reclaim_step("anonymous")

        page_scopes = [call.args[0] for call in reclaim_one.call_args_list[:3]]
        anon_scopes = [call.args[0] for call in reclaim_one.call_args_list[3:]]
        self.assertEqual(
            page_scopes, ["app-background", "leftover/frozen", "leftover/small"]
        )
        self.assertEqual(anon_scopes, ["leftover/frozen"])
        self.assertEqual(page_cache["bytes_freed"], 600)
        self.assertEqual(anon["bytes_freed"], 500)

    def test_guard_reclaim_skips_bad_counters_and_uses_legacy_byte_result(self):
        paths = {
            "leftover/missing": "/fake/missing",
            "leftover/empty": "/fake/empty",
            "leftover/reclaimed": "/fake/reclaimed",
        }
        counters = {
            "/fake/missing": None,
            "/fake/empty": {"reclaimable_bytes": 0},
            "/fake/reclaimed": {"reclaimable_bytes": 10},
        }
        with (
            mock.patch.object(self.daemon, "_memory_paths", return_value=paths),
            mock.patch.object(self.daemon, "_reclaim_class", return_value="background"),
            mock.patch.object(self.daemon, "_freeze_value", return_value="0"),
            mock.patch.object(
                service.memory,
                "scope_counters",
                side_effect=lambda path: counters[path],
            ),
            mock.patch.object(service.memory, "pressure", return_value={}),
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(
                self.daemon,
                "_reclaim_one",
                return_value={
                    "scope": "leftover/reclaimed",
                    "status": "reclaimed",
                    "reclaimed_bytes": 50,
                },
            ) as reclaim,
        ):
            result = self.daemon._guard_reclaim_step("page_cache")
            invalid = self.daemon._guard_reclaim_step("unsupported")

        reclaim.assert_called_once()
        self.assertEqual(result["bytes_freed"], 50)
        self.assertEqual(result["scopes"], ["leftover/reclaimed"])
        self.assertEqual(invalid["performed"], 0)

    def test_status_view_model_shows_an_active_guard(self):
        model = {
            "status": {
                "daemon": "running",
                "mode": "auto",
                "guard": {"active": True, "trigger": "some", "bytes_freed": 2048},
            },
            "scopes": [],
        }
        rendered = view.render_status(model, SimpleNamespace(_width=80, _color=False))
        self.assertIn("guard: ACTIVE (some; 2.0K reclaimed)", rendered)
        self.daemon.guard_state.update(
            active=True,
            trigger="some",
            triggers=["some"],
            steps=[{"step": "page_cache"}],
            bytes_freed=2048,
        )
        status = self.daemon.guard_status()
        self.assertTrue(status["active"])
        self.assertEqual(status["bytes_freed"], 2048)
        status["triggers"].clear()
        self.assertEqual(self.daemon.guard_state["triggers"], ["some"])
        self.daemon.guard_state.update(
            active=True,
            trigger="some",
            triggers=["some"],
            steps=[{"step": "page_cache"}],
            bytes_freed=2048,
        )
        status = self.daemon.guard_status()
        self.assertTrue(status["active"])
        self.assertEqual(status["bytes_freed"], 2048)
        status["triggers"].clear()
        self.assertEqual(self.daemon.guard_state["triggers"], ["some"])

    def test_guard_freeze_uses_guard_flag_and_requires_adopt_opt_in(self):
        self.daemon.cfg["freeze"] = {"enabled": True}
        with mock.patch.object(
            self.daemon,
            "freeze_pass",
            return_value=[{"ok": True, "scope": "leftover/a"}],
        ) as freeze_pass:
            result = self.daemon._guard_freeze_step()
        freeze_pass.assert_called_once_with(guard=True)
        self.assertEqual(result["scopes"], ["leftover/a"])

        self.daemon.cfg["mode"] = "adopt"
        self.daemon.cfg["guard"]["freeze_in_adopt"] = False
        with mock.patch.object(self.daemon, "freeze_pass") as freeze_pass:
            denied = self.daemon._guard_freeze_step()
        freeze_pass.assert_not_called()
        self.assertEqual(denied["performed"], 0)

        self.daemon.cfg["guard"]["freeze_in_adopt"] = True
        with mock.patch.object(
            self.daemon,
            "freeze_pass",
            return_value=[{"ok": True, "scope": "leftover/a"}],
        ) as freeze_pass:
            allowed = self.daemon._guard_freeze_step()
        freeze_pass.assert_called_once_with(guard=True)
        self.assertEqual(allowed["scopes"], ["leftover/a"])

        self.daemon.cfg["mode"] = "observe"
        observed = self.daemon._guard_freeze_step()
        self.assertEqual(observed["reason"], "observe mode")

        self.daemon.cfg["mode"] = "auto"
        self.daemon.cfg["freeze"]["enabled"] = False
        self.daemon.cfg["guard"]["freeze_in_adopt"] = False
        with mock.patch.object(self.daemon, "_freeze_auto_enabled", return_value=False):
            denied = self.daemon._guard_freeze_step()
        self.assertEqual(denied["reason"], "freezing is not authorized in this mode")

        self.daemon.cfg["mode"] = "observe"
        observed = self.daemon._guard_freeze_step()
        self.assertEqual(observed["reason"], "observe mode")

        self.daemon.cfg["mode"] = "auto"
        self.daemon.cfg["freeze"]["enabled"] = False
        self.daemon.cfg["guard"]["freeze_in_adopt"] = False
        with mock.patch.object(self.daemon, "_freeze_auto_enabled", return_value=False):
            denied = self.daemon._guard_freeze_step()
        self.assertEqual(denied["reason"], "freezing is not authorized in this mode")

    def test_guard_reclaim_step_can_reclaim_again_after_page_cache_stage(self):
        path = self.cg.leaf("leftover/reclaim-test", [4242])
        scope = "leftover/reclaim-test"
        self.daemon.cfg["mem"] = {"enabled": True, "reclaim": True}
        self.daemon.reclaim_state[scope] = {"last_at": 999.0}
        counters = {
            "current_bytes": 512,
            "anon_bytes": 128,
            "reclaimable_bytes": 256,
            "workingset_refault_file": 0,
            "swap_bytes": 0,
        }
        allowed = SimpleNamespace(
            verdict=authorization.ACT,
            reason="authorized",
            authority="mode",
        )
        with (
            mock.patch.object(service.cgroup, "tree_procs", return_value=[4242]),
            mock.patch.object(self.daemon, "_reclaim_safety_reason", return_value=""),
            mock.patch.object(self.daemon, "_reclaim_warm", return_value=False),
            mock.patch.object(
                self.daemon, "_reclaim_idle", return_value=(True, "idle")
            ),
            mock.patch.object(self.daemon, "authorize", return_value=allowed),
            mock.patch.object(service.memory, "scope_counters", return_value=counters),
            mock.patch.object(service.memory, "page_cache_budget", return_value=64),
        ):
            regular = self.daemon._reclaim_one(
                scope,
                path,
                1000.0,
                {},
                dry_run=True,
                resource_class="leftover",
                stage="page_cache",
            )
            pressure = self.daemon._reclaim_one(
                scope,
                path,
                1000.0,
                {},
                dry_run=True,
                resource_class="leftover",
                guard=True,
                stage="page_cache",
            )
        self.assertIn("cooldown", regular["reason"])
        self.assertEqual(pressure["status"], "would")

    def test_unlearned_scope_is_not_selected_for_guard_stop(self):
        path = self.cg.leaf("unknown", [4242])
        with (
            mock.patch.object(
                service.engine, "gc_candidates", return_value=[(path, "unlearned")]
            ),
            mock.patch.object(
                service.memory, "scope_counters", return_value={"current_bytes": 100}
            ),
            mock.patch.object(service.engine, "stop") as stop,
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
        ):
            result = self.daemon._guard_stop_step()
        self.assertEqual(result["performed"], 0)
        stop.assert_not_called()

    def test_guard_stops_only_one_authorized_pair_scope_largest_first(self):
        small = self.cg.leaf("leftover/small", [4242])
        large = self.cg.leaf("leftover/large", [4243])
        facts = authorization.Facts(scope="leftover/large", pair_action="stop")
        decision = SimpleNamespace(
            verdict=authorization.ACT, reason="learned pair", authority="learned"
        )
        with (
            mock.patch.object(
                service.engine,
                "gc_candidates",
                return_value=[
                    (small, "pair stop answered"),
                    (large, "pair stop learned"),
                ],
            ),
            mock.patch.object(
                service.memory,
                "scope_counters",
                side_effect=lambda path: {
                    "current_bytes": 100 if path == small else 300
                },
            ),
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(self.daemon, "_pair_scope_facts", return_value=facts),
            mock.patch.object(self.daemon, "authorize", return_value=decision),
            mock.patch.object(self.daemon, "auto_stop_path", return_value=True) as stop,
        ):
            result = self.daemon._guard_stop_step()

        self.assertEqual(result["performed"], 1)
        self.assertEqual(result["bytes_freed"], 300)
        self.assertEqual(result["scopes"], ["leftover/large"])
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[0], large)

    def test_guard_stop_filters_ineligible_candidates_and_stops_next_authorized_scope(
        self,
    ):
        denied = self.cg.leaf("app-denied", [4242])
        allowed = self.cg.leaf("app-allowed", [4243])
        missing = self.cg.leaf("app-missing", [4244])
        filtered = self.cg.leaf("app-filtered", [4245])
        units = {
            "app-denied": {"unit": {"stop_when_unneeded": True}},
            "app-allowed": {"unit": {"stop_when_unneeded": True}},
            "app-missing": {"unit": {"stop_when_unneeded": True}},
            "app-filtered": {"unit": {"stop_when_unneeded": False}},
        }
        decisions = [
            SimpleNamespace(
                verdict=authorization.WOULD_ACT, reason="would stop", authority="unit"
            ),
            SimpleNamespace(
                verdict=authorization.ACT, reason="authorized", authority="unit"
            ),
        ]
        with (
            mock.patch.object(
                service.engine,
                "gc_candidates",
                return_value=[
                    (allowed, "unit idle"),
                    (denied, "unit idle"),
                    (missing, "unit idle"),
                    (filtered, "unit idle"),
                ],
            ),
            mock.patch.object(
                service.engine,
                "unit_for_leaf",
                side_effect=lambda _units, name: units[name],
            ),
            mock.patch.object(
                service.memory,
                "scope_counters",
                side_effect=lambda path: (
                    {"current_bytes": 300 if path == denied else 100}
                    if path != missing
                    else None
                ),
            ),
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(self.daemon, "authorize", side_effect=decisions),
            mock.patch.object(self.daemon, "log_would_stop") as would_stop,
            mock.patch.object(self.daemon, "auto_stop_path", return_value=True) as stop,
        ):
            result = self.daemon._guard_stop_step()

        self.assertEqual(result["performed"], 1)
        self.assertEqual(result["scopes"], ["app-allowed"])
        self.assertEqual(result["results"][0]["status"], "refused")
        self.assertEqual(result["results"][0]["scope"], "app-denied")
        would_stop.assert_called_once_with(
            "guard_would_stop", "app-denied", "unit idle"
        )
        stop.assert_called_once_with(
            allowed,
            "pressure guard: unit idle",
            False,
            authority=self.daemon.effective_authority["value"],
            trigger=authorization.GC_STOP,
        )

    def test_guard_stop_enforce_mode_records_success_and_kernel_refusal(self):
        path = self.cg.leaf("app-enforced", [4242])
        unit = {"unit": {"name": "app-enforced", "stop_when_unneeded": True}}
        decision = SimpleNamespace(
            verdict=authorization.ACT, reason="unit authority", authority="unit"
        )
        self.daemon.cfg["mode"] = "enforce"
        self.daemon.units = [unit]
        audit = {"owner": "unit:app-enforced"}
        common = (
            mock.patch.object(
                service.engine, "gc_candidates", return_value=[(path, "unit idle")]
            ),
            mock.patch.object(service.engine, "unit_for_leaf", return_value=unit),
            mock.patch.object(
                service.memory, "scope_counters", return_value={"current_bytes": 256}
            ),
            mock.patch.object(self.daemon, "_guard_pressure_high", return_value=True),
            mock.patch.object(self.daemon, "authorize", return_value=decision),
            mock.patch.object(
                self.daemon.store, "decision_context", return_value=nullcontext(audit)
            ),
        )
        with ExitStack() as stack:
            for patcher in common:
                stack.enter_context(patcher)
            stack.enter_context(
                mock.patch.object(
                    service.engine, "stop", return_value={"removed": True}
                )
            )
            note_stop = stack.enter_context(
                mock.patch.object(self.daemon, "note_stop", return_value=[])
            )
            stack.enter_context(
                mock.patch.object(self.daemon, "stopped_apps", return_value=[])
            )
            note_auto_stop = stack.enter_context(
                mock.patch.object(self.daemon, "note_auto_stop")
            )
            result = self.daemon._guard_stop_step()
        self.assertEqual(result["performed"], 1)
        self.assertEqual(result["scopes"], ["app-enforced"])
        note_stop.assert_called_once_with({"removed": True})
        note_auto_stop.assert_called_once()

        with ExitStack() as stack:
            for patcher in common:
                stack.enter_context(patcher)
            stack.enter_context(
                mock.patch.object(
                    service.engine,
                    "stop",
                    side_effect=service.engine.Refused("scope changed"),
                )
            )
            refused = self.daemon._guard_stop_step()
        self.assertEqual(refused["performed"], 0)
        self.assertEqual(refused["results"][0]["reason"], "scope changed")


class GuardDoctorTests(unittest.TestCase):
    def test_doctor_shows_external_handlers_and_warns_for_preferred_foreground(self):
        with tempfile.TemporaryDirectory() as root:
            proc_root = os.path.join(root, "proc")
            pid_root = os.path.join(proc_root, "800")
            os.makedirs(pid_root)
            Path(pid_root, "comm").write_text("earlyoom\n")
            Path(pid_root, "cmdline").write_bytes(
                b"\0".join(
                    (
                        b"/usr/bin/earlyoom",
                        b"-m",
                        b"8",
                        b"--prefer",
                        b"node",
                        b"",
                    )
                )
            )
            Path(proc_root, "801").mkdir()
            Path(proc_root, "801", "comm").write_text("systemd-oomd\n")
            Path(proc_root, "801", "cmdline").write_bytes(b"/usr/lib/systemd-oomd\0")
            Path(proc_root, "802").mkdir()
            Path(proc_root, "802", "comm").write_text("nohang\n")
            Path(proc_root, "802", "cmdline").write_bytes(
                b"/usr/bin/nohang\0--config\0/etc/nohang/nohang.conf\0--monitor\0"
            )
            Path(root, "etc/nohang").mkdir(parents=True)
            Path(root, "etc/nohang/nohang.conf").write_text(
                "psi_checking_enabled = True\n"
                "psi_metrics = full_avg10\n"
                "hard_threshold_min_mem = 2 %\n"
            )
            Path(root, "etc/systemd").mkdir(parents=True)
            Path(root, "etc/systemd/oomd.conf").write_text(
                "[OOM]\nDefaultMemoryPressureLimit=45%\n"
                "DefaultMemoryPressureDurationSec=15s\n"
            )
            fake_cg = FakeCg().__enter__()
            self.addCleanup(fake_cg.__exit__)
            scope_path = fake_cg.leaf("app-editor", [4242])
            Path(scope_path, "cgroup.procs").write_text("4242\n")
            Path(proc_root, "4242").mkdir()
            Path(proc_root, "4242", "comm").write_text("node\n")
            unit = {"unit": {"name": "app-editor", "qos_class": "foreground"}}

            report = doctor._oom_handler_check([unit], root, os.getuid())

        self.assertEqual(report["status"], "warn")
        self.assertIn("earlyoom pid 800: -m 8%", report["message"])
        self.assertIn("systemd-oomd pid 801: /etc/systemd/oomd.conf", report["message"])
        self.assertIn("DefaultMemoryPressureLimit=45%", report["message"])
        self.assertIn(
            "nohang pid 802: config=/etc/nohang/nohang.conf", report["message"]
        )
        self.assertIn("psi_metrics=full_avg10", report["message"])
        self.assertIn("foreground scope app-editor process node", report["message"])
        self.assertIn("never edits", report["fix"])
