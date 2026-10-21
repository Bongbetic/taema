"""Memory accounting, sampling, and CLI contract tests for ticket #41."""

import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema.cli import commands
from taema.core import memory
from taema.daemon import service
from tests.test_phase0 import FakeCg, make_cfg
from tests.test_phase1 import write
from tests.test_ipc_v2 import matches

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "cli" / "read-v1.json").read_text())


def write_scope(
    path, current=1000, *, peak=None, anon=600, file=300, swap=50, zswap=10
):
    write(path + "/memory.current", "%d\n" % current)
    write(
        path + "/memory.stat",
        "anon %d\nfile %d\ninactive_file %d\nshmem 20\n"
        % (anon, file, max(0, file - 40)),
    )
    if peak is not None:
        write(path + "/memory.peak", "%d\n" % peak)
    write(path + "/memory.swap.current", "%d\n" % swap)
    write(path + "/memory.zswap.current", "%d\n" % zswap)
    write(
        path + "/memory.pressure",
        "some avg10=2.50 avg60=1.25 avg300=0.50 total=12\n",
    )


class MemoryAccounting(unittest.TestCase):
    def test_host_and_scope_metrics_include_peak_fallback_and_feature_sources(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as temporary:
            proc = os.path.join(temporary, "proc")
            system = os.path.join(temporary, "system")
            write(
                proc + "/meminfo",
                "MemTotal: 4096 kB\nMemAvailable: 1024 kB\nSwapTotal: 2048 kB\nSwapFree: 512 kB\n",
            )
            write(
                proc + "/pressure/memory",
                "some avg10=3.25 avg60=1.00 avg300=0.50 total=9\n",
            )
            write(system + "/sys/kernel/debug/zswap/pool_total_size", "128\n")
            write(cg.base + "/memory.current", "5000\n")
            scope = cg.leaf("app-browser")
            write_scope(scope, current=4096, anon=3000, file=800, swap=128, zswap=32)

            report = memory.snapshot(
                base=cg.base,
                proc_root=proc,
                system_root=system,
                peak_cache={},
                now=123.0,
            )

        self.assertEqual(report["host"]["total_bytes"], 4 * 1024 * 1024)
        self.assertEqual(report["host"]["available_bytes"], 1024 * 1024)
        self.assertEqual(report["host"]["pressure_avg10"], 3.25)
        self.assertEqual(report["host"]["swap_used_bytes"], 1536 * 1024)
        self.assertEqual(report["host"]["zswap_bytes"], 128)
        row = report["scopes"][0]
        self.assertEqual(row["class"], "app")
        self.assertEqual(row["current_bytes"], 4096)
        self.assertEqual(row["peak_bytes"], 4096)
        self.assertEqual(row["peak_source"], "sampled")
        self.assertEqual(row["anon_bytes"], 3000)
        self.assertEqual(row["file_bytes"], 800)
        self.assertEqual(row["swap_bytes"], 128)
        self.assertEqual(row["zswap_bytes"], 32)
        self.assertEqual(row["reclaimable_bytes"], 760)
        self.assertEqual(row["psi_avg10"], 2.5)
        self.assertEqual(row["features"]["peak"], "sampled")

    def test_missing_files_are_unsupported_and_peak_uses_sampled_maximum(self):
        with FakeCg() as cg:
            scope = cg.leaf("scope-legacy")
            write(scope + "/memory.current", "1200\n")
            cache = {"scope-legacy": 2000}
            report = memory.snapshot(base=cg.base, peak_cache=cache)

        row = report["scopes"][0]
        self.assertEqual(row["peak_bytes"], 2000)
        self.assertEqual(row["peak_source"], "sampled")
        self.assertIsNone(row["anon_bytes"])
        self.assertIsNone(row["swap_bytes"])
        self.assertEqual(row["features"]["memory_stat"], "unsupported")
        self.assertEqual(row["features"]["pressure"], "unsupported")

    def test_disabled_mode_does_not_read_host_or_scope_memory(self):
        with mock.patch.dict(os.environ, {"TAEMA_MEM": "0"}):
            with mock.patch.object(
                memory.cgroup, "subdirs", side_effect=AssertionError
            ):
                report = memory.snapshot(
                    base="/missing", cfg={"mem": {"enabled": True}}
                )
        self.assertFalse(report["enabled"])
        self.assertIsNone(report["host"])
        self.assertEqual(report["scopes"], [])
        self.assertEqual(report["features"], {})

    def test_daemon_skips_all_memory_sampling_when_disabled(self):
        with FakeCg(), tempfile.TemporaryDirectory() as state:
            with mock.patch.dict(os.environ, {"TAEMA_MEM": "0"}):
                with (
                    mock.patch.object(
                        service.memory, "snapshot", side_effect=AssertionError
                    ),
                    mock.patch.object(
                        service.knowledge.Store,
                        "latest_memory_samples",
                        side_effect=AssertionError,
                    ),
                ):
                    daemon = service.Daemon(make_cfg(state))
                    self.assertFalse(daemon.mem_enabled)
                    self.assertEqual(daemon.memory_pass(now=1000), 0)

    def test_daemon_does_not_store_samples_when_accounting_is_unsupported(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            cg.leaf("app-no-accounting")
            daemon = service.Daemon(make_cfg(state))
            self.assertEqual(daemon.memory_pass(now=1000.0), 0)
            self.assertEqual(daemon.store.latest_memory_samples(), {})

    def test_change_sampling_uses_strict_five_percent_and_ten_minute_heartbeat(self):
        previous = {
            "ts": 100.0,
            "current_bytes": 1000,
            "peak_bytes": 1000,
            "anon_bytes": 600,
            "file_bytes": 300,
            "swap_bytes": 50,
            "zswap_bytes": 10,
            "psi_avg10": 2.0,
        }
        current = dict(previous)
        current["current_bytes"] = 1050
        self.assertFalse(memory.sample_due(previous, current, 101.0))
        current["current_bytes"] = 1051
        self.assertTrue(memory.sample_due(previous, current, 101.0))
        current = dict(previous)
        self.assertTrue(memory.sample_due(previous, current, 700.0))

    def test_retention_prunes_samples_and_rollups_even_when_no_scope_changed(self):
        with FakeCg(), tempfile.TemporaryDirectory() as state:
            daemon = service.Daemon(make_cfg(state))
            now = 1_800_000_000.0
            with daemon.store.db.connection() as connection:
                connection.execute(
                    "INSERT INTO mem_samples(scope_key, ts, current) VALUES (?, ?, ?)",
                    ("app-old", now - 8 * 24 * 60 * 60, 1024),
                )
                connection.execute(
                    "INSERT INTO mem_rollup(app, day) VALUES (?, ?)",
                    ("app-old", int(now // 86400) - 366),
                )
                connection.commit()

            self.assertEqual(daemon.memory_pass(now=now), 0)
            with daemon.store.db.connection() as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM mem_samples").fetchone()[
                        0
                    ],
                    0,
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM mem_rollup").fetchone()[0],
                    0,
                )

    def test_daemon_persists_only_changes_and_handles_a_disappearing_scope(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            path = cg.leaf("app-test")
            write_scope(path, current=1000)
            daemon = service.Daemon(make_cfg(state))

            self.assertEqual(daemon.memory_pass(now=1000.0), 1)
            self.assertEqual(daemon.memory_pass(now=1001.0), 0)
            write(path + "/memory.current", "1100\n")
            self.assertEqual(daemon.memory_pass(now=1002.0), 1)
            self.assertEqual(daemon.memory_pass(now=1602.0), 1)
            latest = daemon.store.latest_memory_samples()["app-test"]
            self.assertEqual(latest["current"], 1100)
            self.assertEqual(latest["peak"], 1100)
            with daemon.store.db.connection() as connection:
                rollup = connection.execute(
                    "SELECT current_p50, peak FROM mem_rollup WHERE app = 'app-test'"
                ).fetchone()
            self.assertEqual(tuple(rollup), (1100, 1100))

            import shutil

            shutil.rmtree(path)
            self.assertEqual(daemon.memory_pass(now=1603.0), 0)
            self.assertNotIn("app-test", daemon.memory_last_samples)
            self.assertNotIn("app-test", daemon.memory_peaks)

    def test_memory_commands_emit_schema_valid_json(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            scope = cg.leaf("app-json")
            write_scope(scope, current=2048)
            cfg = make_cfg(state)
            for argv, output_schema in (
                (["memory", "--json"], "taema.memory.v1"),
                (["memory", "top", "--json"], "taema.memory.v1"),
                (["memory", "pressure", "--json"], "taema.memory.v1"),
                (
                    ["memory", "watch", "--count", "1", "--json"],
                    "taema.memory-watch.v1",
                ),
            ):
                output = io.StringIO()
                with (
                    mock.patch.object(
                        commands, "_memory_config", return_value=(cfg, None)
                    ),
                    redirect_stdout(output),
                ):
                    result = commands.main(argv)
                value = json.loads(output.getvalue())
                self.assertEqual(result, 0)
                self.assertEqual(value["schema"], output_schema)
                self.assertTrue(matches(value, SCHEMA, SCHEMA))
                if output_schema == "taema.memory.v1":
                    self.assertEqual(value["scopes"][0]["current_bytes"], 2048)

    def test_two_hundred_scope_memory_pass_is_under_one_hundred_ms(self):
        with FakeCg() as cg, tempfile.TemporaryDirectory() as state:
            for index in range(200):
                path = cg.leaf("app-%03d" % index)
                write_scope(path, current=1024 + index)
            daemon = service.Daemon(make_cfg(state))

            started = time.perf_counter()
            sampled = daemon.memory_pass(now=1_800_000_000.0)
            elapsed = time.perf_counter() - started

        self.assertEqual(sampled, 200)
        self.assertLess(elapsed, 0.1, "200-scope memory pass took %.3f s" % elapsed)


if __name__ == "__main__":
    unittest.main()
