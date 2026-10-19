"""Resource-budget smoke test: repeated passes on a fake tree must not grow state."""

import os
import unittest
from unittest import mock

from taema.daemon import service as daemon
from taema.core import process as inspect
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_phase1 import write

N = 20


def size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0


class Budget(unittest.TestCase):
    def test_passes_do_not_grow_state(self):
        with FakeCg() as cg:
            proc = tmp()
            write(proc + "/loadavg", "0 0 0 1/10 99\n")
            cg.leaf("shared/idle-1", [7], cpu=1)
            cg.leaf("app-busy", [8])
            os.makedirs(cg.root + "/3")
            write(cg.root + "/3/cgroup.procs", "8\n")
            d = daemon.Daemon(make_cfg(tmp(), mode="observe"))
            d.units = [
                {"unit": {"name": "app-busy", "kind": "app"}, "match": {"comm": "x"}}
            ]
            with (
                mock.patch.object(inspect, "PROC", proc),
                mock.patch.object(
                    inspect,
                    "Snapshot",
                    return_value=type(
                        "S",
                        (),
                        {
                            "ok": True,
                            "unix": [],
                            "tcp": [],
                            "tcp_listen": [],
                            "by_inode": {},
                        },
                    )(),
                ),
                mock.patch.object(
                    inspect.ProcTable,
                    "scan",
                    return_value=inspect.ProcTable.from_ppid({7: 1, 8: 1}),
                ),
                mock.patch.object(daemon.engine.policy, "exe_key", return_value="k"),
            ):
                d.adopt_pass()
                d.gc_pass()
                before = (
                    len(d.owners),
                    len(d.idle_since),
                    len(d.store.sigs),
                    len(d.gc_usage),
                    size(d.store.log_path),
                )
                for _ in range(N):
                    d.adopt_pass()
                    d.gc_pass()
                after = (
                    len(d.owners),
                    len(d.idle_since),
                    len(d.store.sigs),
                    len(d.gc_usage),
                    size(d.store.log_path),
                )
            self.assertEqual(before, after)

    def test_idle_loop_sleeps_more_than_a_second(self):
        d = daemon.Daemon(make_cfg(tmp()))
        now = 1000.0
        d.last = {"adopt": now, "gc": now}
        self.assertGreater(d.next_timeout(now), 1.0)


if __name__ == "__main__":
    unittest.main()
