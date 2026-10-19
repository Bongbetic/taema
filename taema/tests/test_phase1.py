"""Phase 1 tests: one proc snapshot per pass, fork gate, lazy ss, deadline loop, empty leaves,
store bounds, log dedupe/rotation, direct cgroup moves."""

import json
import os
import select
import shutil
import time
import unittest
from unittest import mock

from taema.daemon import service as daemon
from taema.core import cgroup, process as inspect
from taema.governor import engine
from taema.store import knowledge
from taema.config import policy
from tests.test_phase0 import FakeCg, OkSnap, UID, make_cfg, tmp


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def stat_line(pid, ppid, state="S", pgrp=None, sid=None, tty=0, start=100):
    return "%d (c m)d) %s %d %d %d %d -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n" % (
        pid,
        state,
        ppid,
        pgrp or pid,
        sid or pid,
        tty,
        start,
    )


def fake_proc(rows, loadavg=None):
    root = tmp()
    for pid, args in rows.items():
        write(
            "%s/%d/stat" % (root, pid),
            stat_line(pid, *args[:1], **args[1] if len(args) > 1 else {}),
        )
    if loadavg:
        write(root + "/loadavg", loadavg)
    return root


# ---- 1. ProcTable ------------------------------------------------------------------------------


class ProcTableTests(unittest.TestCase):
    def test_fields_and_zombie_skip(self):
        root = fake_proc(
            {
                10: (1, {"pgrp": 10, "sid": 5, "tty": 34816, "start": 777}),
                11: (10,),
                12: (10, {"state": "Z"}),
            }
        )
        with mock.patch.object(inspect, "PROC", root):
            pt = inspect.ProcTable.scan()
            self.assertEqual(sorted(pt.rows), [10, 11])
            r = pt.rows[10]
            self.assertEqual(
                (r.ppid, r.pgrp, r.sid, r.tty, r.start, r.state),
                (1, 10, 5, 34816, 777, "S"),
            )
            self.assertEqual(sorted(pt.descendants([10])), [10, 11])
            self.assertEqual(pt.ancestors(11), [10, 1])
            self.assertEqual(
                inspect.ppid_map(), {10: 1, 11: 10}
            )  # compatibility wrapper

    def test_helpers_accept_table_or_map(self):
        pt = inspect.ProcTable.from_ppid({2: 1, 3: 2})
        self.assertEqual(sorted(inspect.descendants([2], pt)), [2, 3])
        self.assertEqual(sorted(inspect.descendants([2], {2: 1, 3: 2})), [2, 3])
        self.assertEqual(inspect.ancestors(3, pt), [2, 1])

    def test_one_scan_per_adopt_pass(self):
        cg = FakeCg()
        with cg:
            d = daemon.Daemon(make_cfg(tmp()))
            d.units = [
                {
                    "unit": {"name": "app-x", "kind": "app"},
                    "match": {"comm": "x"},
                    "children": [{"name": "s", "comm": "y"}],
                }
            ]
            with (
                mock.patch.object(
                    inspect.ProcTable,
                    "scan",
                    return_value=inspect.ProcTable.from_ppid({}),
                ) as sc,
                mock.patch.object(inspect, "ppid_map") as old,
            ):
                d.adopt_pass()
            self.assertEqual(sc.call_count, 1)
            old.assert_not_called()


# ---- 2. fork gate -------------------------------------------------------------------------------


class ForkGate(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.root = tmp()
        write(self.root + "/loadavg", "0.1 0.1 0.1 1/100 500\n")
        p = mock.patch.object(inspect, "PROC", self.root)
        p.start()
        self.addCleanup(p.stop)
        os.makedirs(self.cg.root + "/2")
        write(self.cg.root + "/2/cgroup.procs", "40\n")
        self.d = daemon.Daemon(make_cfg(tmp()))
        self.d.units = [
            {"unit": {"name": "app-x", "kind": "app"}, "match": {"comm": "x"}}
        ]

    def passes(self, n):
        with (
            mock.patch.object(daemon.engine, "adopt_plan", return_value=[]) as ap,
            mock.patch.object(
                inspect.ProcTable, "scan", return_value=inspect.ProcTable.from_ppid({})
            ),
        ):
            for _ in range(n):
                self.d.adopt_pass()
        return ap.call_count

    def test_unchanged_passes_skipped_every_fifth_runs(self):
        self.assertEqual(self.passes(10), 2)  # runs on #1 and #6

    def test_new_pid_or_session_member_runs(self):
        self.assertEqual(self.passes(3), 1)
        write(self.root + "/loadavg", "0.1 0.1 0.1 1/100 501\n")
        self.assertEqual(self.passes(1), 1)
        self.assertEqual(self.passes(1), 0)
        write(self.cg.root + "/2/cgroup.procs", "40\n41\n")
        self.assertEqual(self.passes(1), 1)

    def test_unreadable_loadavg_never_skips(self):
        os.unlink(self.root + "/loadavg")
        self.assertEqual(self.passes(4), 4)


# ---- 3. lazy / merged ss ----------------------------------------------------------------------------


class LazySs(unittest.TestCase):
    def test_snapshot_runs_two_ss_calls(self):
        calls = []
        tcp = (
            'LISTEN 0 4096 127.0.0.1:80 0.0.0.0:* users:(("a",pid=5,fd=3))\n'
            'ESTAB 0 0 127.0.0.1:80 127.0.0.1:5555 users:(("a",pid=5,fd=4))\n'
        )
        with mock.patch.object(
            inspect,
            "_ss",
            side_effect=lambda *a: calls.append(a) or (tcp if "-tanp" in a else ""),
        ):
            s = inspect.Snapshot()
        self.assertEqual(calls, [("-xapn",), ("-tanp",)])
        self.assertEqual([r["state"] for r in s.tcp_listen], ["LISTEN"])
        self.assertEqual([r["state"] for r in s.tcp], ["ESTAB"])
        self.assertTrue(s.ok)

    def test_all_protected_builds_no_snapshot(self):
        store = knowledge.Store(tmp(), {})
        with (
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[5, 6]),
            mock.patch.object(engine.policy, "protected_reason", return_value="x"),
            mock.patch.object(engine.policy, "exe_key", return_value="k"),
            mock.patch.object(engine.inspect, "comm", return_value="c"),
            mock.patch.object(engine.inspect, "Snapshot") as sn,
        ):
            out = engine.plan_stop("/x", {}, store, pt=inspect.ProcTable.from_ppid({}))
        sn.assert_not_called()
        self.assertTrue(all(d["action"] == "skip" for d in out))

    def test_one_snapshot_across_passes(self):
        store = knowledge.Store(tmp(), {})
        lazy = inspect.LazySnapshot()
        with (
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[5]),
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
            mock.patch.object(engine.policy, "exe_key", return_value="k"),
            mock.patch.object(engine.inspect, "comm", return_value="c"),
            mock.patch.object(engine.inspect, "edges", return_value={}),
            mock.patch.object(engine.inspect, "Snapshot", return_value=OkSnap()) as sn,
        ):
            for _ in range(3):
                engine.plan_stop(
                    "/x", {}, store, pt=inspect.ProcTable.from_ppid({5: 1}), snap=lazy
                )
        self.assertEqual(sn.call_count, 1)

    def test_gc_builds_snapshot_only_for_edge_checks(self):
        with FakeCg() as cg:
            cg.leaf("shared/empty-1", [])
            cfg = make_cfg(tmp())
            store = knowledge.Store(tmp(), {})
            with mock.patch.object(
                engine.inspect, "Snapshot", return_value=OkSnap()
            ) as sn:
                out = engine.gc_candidates(cfg, [], store, {})
            self.assertEqual([w for _p, w in out], ["empty"])
            sn.assert_not_called()
            cg.leaf("shared/a-2", [7], cpu=1)
            cg.leaf("shared/b-3", [8], cpu=1)
            with (
                mock.patch.object(
                    engine.inspect, "Snapshot", return_value=OkSnap()
                ) as sn,
                mock.patch.object(engine.inspect, "edges", return_value={}),
                mock.patch.object(
                    engine.inspect.ProcTable,
                    "scan",
                    return_value=inspect.ProcTable.from_ppid({}),
                ),
                mock.patch.object(engine.policy, "exe_key", return_value="x"),
            ):
                engine.gc_candidates(cfg, [], store, {})
            self.assertEqual(sn.call_count, 1)


# ---- 4. deadline loop and session state ------------------------------------------------------------


class DeadlineLoop(unittest.TestCase):
    def test_timeout_follows_next_timer(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.last = {"adopt": 100.0, "gc": 100.0}
        self.assertAlmostEqual(d.next_timeout(now=101.0), 14.0)
        d.last["adopt"] = 110.0
        self.assertAlmostEqual(d.next_timeout(now=124.0), 1.0)
        self.assertEqual(d.next_timeout(now=500.0), 0.0)  # overdue
        d.iv_adopt = d.iv_gc = 10**6
        self.assertEqual(d.next_timeout(now=101.0), daemon.MAX_SLEEP)

    def test_session_state_file(self):
        root = tmp()
        write("%s/%d" % (root, UID), "NAME=x\nSTATE=active\nSESSIONS=3 4\nREALTIME=1\n")
        with mock.patch.object(policy, "USERS_DIR", root):
            self.assertEqual(policy.session_state(), ("active", ["3", "4"]))
            d = daemon.Daemon(make_cfg(tmp()))
            self.assertFalse(d.session_ended())
            self.assertTrue(d.session_seen)
            write("%s/%d" % (root, UID), "STATE=offline\nSESSIONS=\n")
            with mock.patch.object(
                policy, "session_cgroups", side_effect=AssertionError("scanned")
            ):
                self.assertTrue(d.session_ended())
        with mock.patch.object(policy, "USERS_DIR", tmp()):
            self.assertIsNone(policy.session_state())

    def test_session_check_runs_at_adopt_interval(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.last["gc"] = time.time()
        with (
            mock.patch.object(d, "session_ended", return_value=False) as se,
            mock.patch.object(d, "check_socket"),
            mock.patch.object(d, "adopt_pass"),
        ):
            d.tick()
            d.tick()
        self.assertEqual(se.call_count, 1)

    def test_wait_poll_step(self):
        self.assertEqual(engine.POLL_STEP, 0.05)


# ---- 5. empty leaves ------------------------------------------------------------------------------


class EmptyLeaves(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        # cgroupfs control files vanish with rmdir; a fake tree needs rmtree to do the same
        p = mock.patch.object(engine.cgroup, "rmdir_tree", side_effect=shutil.rmtree)
        p.start()
        self.addCleanup(p.stop)
        for rel in ("app-gone", "scope-gone", "shared/gone-1", "manager", "other"):
            self.cg.leaf(rel, [])
        self.cg.leaf("app-busy", [5])
        self.cg.leaf("app-parent/child", [6])
        self.cg.leaf("app-hollow/child", [])

    def daemon(self, mode):
        d = daemon.Daemon(make_cfg(tmp(), mode=mode))
        self.addCleanup(lambda: [os.close(f) for f in list(d.owners)])
        return d

    def exists(self, rel):
        return os.path.isdir("%s/%s" % (self.cg.base, rel))

    def test_candidates_include_empty_never_manager(self):
        out = dict(
            (cgroup.rel(p), w)
            for p, w in engine.gc_candidates(
                make_cfg(tmp()), [], knowledge.Store(tmp(), {}), {}
            )
        )
        self.assertEqual(
            sorted(out), ["app-gone", "app-hollow", "scope-gone", "shared/gone-1"]
        )
        self.assertTrue(all(w == "empty" for w in out.values()))

    def test_gc_pass_fallback_removes_on_second_pass(self):
        d = self.daemon("adopt")
        d.gc_pass()
        for rel in ("app-gone", "scope-gone", "shared/gone-1", "app-hollow"):
            self.assertTrue(self.exists(rel), rel)  # first sighting: kept
        d.gc_pass()
        for rel in ("app-gone", "scope-gone", "shared/gone-1", "app-hollow"):
            self.assertFalse(self.exists(rel), rel)
        for rel in ("manager", "other", "app-busy", "app-parent/child"):
            self.assertTrue(self.exists(rel), rel)
        with open(d.store.log_path) as f:
            self.assertIn("gc_removed_empty", f.read())

    def test_leaf_that_gets_a_process_is_kept(self):
        d = self.daemon("adopt")
        d.gc_pass()
        self.cg.set_procs("app-gone", [9])
        d.gc_pass()
        self.assertTrue(self.exists("app-gone"))

    def test_observe_mode_and_dry_run_remove_nothing(self):
        d = self.daemon("observe")
        d.gc_pass()
        d.gc_pass()
        self.assertTrue(self.exists("app-gone"))
        d = self.daemon("enforce")
        d.gc_pass(dry_run=True)
        d.gc_pass(dry_run=True)
        self.assertTrue(self.exists("app-gone"))

    def test_unwatchable_leaf_falls_back(self):
        d = self.daemon("adopt")
        d.gc_pass()
        self.assertIn("app-gone", d.leaf_nowatch)  # no cgroup.events in the fake tree
        self.assertEqual(d.leaf_watch, {})

    def test_events_handler_removes_on_populated_0(self):
        d = self.daemon("adopt")
        ev = self.cg.base + "/app-gone/cgroup.events"
        write(ev, "populated 0\nfrozen 0\n")
        f = open(ev)
        ep = mock.Mock()
        ep.poll.return_value = [(f.fileno(), select.EPOLLPRI)]
        d.leaf_ep = ep
        d.leaf_watch[f.fileno()] = ("app-gone", f)
        d.on_leaf_events()
        self.assertFalse(self.exists("app-gone"))
        self.assertEqual(d.leaf_watch, {})

    def test_events_handler_keeps_populated_leaf(self):
        d = self.daemon("adopt")
        ev = self.cg.base + "/app-busy/cgroup.events"
        write(ev, "populated 1\n")
        f = open(ev)
        d.leaf_ep = mock.Mock()
        d.leaf_ep.poll.return_value = [(f.fileno(), select.EPOLLPRI)]
        d.leaf_watch[f.fileno()] = ("app-busy", f)
        self.addCleanup(f.close)
        d.on_leaf_events()
        self.assertTrue(self.exists("app-busy"))
        self.assertIn(f.fileno(), d.leaf_watch)

    def test_regular_file_cannot_be_epolled_falls_back(self):
        """cgroupfs files accept EPOLLPRI; a regular file does not (EPERM) and must fall back."""
        d = self.daemon("adopt")
        write(self.cg.base + "/app-gone/cgroup.events", "populated 0\n")
        d.sync_leaf_watches()
        self.assertIn("app-gone", d.leaf_nowatch)


# ---- 6. store bounds ------------------------------------------------------------------------------------


class StoreBounds(unittest.TestCase):
    def setUp(self):
        self.t = [1e7]
        self.store = knowledge.Store(tmp(), {}, now=lambda: self.t[0])

    def test_sqlite_state_and_save_interval(self):
        self.store.bump("a", "seen")
        self.assertTrue(self.store.save_if_dirty(300))
        self.assertEqual(
            knowledge.Store(self.store.dir, {}, now=lambda: self.t[0]).peek("a")[
                "seen"
            ],
            1,
        )
        self.store.bump("a", "seen")
        self.t[0] += 100
        self.assertFalse(self.store.save_if_dirty(300))
        self.assertTrue(self.store.dirty)
        self.t[0] += 250
        self.assertTrue(self.store.save_if_dirty(300))

    def test_daemon_commits_routine_state_once_at_end_of_tick(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.store.bump("a", "seen")
        d.last = {"adopt": time.time(), "gc": time.time()}
        with (
            mock.patch.object(d, "check_socket"),
            mock.patch.object(d, "run_deadlines"),
            mock.patch.object(
                d.store.db, "save_state", wraps=d.store.db.save_state
            ) as save,
        ):
            d.tick()
        save.assert_called_once()

    def test_gc_command_defers_pass_writes_then_commits_once(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.store.bump("a", "seen")
        with (
            mock.patch.object(d, "gc_pass", return_value=["candidate"]),
            mock.patch.object(
                d.store.db, "save_state", wraps=d.store.db.save_state
            ) as save,
        ):
            self.assertEqual(
                d.handle({"cmd": "gc", "dry_run": True}),
                {"candidates": ["candidate"]},
            )
        save.assert_called_once()
        self.assertFalse(d.store.defer_writes)

    def test_explicit_feedback_saves_at_once(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.store.save()
        d.store.last_save = time.time()
        d.store.defer_writes = True
        self.assertEqual(
            d.handle({"cmd": "feedback", "op": "keep", "key": "k"}), {"ok": True}
        )
        self.assertFalse(d.store.dirty)
        reopened = knowledge.Store(d.store.dir, {}, read_only=True)
        self.assertEqual(reopened.peek("k")["user_keep"], 3.0)

    def test_all_zero_records_dropped(self):
        self.store.rec("zero")
        self.store.bump("live", "seen")
        self.store.enforce_caps()
        self.assertEqual(sorted(self.store.data["exes"]), ["live"])

    def test_cap_evicts_stale_then_lowest_weight(self):
        for i in range(knowledge.MAX_EXES):
            self.store.bump("k%d" % i, "seen", 1.0 + i)
        self.store.data["exes"]["k511"]["last_seen"] = (
            self.t[0] - 91 * 86400
        )  # stale but heaviest
        self.store.bump("new", "seen", 100.0)
        self.store.data["exes"]["new"]["last_seen"] = self.t[0]
        self.store.enforce_caps()
        exes = self.store.data["exes"]
        self.assertEqual(len(exes), knowledge.MAX_EXES)
        self.assertNotIn("k511", exes)
        self.assertIn("new", exes)
        self.bump_more()

    def bump_more(self):
        self.store.bump("newer", "seen", 100.0)
        self.store.enforce_caps()
        self.assertEqual(len(self.store.data["exes"]), knowledge.MAX_EXES)
        self.assertNotIn("k0", self.store.data["exes"])  # lowest weight went

    def test_gc_pass_decays_and_prunes_idle(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.store.now = lambda: self.t[0]
        d.store.data["last_decay"] = self.t[0]
        d.store.bump("a", "seen", 10.0)
        self.t[0] += 14 * 86400
        d.idle_since["shared/gone-1"] = 5.0
        with FakeCg():
            d.gc_pass()
        self.assertAlmostEqual(d.store.peek("a")["seen"], 10.0 * 0.9**2)
        self.assertEqual(d.idle_since, {})

    def test_owner_watch_cap(self):
        d = daemon.Daemon(make_cfg(tmp()))
        d.owners = {i: ("l%d" % i, 1, 1) for i in range(daemon.MAX_OWNERS)}
        self.assertFalse(d.watch_owner("scope-x", os.getpid()))
        self.assertEqual(len(d.owners), daemon.MAX_OWNERS)


# ---- 7. decisions.log -----------------------------------------------------------------------------------


class DecisionLog(unittest.TestCase):
    def test_adopt_would_only_on_change(self):
        store = knowledge.Store(tmp(), {})
        cfg = make_cfg(tmp())

        def ops(pids):
            return [
                {"op": "move", "scope": "app-x", "unit": "app-x", "pids": list(pids)}
            ]

        with mock.patch.object(engine.policy, "protected_reason", return_value=None):
            for pids in ([1, 2], [2, 1], [1, 2], [1, 2, 3], [1, 2, 3]):
                engine.run_ops(cfg, store, ops(pids), False)
            engine.run_ops(cfg, store, [], False)  # scope vanished: signature forgotten
            engine.run_ops(cfg, store, ops([1, 2, 3]), False)
        with open(store.log_path) as f:
            self.assertEqual(f.read().count("adopt_would"), 3)

    def test_rotates_at_1mib_keeping_one(self):
        store = knowledge.Store(tmp(), {})
        with open(store.log_path, "w") as f:
            f.write("x" * knowledge.LOG_MAX)
        store.log(event="after")
        with open(store.log_path + ".1") as f:
            self.assertEqual(len(f.read()), knowledge.LOG_MAX)
        with open(store.log_path) as f:
            self.assertEqual(json.loads(f.read())["event"], "after")


# ---- 8. direct moves ------------------------------------------------------------------------------------


class DirectMoves(unittest.TestCase):
    def run_it(self, where, op="move"):
        with FakeCg():
            store = knowledge.Store(tmp(), {})
            o = {
                "op": op,
                "scope": "app-x",
                "unit": "app-x",
                "pids": [10, 11],
                "root": 10,
            }
            with (
                mock.patch.object(engine.policy, "protected_reason", return_value=None),
                mock.patch.object(
                    engine.cgroup, "proc_cgroup", side_effect=lambda p: where[p]
                ),
                mock.patch.object(engine.cgroup, "move", return_value=True) as mv,
                mock.patch.object(engine.inspect, "descendants", return_value=[]),
                mock.patch.object(engine, "helper_move") as hm,
            ):
                engine.run_ops(make_cfg(tmp()), store, [o], True)
        return mv, hm

    def test_inside_user_moves_without_sudo(self):
        inside = "/user/%d/app-y" % UID
        mv, hm = self.run_it({10: inside, 11: inside})
        hm.assert_not_called()
        self.assertEqual(sorted(c.args[0] for c in mv.call_args_list), [10, 11])

    def test_session_pid_uses_helper(self):
        mv, hm = self.run_it({10: "/2", 11: "/user/%d/app-y" % UID})
        hm.assert_called_once()
        self.assertEqual(hm.call_args[0][2], [10])
        self.assertEqual([c.args[0] for c in mv.call_args_list], [11])

    def test_unknown_cgroup_uses_helper(self):
        mv, hm = self.run_it({10: None, 11: None})
        self.assertEqual(hm.call_args[0][2], [10, 11])
        mv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
