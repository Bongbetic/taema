"""Mode and lifecycle tests: app-root adoption, pair authority, auto stops, leftover leaves, logout,
the attach socket command and status. Fake /proc and cgroup trees; no real signal is ever sent."""

import argparse
import io
import json
import os
import sys
import time
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema.daemon import service as daemon
import taema.cli.commands as cli
from taema.core import cgroup, process as inspect
from taema.governor import engine
from taema.store import knowledge
from taema.config import policy
from taema.core.lineage import HZ, Lineage
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_phase2 import DAY, ProcCase

UID = os.getuid()
GOOD = {"edges": [], "protected": None, "ptmx": False, "cpu": 0.2, "origin": "npm"}


def store(seeds=None, clock=None):
    return knowledge.Store(tmp(), seeds or {}, now=clock or time.time)


def mi(**kw):
    return dict(GOOD, **kw)


# ---- 1. authority: auto_stop_ok ---------------------------------------------------------------


class Authority(unittest.TestCase):
    def silent_store(self, age_days=10):
        """Store with silent stop evidence for npm>vite: 8 kills on 4 days, first seen 2 days ago."""
        t = [1000 * DAY]
        s = store(clock=lambda: t[0])
        s.data["created"] = t[0] - age_days * DAY
        for d in range(4):
            for _ in range(2):
                s.observe_kill_inferred("npm", "vite", day=d)
        s.data["pairs"][s.pkey("npm", "vite")]["first_seen"] = t[0] - age_days * DAY
        return s

    def test_explicit_stop_acts(self):
        s = store()
        s.answer("npm", "vite", "stop")
        self.assertTrue(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        self.assertTrue(s.pair_explicit("npm", "vite"))

    def test_ask_keep_standalone_never_act(self):
        s = store()
        self.assertFalse(
            engine.auto_stop_ok(s, "npm", "vite", mi())[0]
        )  # no evidence: ask
        s.answer("npm", "vite", "keep")
        self.assertFalse(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        s.answer("npm", "tool", "standalone")
        self.assertFalse(engine.auto_stop_ok(s, "npm", "tool", mi())[0])
        self.assertFalse(engine.auto_stop_ok(s, "", "vite", mi())[0])

    def test_silent_needs_thresholds_and_burn_in(self):
        s = self.silent_store(age_days=10)
        self.assertEqual(s.pair_decision("npm", "vite")[0], "stop")
        self.assertTrue(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        self.assertFalse(s.pair_explicit("npm", "vite"))
        young = self.silent_store(
            age_days=1
        )  # store younger than 7 days and < 20 closes
        self.assertEqual(young.pair_decision("npm", "vite")[0], "ask")
        self.assertFalse(engine.auto_stop_ok(young, "npm", "vite", mi())[0])
        few = store()
        few.observe_kill_inferred("npm", "vite", day=1)
        self.assertFalse(engine.auto_stop_ok(few, "npm", "vite", mi())[0])

    def test_members_that_must_stay(self):
        s = store(seeds={"persist": ["tmux"], "share": ["adb"]})
        for k in ("vite", "tmux", "adb"):
            s.answer("npm", k, "stop")
        ok = lambda k="vite", **kw: engine.auto_stop_ok(s, "npm", k, mi(**kw))
        self.assertTrue(ok()[0])
        self.assertFalse(ok(cpu=5.0)[0])  # busier than 1 %
        self.assertFalse(ok(cpu=None)[0])  # unknown keeps
        self.assertFalse(ok(edges=[{"kind": "unix_server"}])[0])
        self.assertFalse(ok(edges=None)[0])
        self.assertFalse(ok(protected="protected comm niri")[0])
        self.assertFalse(ok(ptmx=True)[0])
        self.assertFalse(ok(origin="")[0])
        self.assertFalse(ok("tmux")[0])  # persist seed, even answered stop
        self.assertTrue(ok("adb")[0])  # share seed alone may stop ...
        s.apply_op("keep", "adb")
        self.assertFalse(ok("adb")[0])  # ... not once the user keeps it

    def test_regret_suspends_the_pair(self):
        s = store()
        s.answer("npm", "vite", "stop")
        s.auto_stopped("npm", "vite")
        self.assertTrue(s.regret("npm", "vite"))
        self.assertEqual(s.pair_decision("npm", "vite")[0], "ask")
        self.assertFalse(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        self.assertFalse(s.regret("npm", "vite"))  # only once per auto stop

    def test_invalid_owner_pair_never_authorizes_a_stop(self):
        """The reference machine's explicit MainThread > sh/sort/head answer stays inert."""
        s = store()
        for k in ("sh", "sort", "head"):
            s.data["pairs"][s.pkey("MainThread", k)] = {
                "first_seen": 1000.0,
                "ex_stop": knowledge.W_ANSWER,
                "ex_last": "stop",
            }
            self.assertEqual(s.pair_decision("MainThread", k)[0], "invalid")
            self.assertFalse(s.pair_explicit("MainThread", k))
            self.assertFalse(engine.auto_stop_ok(s, "MainThread", k, mi())[0])
            self.assertFalse(
                engine.auto_stop_ok(s, "MainThread", k, dict(mi(cpu=None)))[0]
            )

    def test_grace_bounds(self):
        s = store()
        self.assertEqual(engine.auto_grace(s, {"x"}), 5.0)
        for ms in (40000, 41000, 42000):
            s.add_term_ms("slow", ms)
        self.assertEqual(engine.auto_grace(s, {"slow"}), 30.0)
        for ms in (7000, 7000, 7000):
            s.add_term_ms("mid", ms)
        self.assertAlmostEqual(engine.auto_grace(s, {"mid"}), 10.5)


# ---- 2. engine.stop allow_sigkill -------------------------------------------------------------


class SigkillRule(unittest.TestCase):
    def run_stop(self, allow):
        sent = []
        plan = [
            {
                "pid": 5,
                "comm": "x",
                "key": "x",
                "edges": [],
                "action": "kill",
                "why": "t",
            }
        ]
        with (
            mock.patch.object(engine, "plan_stop", return_value=plan),
            mock.patch.object(engine, "self_guard"),
            mock.patch.object(
                engine.inspect.ProcTable, "scan", return_value=inspect.ProcTable()
            ),
            mock.patch.object(
                engine,
                "_signal_all",
                side_effect=lambda p, pids, sig, cfg: sent.append(sig) or [],
            ),
            mock.patch.object(engine, "_wait_each", return_value={}),
            mock.patch.object(engine.cgroup, "rmdir_tree", side_effect=OSError("busy")),
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[5]),
        ):
            rep = engine.stop(
                "/x/user/1/y", {"timers": {}}, store(), timeout=1, allow_sigkill=allow
            )
        return sent, rep

    def test_sigkill_only_when_allowed(self):
        import signal

        sent, rep = self.run_stop(False)
        self.assertEqual(sent, [signal.SIGTERM])  # one pass, no SIGKILL
        self.assertEqual(rep["unkilled"], [5])
        sent, _ = self.run_stop(True)
        self.assertIn(signal.SIGKILL, sent)

    def test_vetoed_app_is_kept_before_any_stop_signal(self):
        s = store()
        s.add_veto("app", "firefox")
        with (
            mock.patch.object(engine, "self_guard"),
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[42]),
            mock.patch.object(engine.inspect, "starttime", return_value=1234),
            mock.patch.object(engine.policy, "app_key", return_value="firefox"),
            mock.patch.object(engine.policy, "app_key", return_value="firefox"),
            mock.patch.object(engine, "_signal_all") as signal_all,
        ):
            with self.assertRaises(engine.Vetoed):
                engine.stop("/x/user/1/app-firefox", {"timers": {}}, s)
        signal_all.assert_not_called()
        with open(s.log_path) as f:
            events = [json.loads(line)["event"] for line in f]
        self.assertIn("vetoed", events)


# ---- 3. auto adoption of app roots ------------------------------------------------------------


class AutoAdopt(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.session = self.cg.root + "/2"
        os.makedirs(self.session)
        self.cfg = make_cfg(
            tmp(), mode="auto", protected={"comm": ["niri*", "niriapp"]}
        )
        self.cfg["paths"]["session_cgroup"] = self.session
        self.fp.add(
            100, 1, comm="niri", sid=100, born=100.0
        )  # compositor: session leader, protected
        self.pids = []
        self.lin = Lineage(self.cfg)

    def add(self, pid, ppid=100, **kw):
        self.fp.add(pid, ppid, **kw)
        self.pids.append(pid)

    def plan(self, lin=None, cap=engine.AUTO_CAP, units=()):
        lin = lin or self.lin
        with open(self.session + "/cgroup.procs", "w") as f:
            f.write("".join("%d\n" % p for p in self.pids))
        lin.observe(self.fp.table(), now=self.fp.up, uptime=self.fp.up)
        return engine.auto_adopt_plan(
            self.cfg, list(units), self.fp.table(), lin, store(), cap=cap
        )

    def test_root_and_descendants_get_one_scope(self):
        self.add(200, comm="firefox")
        self.add(201, 200, comm="web")
        ops = self.plan()
        self.assertEqual(len(ops), 1)
        self.assertRegex(ops[0]["scope"], r"^app-firefox-[0-9a-f]{6}$")
        self.assertEqual(ops[0]["pids"], [200, 201])
        self.assertTrue(cgroup.valid_rel(ops[0]["scope"]))
        self.assertEqual(
            ops[0]["scope"], self.plan()[0]["scope"]
        )  # stable across passes

    def test_skips(self):
        self.add(210, comm="leader", sid=210)  # session leader
        self.add(220, comm="niriapp")  # protected
        self.add(230, comm="young", born=self.fp.up - 2)  # younger than 5 s
        self.add(240, comm="host", fds=("/dev/ptmx",))  # pty host
        self.add(250, comm="viewer", tty=34816)  # on a tty: a terminal job
        self.fp.add(260, 1, comm="bash", sid=260, tty=34816, born=1000.0)
        self.pids.append(260)
        self.add(261, 260, comm="server")  # child of an interactive shell
        self.add(270, comm="tagged", env={"TAEMA_JOB": "260.1"})  # carries a job tag
        self.add(280, comm="okapp")
        ops = self.plan()
        self.assertEqual([o["scope"].split("-")[1] for o in ops], ["okapp"])

    def test_already_adopted_root_is_not_in_session(self):
        self.add(200, comm="firefox")
        self.assertEqual(len(self.plan()), 1)
        self.pids.remove(200)
        self.assertEqual(self.plan(), [])

    def test_explicit_unit_wins(self):
        self.add(200, comm="firefox", exe="/usr/lib/firefox/firefox")
        unit = {
            "unit": {"name": "ff", "kind": "app"},
            "match": {"exe": "/usr/lib/firefox/firefox"},
        }
        self.assertEqual(self.plan(units=[unit]), [])
        self.assertEqual(len(self.plan()), 1)

    def test_cap(self):
        for i in range(70):
            self.add(300 + i, comm="app%d" % i)
        self.assertEqual(len(self.plan()), engine.AUTO_CAP)
        self.assertEqual(len(self.plan(cap=5)), 5)

    def test_daemon_runs_ops_through_helper(self):
        d = daemon.Daemon(self.cfg)
        self.add(200, comm="firefox")
        self.add(201, 200, comm="web")
        pt = self.fp.table()
        with open(self.session + "/cgroup.procs", "w") as f:
            f.write("200\n201\n")
        d.lineage.observe(pt, now=self.fp.up, uptime=self.fp.up)
        with (
            mock.patch.object(engine, "helper_move") as hm,
            mock.patch.object(cgroup, "proc_cgroup", return_value="/2"),
        ):
            d.auto_adopt(pt)
        self.assertEqual(hm.call_args[0][2], [200, 201])
        self.assertEqual(len(d.auto_scopes), 1)
        self.assertEqual(d.auto_status()["auto_adopted_scopes"], 1)

    def test_adopt_and_enforce_modes_scope_app_roots(self):
        self.add(200, comm="firefox")
        self.add(201, 200, comm="web")
        with open(self.session + "/cgroup.procs", "w") as f:
            f.write("200\n201\n")
        for mode in ("adopt", "enforce"):
            cfg = make_cfg(tmp(), mode=mode, protected={"comm": ["niri*"]})
            cfg["paths"]["session_cgroup"] = self.session
            d = daemon.Daemon(cfg)
            with (
                mock.patch.object(engine, "helper_move"),
                mock.patch.object(cgroup, "proc_cgroup", return_value="/2"),
            ):
                d.adopt_pass()
            self.assertEqual(d.auto_status()["auto_adopted_scopes"], 1, mode)

    def test_observe_logs_each_unchanged_would_adopt_once_without_moving(self):
        self.cfg["mode"] = "observe"
        self.add(200, comm="firefox")
        self.add(201, 200, comm="web")
        self.add(300, comm="unitapp")
        with open(self.session + "/cgroup.procs", "w") as f:
            f.write("200\n201\n300\n")
        d = daemon.Daemon(self.cfg)
        d.units = [
            {"unit": {"name": "known-app", "kind": "app"}, "match": {"comm": "unitapp"}}
        ]
        with (
            mock.patch.object(engine, "helper_move") as hm,
            mock.patch.object(cgroup, "move") as mv,
        ):
            d.adopt_pass()
            d.adopt_pass()
        hm.assert_not_called()
        mv.assert_not_called()
        self.assertEqual(d.auto_scopes, set())
        self.assertFalse(
            any(
                os.path.basename(path).startswith("app-")
                for path in os.listdir(self.cg.base)
            )
        )
        events = []
        if os.path.exists(d.store.log_path):
            with open(d.store.log_path) as f:
                events = [json.loads(line)["event"] for line in f]
        self.assertEqual(events.count("adopt_would"), 2)


# ---- 4. job survivors, GUI closes, regret, standalone -----------------------------------------


class AutoCase(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.rt = tmp()
        self.cgmap, self.edges = {}, {}
        for p in (
            mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.rt}),
            mock.patch.object(
                cgroup,
                "proc_cgroup",
                side_effect=lambda p: self.cgmap.get(p, "/user/%d/app-host" % UID),
            ),
            mock.patch.object(
                inspect, "Snapshot", return_value=types.SimpleNamespace(ok=True)
            ),
            mock.patch.object(
                inspect,
                "edges",
                side_effect=lambda m, s=None, pids_info=None: self.edges,
            ),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.d = daemon.Daemon(
            make_cfg(
                tmp(),
                mode="auto",
                seeds={"persist": ["gpg-agent"]},
                protected={"comm": ["niri*"]},
            )
        )
        self.fp.add(20, 1, comm="bash", sid=20, tty=34816, born=1000.0)
        stop = mock.patch.object(
            engine,
            "stop",
            return_value={
                "removed": True,
                "decisions": [{"action": "kill", "key": "vite", "pid": 30}],
                "left": [],
                "stopped": [30],
            },
        )
        self.stopm = stop.start()
        self.addCleanup(stop.stop)

    def log(self):
        with open(self.d.store.log_path) as f:
            return [json.loads(l) for l in f]

    def idle(self, *pids):
        """Give pids a flat CPU history spanning a minute so cpu_pct is 0."""
        for p in pids:
            self.d.lineage.entry(p)["cpu"] = [(time.time() - 60, 0), (time.time(), 0)]


class JobSurvivors(AutoCase):
    def job(self, tag="20.1"):
        env = {"TAEMA_JOB": tag}
        up = self.fp.up
        self.fp.add(21, 20, comm="npm", env=env, born=up - 6.0, pgrp=21)
        self.fp.add(30, 1, comm="vite", env=env, born=up - 5.0, sid=30)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.again()

    def again(self, cpu_idle=True):
        """job_done + settle for the current tag."""
        self.d.handle(
            {
                "cmd": "job_done",
                "shell_pid": 20,
                "tag": "20.1",
                "status": 0,
                "word": "npm",
            }
        )
        self.d.deadlines.clear()
        if cpu_idle:
            self.idle(30)
        self.d.decide_job("20.1")

    def prime(self):
        self.fp.add(
            21,
            20,
            comm="npm",
            env={"TAEMA_JOB": "20.1"},
            born=self.fp.up - 6.0,
            pgrp=21,
        )
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)

    def refusals(self):
        return [e["why"] for e in self.log() if e["event"] == "auto_stop_refused"]

    def test_explicit_stop_carves_and_stops_gracefully_during_probation(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.stopm.assert_called_once()
        path, kw = self.stopm.call_args[0][0], self.stopm.call_args[1]
        self.assertTrue(path.endswith("/app-host/job-20-1"), path)
        self.assertFalse(kw["allow_sigkill"])  # first automatic stop is probationary
        self.assertTrue(5 <= kw["timeout"] <= 30)
        with open(path + "/cgroup.procs") as f:
            self.assertEqual(f.read().split(), ["30"])  # carved, no sudo
        self.assertGreater(
            self.d.store.data["pairs"][knowledge.Store.pkey("npm", "vite")][
                "last_auto_stop"
            ],
            0,
        )
        st = self.d.handle({"cmd": "status"})["auto"]
        self.assertEqual(len(st["auto_stops"]), 1)
        self.assertIn("answered stop", st["auto_stops"][0]["why"])
        pair = self.d.store.data["pairs"][self.d.store.pkey("npm", "vite")]
        self.assertEqual(pair["probation"], 1)
        self.assertEqual(len(self.d.store.pending_auto_stops()), 1)

    def test_refused_carved_stop_does_not_open_a_learning_outcome(self):
        self.d.store.answer("npm", "vite", "stop")
        self.stopm.side_effect = engine.Refused("stop refused")

        self.job()

        self.stopm.assert_called_once()
        pair = self.d.store.data["pairs"][self.d.store.pkey("npm", "vite")]
        self.assertEqual(pair.get("probation", 0), 0)
        self.assertEqual(self.d.store.pending_auto_stops(), [])

    def test_unsignalled_loose_survivor_does_not_open_a_learning_outcome(self):
        self.d.store.answer("npm", "vite", "stop")
        self.cgmap[30] = "/2"

        with mock.patch.object(engine, "signal_survivors", return_value=[]) as signal:
            self.job()

        signal.assert_called_once()
        pair = self.d.store.data["pairs"][self.d.store.pkey("npm", "vite")]
        self.assertEqual(pair.get("probation", 0), 0)
        self.assertEqual(self.d.store.pending_auto_stops(), [])

    def test_adopt_stops_an_explicitly_answered_pair_on_job_close(self):
        self.d.cfg["mode"] = "adopt"
        self.d.store.answer("npm", "vite", "stop")

        self.job()

        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args.kwargs["allow_sigkill"])
        self.assertEqual(self.stopm.call_args.kwargs["decision_authority"], "pair")

    def test_adopt_answered_default_does_not_stop_a_learned_pair_on_close(self):
        self.d.cfg["mode"] = "adopt"
        store = self.d.store
        store.data["created"] -= 30 * knowledge.DAY
        for day in range(4):
            for _ in range(2):
                store.observe_kill_inferred("npm", "vite", day=day)
        store.data["pairs"][store.pkey("npm", "vite")]["first_seen"] -= (
            8 * knowledge.DAY
        )

        self.job()

        self.assertEqual(store.pair_decision("npm", "vite")[0], "stop")
        self.stopm.assert_not_called()

    def test_silent_pair_never_sigkills(self):
        s = self.d.store
        s.data["created"] -= 30 * DAY
        for day in range(4):
            for _ in range(2):
                s.observe_kill_inferred("npm", "vite", day=day)
        s.data["pairs"][s.pkey("npm", "vite")]["first_seen"] -= 8 * DAY
        self.job()
        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args[1]["allow_sigkill"])

    def test_ask_and_keep_do_nothing(self):
        self.job()
        self.stopm.assert_not_called()
        self.assertFalse(os.path.exists("%s/app-host/job-20-1" % self.cg.base))
        self.d.store.answer("npm", "vite", "keep")
        self.prime()
        self.again()
        self.stopm.assert_not_called()

    def test_busy_cpu_unknown_cpu_and_edges_keep(self):
        self.d.store.answer("npm", "vite", "stop")
        with mock.patch.object(type(self.d.lineage), "cpu_pct", return_value=50.0):
            self.job()
        self.stopm.assert_not_called()
        self.assertIn("cpu 50.0% > 1%", self.refusals())
        self.prime()  # no cpu history at all: unknown keeps
        self.d.lineage.entry(30)["cpu"] = []
        self.again(cpu_idle=False)
        self.stopm.assert_not_called()
        self.assertIn("cpu unknown", self.refusals())
        self.prime()
        self.edges = {30: [{"kind": "tcp_server", "detail": "x", "peers": [9]}]}
        self.again()
        self.stopm.assert_not_called()
        self.assertIn("has edges", self.refusals())
        self.assertFalse(
            os.path.exists("%s/app-host/job-20-1" % self.cg.base)
        )  # nothing was carved

    def test_not_under_user_scope_is_signalled_in_place(self):
        self.d.store.answer("npm", "vite", "stop")
        self.cgmap[30] = "/2"
        with mock.patch.object(engine, "signal_survivors") as sig:
            self.job()
        self.stopm.assert_not_called()
        self.assertEqual([i["pid"] for i in sig.call_args[0][1]], [30])
        self.assertFalse(sig.call_args[0][3])  # explicit but still in probation

    def test_standalone_adopted_never_stopped(self):
        self.d.store.answer("npm", "vite", "standalone")
        self.cgmap[30] = "/2"
        with mock.patch.object(engine, "helper_move") as hm:
            self.job()
        self.stopm.assert_not_called()
        self.assertEqual(hm.call_args[0][2], [30])
        self.assertRegex(hm.call_args[0][1], r"^app-vite-[0-9a-f]{6}$")
        self.assertEqual(len(self.d.auto_scopes), 1)

    def test_reappearance_under_an_unrelated_owner_does_not_regret_pair(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")
        self.fp.remove(30)
        self.d.lineage.observe(self.fp.table())
        self.fp.add(60, 1, comm="vite", born=self.fp.up - 1)
        self.d.lineage.observe(self.fp.table())
        self.d.after_observe()
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")
        self.assertEqual([e["event"] for e in self.log()].count("regret"), 0)

    def test_reappearance_under_the_same_owner_records_respawn_and_regret(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.fp.remove(30)
        self.d.lineage.observe(self.fp.table())
        self.fp.add(60, 20, comm="npm", born=self.fp.up - 1)
        self.fp.add(61, 60, comm="vite", born=self.fp.up - 1)
        self.d.lineage.observe(self.fp.table())

        self.d.after_observe()

        pair = self.d.store.data["pairs"][self.d.store.pkey("npm", "vite")]
        self.assertEqual(pair["respawn"], 1)
        self.assertEqual(pair["keep"], 1.0)
        self.assertEqual(pair["regret_keep"], 3.0)
        self.assertGreater(pair["suspended_until"], time.time())
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "ask")
        self.assertEqual([e["event"] for e in self.log()].count("regret"), 1)

    def test_regret_window_expires(self):
        self.d.store.answer("npm", "vite", "stop")
        self.d.note_auto_stop("s", "w", [("npm", "vite")])
        pending = self.d.store.data["pairs"][self.d.store.pkey("npm", "vite")][
            "pending_stop"
        ]
        pending["ts"] = time.time() - knowledge.REGRET_WINDOW - 5
        self.fp.add(60, 1, comm="vite", born=self.fp.up - 1)
        self.d.lineage.observe(self.fp.table())
        self.d.check_regret(self.d.lineage, time.time())
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")


class GuiClose(AutoCase):
    def close_gui(self, comm="firefox", root_pid=200, survivor_pid=201, **root_kw):
        up = self.fp.up
        self.fp.add(
            100, 1, comm="niri", sid=100, born=100.0
        )  # parent: roots need a parent entry
        self.fp.add(root_pid, 100, comm=comm, born=up - 100, **root_kw)
        self.fp.add(survivor_pid, root_pid, comm="helper", born=up - 90)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(root_pid)
        self.d.lineage.observe(self.fp.table())
        self.assertEqual(len(self.d.lineage.closed), 1)

    def test_leftovers_move_to_leftover_leaf_and_are_learned(self):
        self.close_gui()
        self.d.after_observe()
        dest = "%s/leftover/firefox-200" % self.cg.base
        with open(dest + "/cgroup.procs") as f:
            self.assertEqual(f.read().split(), ["201"])
        p = self.d.store.data["pairs"][knowledge.Store.pkey("firefox", "helper")]
        self.assertEqual((p["closes"], p["launches"]), (1, 0))
        self.assertEqual(self.d.handle({"cmd": "status"})["auto"]["leftover_leaves"], 1)

    def test_junk_root_close_counts_noise_and_never_pairs(self):
        self.close_gui(comm="MainThread")
        self.d.after_observe()
        self.assertEqual(self.d.store.data["pairs"], {})
        self.assertEqual(self.d.store.data["noise"], {"helper": 1})
        self.assertFalse([e for e in self.log() if e["event"] == "would_stop"])

    def test_adopt_mode_contains_gui_survivors_in_one_pass(self):
        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        destination = self.cg.base + "/leftover/firefox-200"
        with mock.patch.object(
            self.d,
            "_enable_memory_controllers",
            wraps=self.d._enable_memory_controllers,
        ) as enable_memory:
            self.d.after_observe()
        enable_memory.assert_called_once_with("leftover/firefox-200", destination)
        dest = self.cg.base + "/leftover/firefox-200"
        with open(dest + "/cgroup.procs") as f:
            self.assertEqual(f.read().split(), ["201"])

    def test_leftover_parent_enables_memory_controller_before_leaf_creation(self):
        self.d.cfg["mode"] = "adopt"
        base = self.cg.base
        leftover_parent = self.cg.leaf("leftover")
        for path, value in (
            (base + "/cgroup.controllers", "memory\n"),
            (base + "/cgroup.subtree_control", "+memory\n"),
            (base + "/cgroup.procs", ""),
            (leftover_parent + "/cgroup.controllers", "memory\n"),
            (leftover_parent + "/cgroup.subtree_control", ""),
            (leftover_parent + "/cgroup.procs", ""),
        ):
            with open(path, "w", encoding="ascii") as target:
                target.write(value)

        self.close_gui()
        self.d.after_observe()

        with open(
            leftover_parent + "/cgroup.subtree_control", encoding="ascii"
        ) as source:
            self.assertEqual(source.read(), "+memory\n")

    def test_leftover_parent_respects_memory_disabled(self):
        self.d.cfg["mode"] = "adopt"
        self.d.cfg["mem"] = {"enabled": False}
        base = self.cg.base
        leftover_parent = self.cg.leaf("leftover")
        for path, value in (
            (base + "/cgroup.controllers", "memory\n"),
            (base + "/cgroup.subtree_control", ""),
            (base + "/cgroup.procs", ""),
            (leftover_parent + "/cgroup.controllers", "memory\n"),
            (leftover_parent + "/cgroup.subtree_control", ""),
            (leftover_parent + "/cgroup.procs", ""),
        ):
            with open(path, "w", encoding="ascii") as target:
                target.write(value)

        self.close_gui()
        self.d.after_observe()

        with open(
            leftover_parent + "/cgroup.subtree_control", encoding="ascii"
        ) as source:
            self.assertEqual(source.read(), "")
        leaf = base + "/leftover/firefox-200"
        with open(leaf + "/cgroup.procs", encoding="ascii") as source:
            self.assertEqual(source.read().split(), ["201"])

    def test_adopt_stops_an_explicitly_answered_pair_on_gui_close(self):
        self.d.cfg["mode"] = "adopt"
        self.d.store.answer("firefox", "helper", "stop")
        self.close_gui()
        self.idle(201)

        with mock.patch.object(engine, "signal_survivors", return_value=[201]) as stop:
            self.d.after_observe()

        stop.assert_called_once()
        self.assertFalse(
            stop.call_args.args[3]
        )  # explicit answers still pass probation gracefully
        self.assertEqual(self.d.store.open_reviews(), [])
        self.assertFalse(os.path.exists(self.cg.base + "/leftover/firefox-200"))

    def test_adopt_stops_an_explicitly_answered_signature_on_gui_close(self):
        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        entry = self.d.lineage.entry(201)
        signature = self.d.survivor_signature(
            "firefox",
            [{"pid": 201, "start": entry["start"], "key": "helper"}],
        )
        self.assertTrue(self.d.store.answer_signature("firefox", signature, "stop"))
        self.idle(201)

        with mock.patch.object(engine, "signal_survivors", return_value=[201]) as stop:
            self.d.after_observe()

        stop.assert_called_once()
        self.assertFalse(
            stop.call_args.args[3]
        )  # new signatures begin in graceful-only probation
        self.assertEqual(self.d.store.pair_decision("firefox", "helper")[0], "ask")
        self.assertEqual(self.d.store.open_reviews(), [])

    def test_enforce_mode_contains_gui_survivors_in_one_pass(self):
        self.d.cfg["mode"] = "enforce"
        self.close_gui()
        self.d.after_observe()
        dest = self.cg.base + "/leftover/firefox-200"
        with open(dest + "/cgroup.procs") as f:
            self.assertEqual(f.read().split(), ["201"])

    def test_observe_logs_would_contain_without_moving(self):
        self.d.cfg["mode"] = "observe"
        self.close_gui()
        self.d.after_observe()
        self.assertFalse(os.path.exists(self.cg.base + "/leftover"))
        would = [e for e in self.log() if e["event"] == "would_contain"]
        self.assertEqual(len(would), 1)
        self.assertEqual(
            (would[0]["owner"], would[0]["survivors"], would[0]["pids"]),
            ("firefox", ["helper"], [201]),
        )

    def test_containment_records_a_persistent_review(self):
        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        self.d.after_observe()
        status = self.d.handle({"cmd": "status"})
        self.assertEqual(status["reviews"], 1)
        reviews = self.d.handle({"cmd": "review"})["reviews"]
        self.assertEqual(len(reviews), 1)
        review = reviews[0]
        self.assertEqual(
            (review["id"], review["owner"], review["survivors"], review["pids"]),
            (1, "firefox", ["helper"], [201]),
        )
        self.assertEqual(review["expires"] - review["created"], 14 * DAY)
        out = io.StringIO()
        readonly = knowledge.Store(self.d.store.dir, read_only=True)
        with (
            mock.patch.object(cli, "_load", return_value=(self.d.cfg, readonly, [])),
            redirect_stdout(out),
        ):
            cli.main(["review"])
        self.assertIn("review #1", out.getvalue())
        self.assertIn("owner=firefox", out.getvalue())
        self.assertIn("survivors=helper", out.getvalue())
        self.assertIn("age=", out.getvalue())
        self.assertIn("closes=", out.getvalue())
        self.assertIn("mem=", out.getvalue())
        self.assertIn("provenance:", out.getvalue())
        self.assertIn("sig ", out.getvalue())
        self.assertNotIn("open reviews: 1", out.getvalue())

        restarted = daemon.Daemon(make_cfg(self.d.store.dir, mode="adopt"))
        self.assertEqual(restarted.handle({"cmd": "status"})["reviews"], 1)
        self.assertEqual(restarted.handle({"cmd": "review"})["reviews"], reviews)

    def test_standalone_review_answer_adopts_recorded_live_members(self):
        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        self.d.after_observe()
        review = self.d.store.open_reviews()[0]

        with (
            mock.patch.object(
                self.d,
                "_live_standalone_members",
                return_value=[{"key": "helper", "pid": 201, "start": 100}],
            ),
            mock.patch.object(cgroup, "move") as move,
        ):
            reply = self.d.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "standalone-review-1",
                    "op": "review_answer",
                    "review_id": review["id"],
                    "choice": "standalone",
                }
            )

        self.assertTrue(reply["ok"])
        self.assertTrue(self.d.store.standalone("helper"))
        self.assertTrue(self.d.store.data["reviews"][0]["adopted"])
        move.assert_called_once()
        self.assertEqual(move.call_args.args[0], 201)

    def test_interactive_review_routes_shown_and_answer_through_feedback(self):
        class TTYInput(io.StringIO):
            def isatty(self):
                return True

        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        self.d.after_observe()
        readonly = knowledge.Store(self.d.store.dir, read_only=True)
        next_id = [0]

        def feedback(_cfg, _store, op, **fields):
            next_id[0] += 1
            reply = self.d.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "interactive-review-%d" % next_id[0],
                    "op": op,
                    **fields,
                }
            )
            return "daemon", reply

        output = io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(self.d.cfg, readonly, [])),
            mock.patch.object(cli, "feedback_action", side_effect=feedback),
            mock.patch("sys.stdin", TTYInput("2\n")),
            redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["review", "--interactive"]), 0)

        self.assertIn("Choice [1 stop", output.getvalue())
        self.assertIn("answered keep", output.getvalue())
        self.assertEqual(self.d.store.pair_decision("firefox", "helper")[0], "keep")
        self.assertEqual(self.d.store.data["asked"]["n"], 1)
        self.assertEqual(next_id[0], 2)

    def test_interactive_review_empty_queue_and_terminal_requirements(self):
        class TTYInput(io.StringIO):
            def isatty(self):
                return True

        output, errors = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(
                cli, "_load", return_value=(self.d.cfg, self.d.store, [])
            ),
            mock.patch("sys.stdin", TTYInput("")),
            redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["review", "--interactive"]), 0)
        self.assertIn("open reviews: 0", output.getvalue())

        with (
            mock.patch.object(
                cli, "_load", return_value=(self.d.cfg, self.d.store, [])
            ),
            mock.patch("sys.stdin", TTYInput("")),
            redirect_stderr(errors),
        ):
            self.assertEqual(cli.main(["review", "--interactive", "--json"]), 2)
        self.assertIn("cannot be combined with JSON", errors.getvalue())

        errors = io.StringIO()
        with (
            mock.patch.object(
                cli, "_load", return_value=(self.d.cfg, self.d.store, [])
            ),
            mock.patch("sys.stdin", io.StringIO("")),
            redirect_stderr(errors),
        ):
            self.assertEqual(cli.main(["review", "--interactive"]), 2)
        self.assertIn("needs a terminal", errors.getvalue())

    def test_open_review_holds_a_previously_authorized_leftover(self):
        self.d.store.answer("firefox", "helper", "stop")
        self.close_gui()
        self.d.after_observe()
        scope = "leftover/firefox-200"
        self.cg.set_cpu(scope, 100)
        self.d.gc_usage[scope] = 100
        self.d.idle_since[scope] = time.time() - 2000
        self.d.gc_pass()
        self.stopm.assert_not_called()

    def test_expired_review_resolves_to_keep_and_never_stops(self):
        self.d.store.answer("firefox", "helper", "stop")
        self.close_gui()
        self.d.after_observe()
        review = self.d.store.data["reviews"][0]
        review["expires"] = time.time() - 1
        scope = "leftover/firefox-200"
        self.cg.set_cpu(scope, 100)
        self.d.gc_usage[scope] = 100
        self.d.idle_since[scope] = time.time() - 2000
        self.d.gc_pass()
        self.assertEqual(review["state"], "expired")
        self.assertEqual(self.d.store.pair_decision("firefox", "helper")[0], "keep")
        self.stopm.assert_not_called()

    def test_expired_review_keeps_survivors_even_with_invalid_owner(self):
        self.close_gui(comm="MainThread")
        self.d.after_observe()
        review = self.d.store.data["reviews"][0]
        review["expires"] = time.time() - 1
        scope = review["scope"]
        self.cg.set_cpu(scope, 100)
        self.d.gc_usage[scope] = 100
        self.d.idle_since[scope] = time.time() - 2000
        self.d.gc_pass()
        self.assertEqual(review["state"], "expired")
        self.assertTrue(self.d.store.review_holds_scope(scope))
        self.stopm.assert_not_called()

    def test_terminal_job_root_gets_no_leftover_leaf(self):
        self.close_gui(tty=34816)
        self.d.after_observe()
        self.assertFalse(os.path.exists(self.cg.base + "/leftover"))

    def test_standalone_leftover_gets_its_own_scope(self):
        self.d.store.answer("firefox", "helper", "standalone")
        self.cgmap[201] = "/2"
        self.close_gui()
        with mock.patch.object(engine, "helper_move") as hm:
            self.d.after_observe()
        self.assertRegex(hm.call_args[0][1], r"^app-helper-[0-9a-f]{6}$")
        self.assertFalse(os.path.exists(self.cg.base + "/leftover"))

    def test_standalone_survivors_get_app_scopes_in_adopt_and_enforce(self):
        self.d.store.answer("firefox", "helper", "standalone")
        for i, mode in enumerate(("adopt", "enforce")):
            root_pid, survivor_pid = 300 + i * 10, 301 + i * 10
            self.d.cfg["mode"] = mode
            self.cgmap[survivor_pid] = "/2"
            with mock.patch.object(engine, "helper_move") as hm:
                self.close_gui(root_pid=root_pid, survivor_pid=survivor_pid)
                self.d.after_observe()
            self.assertEqual(hm.call_args[0][2], [survivor_pid])
            self.assertRegex(hm.call_args[0][1], r"^app-helper-[0-9a-f]{6}$")
        self.assertFalse(os.path.exists(self.cg.base + "/leftover"))
        self.assertEqual(self.d.handle({"cmd": "status"})["reviews"], 0)


# ---- 5. GC rules for leftover/* --------------------------------------------------------------


class RuntimeGc(AutoCase):
    def runtime_unit(self, mode="enforce", hook=None):
        pid = 303
        self.fp.add(pid, 1, comm="qemu-system-x86_64", born=self.fp.up - 300)
        self.d.lineage.observe(self.fp.table())
        self.idle(pid)
        path = self.cg.leaf("app-libvirt-qemu-abcdef12", [pid], cpu=100)
        unit = {
            "unit": {
                "name": "app-libvirt-qemu",
                "kind": "app",
                "class": "vm",
                "stop_when_unneeded": True,
            },
            "mem": {"idle_reclaim": True},
            "gc": {"qmp_socket": True, "no_attach_grace": 120},
        }
        if hook:
            unit["mem"][hook[0]] = hook[1]
        self.d.units = [unit]
        self.d.cfg["mode"] = mode
        return path, unit, pid

    def assert_empty_runtime_lifecycle(self, remove):
        path, _unit, _pid = self.runtime_unit()
        leaf = cgroup.rel(path)
        self.cg.set_procs(leaf, [])
        self.d.cfg["mem"] = {"enabled": True}
        self.d.memory_scope_seen.add(leaf)
        with (
            mock.patch.object(self.d, "_review_memory", side_effect=[4096, 4096]),
            mock.patch.object(self.d, "memory_governor_pass") as rebalance,
            mock.patch.object(
                engine, "remove_empty", return_value=True
            ) as remove_empty,
        ):
            self.assertTrue(remove(path, leaf))

        lifecycle = [
            event
            for event in self.log()
            if event["event"] in ("gc_quit", "gc_removed_empty", "freed")
        ]
        self.assertEqual(
            [event["event"] for event in lifecycle],
            ["gc_quit", "gc_removed_empty", "freed"],
        )
        self.assertEqual(lifecycle[0]["before"], {"memory_bytes": 4096, "pids": 0})
        self.assertEqual(lifecycle[0]["after"], {"memory_bytes": 4096, "pids": 0})
        self.assertIn("already exited", lifecycle[0]["hook"]["result"])
        self.assertEqual(lifecycle[2]["before"]["memory_bytes"], 4096)
        self.assertEqual(lifecycle[2]["after"]["memory_bytes"], 0)
        remove_empty.assert_called_once_with(path)
        rebalance.assert_called_once()

    def test_populated_zero_runtime_exit_releases_budget(self):
        with mock.patch.object(self.d, "_drop_leaf_watch"):
            self.assert_empty_runtime_lifecycle(
                lambda _path, leaf: self.d._remove_if_currently_empty(
                    73, leaf, {"populated": "0"}
                )
            )

    def test_scheduled_empty_runtime_exit_releases_budget(self):
        def remove(path, leaf):
            self.d.empty_seen.add(leaf)
            with mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "empty")]
            ):
                result = self.d.gc_pass()
            return result == [[leaf, "empty", "remove"]]

        self.assert_empty_runtime_lifecycle(remove)

    def test_runtime_class_resolution_preserves_legacy_unit_fields(self):
        path, unit, _pid = self.runtime_unit()
        unit["unit"].pop("class")
        unit["unit"]["mem_class"] = "vm"

        self.assertIs(self.d._runtime_gc_unit(path), unit)
        self.assertEqual(self.d._reclaim_class("app-libvirt-qemu-abcdef12", path), "vm")

    def test_podman_hook_keeps_last_container_id_after_conmon_exits(self):
        self.fp.add(330, 1, comm="catatonit", env={"XDG_RUNTIME_DIR": self.rt})
        self.fp.add(
            331,
            330,
            comm="conmon",
            argv=["conmon", "-c", "container-id"],
            env={"XDG_RUNTIME_DIR": self.rt},
        )
        self.cg.leaf("app-podman-abcdef12", [330, 331])
        unit = {
            "unit": {
                "name": "app-podman",
                "kind": "app",
                "class": "container",
            }
        }
        self.d.units = [unit]

        self.d._remember_runtime_identities()
        self.cg.set_procs("app-podman-abcdef12", [330])
        unit["mem"] = {"pause": ["podman", "pause", "%(container)s"]}
        process = mock.Mock(returncode=0)
        process.communicate.return_value = ("paused\n", None)
        with mock.patch.object(
            daemon.subprocess, "Popen", return_value=process
        ) as popen:
            success, reason = self.d._run_runtime_hook(
                "app-podman-abcdef12", unit, 1000, field="pause"
            )

        self.assertTrue(success, reason)
        self.assertEqual(popen.call_args.args[0], ["podman", "pause", "container-id"])

    def test_podman_hook_preserves_each_container_in_a_shared_runtime_scope(self):
        self.fp.add(330, 1, comm="catatonit", env={"XDG_RUNTIME_DIR": self.rt})
        self.fp.add(
            331,
            330,
            comm="conmon",
            argv=["conmon", "-c", "first-container"],
            env={"XDG_RUNTIME_DIR": self.rt},
        )
        self.fp.add(
            332,
            330,
            comm="conmon",
            argv=["conmon", "-c", "second-container"],
            env={"XDG_RUNTIME_DIR": self.rt},
        )
        scope = "app-podman-abcdef12"
        self.cg.leaf(scope, [330, 331, 332])
        unit = {
            "unit": {
                "name": "app-podman",
                "kind": "app",
                "class": "container",
            },
            "mem": {"pause": ["podman", "pause", "%(container)s"]},
        }
        self.d.units = [unit]
        self.d._remember_runtime_identities()
        self.cg.set_procs(scope, [330, 332])
        self.d._runtime_hook_fields(os.path.join(cgroup.base(), scope), unit["unit"])
        self.cg.set_procs(scope, [330])
        processes = []
        for output in ("paused first\n", "paused second\n"):
            process = mock.Mock(returncode=0)
            process.communicate.return_value = (output, None)
            processes.append(process)

        with mock.patch.object(
            daemon.subprocess, "Popen", side_effect=processes
        ) as popen:
            success, reason = self.d._run_runtime_hook(scope, unit, 1000, field="pause")

        self.assertTrue(success, reason)
        self.assertEqual(
            [call.args[0] for call in popen.call_args_list],
            [
                ["podman", "pause", "first-container"],
                ["podman", "pause", "second-container"],
            ],
        )
        pause_events = [
            event for event in self.log() if event["event"] == "runtime_pause"
        ]
        self.assertEqual(
            [event["container"] for event in pause_events],
            ["first-container", "second-container"],
        )

    def test_podman_hook_retries_only_containers_not_already_paused(self):
        self.fp.add(330, 1, comm="catatonit", env={"XDG_RUNTIME_DIR": self.rt})
        self.fp.add(
            331,
            330,
            comm="conmon",
            argv=["conmon", "-c", "first-container"],
            env={"XDG_RUNTIME_DIR": self.rt},
        )
        self.fp.add(
            332,
            330,
            comm="conmon",
            argv=["conmon", "-c", "second-container"],
            env={"XDG_RUNTIME_DIR": self.rt},
        )
        scope = "app-podman-abcdef12"
        self.cg.leaf(scope, [330, 331, 332])
        unit = {
            "unit": {
                "name": "app-podman",
                "kind": "app",
                "class": "container",
            },
            "mem": {"pause": ["podman", "pause", "%(container)s"]},
        }
        self.d.units = [unit]
        self.d._remember_runtime_identities()
        self.cg.set_procs(scope, [330])
        first = mock.Mock(returncode=0)
        first.communicate.return_value = ("paused first\n", None)
        second = mock.Mock(returncode=1)
        second.communicate.return_value = ("already running\n", None)

        with mock.patch.object(
            daemon.subprocess, "Popen", side_effect=[first, second]
        ) as popen:
            success, reason = self.d._run_runtime_hook(scope, unit, 1000, field="pause")

        self.assertFalse(success)
        self.assertEqual(reason, "runtime hook exited 1")
        self.assertEqual(
            [call.args[0] for call in popen.call_args_list],
            [
                ["podman", "pause", "first-container"],
                ["podman", "pause", "second-container"],
            ],
        )

        retry = mock.Mock(returncode=0)
        retry.communicate.return_value = ("paused second\n", None)
        with mock.patch.object(daemon.subprocess, "Popen", return_value=retry) as popen:
            success, reason = self.d._run_runtime_hook(scope, unit, 1301, field="pause")

        self.assertTrue(success, reason)
        popen.assert_called_once_with(
            ["podman", "pause", "second-container"],
            start_new_session=True,
            stdout=daemon.subprocess.PIPE,
            stderr=daemon.subprocess.STDOUT,
            text=True,
        )

    def test_vm_resume_allows_a_new_save_hook_attempt(self):
        path, unit, _pid = self.runtime_unit(
            hook=("save_state", ["virsh", "managedsave", "guest"])
        )
        scope = cgroup.rel(path)
        first = mock.Mock(returncode=0)
        first.communicate.return_value = ("saved\n", None)
        second = mock.Mock(returncode=0)
        second.communicate.return_value = ("saved again\n", None)

        with mock.patch.object(
            daemon.subprocess, "Popen", side_effect=[first, second]
        ) as popen:
            success, reason = self.d._run_runtime_hook(
                scope, unit, 1000, field="save_state"
            )
            self.assertTrue(success, reason)
            self.assertIn(scope, self.d.saved_vm_scopes)

            self.d.mark_vm_resumed(scope)
            self.assertNotIn(scope, self.d.saved_vm_scopes)
            self.assertNotIn(scope, self.d.runtime_hook_completed)
            success, reason = self.d._run_runtime_hook(
                scope, unit, 1301, field="save_state"
            )

        self.assertTrue(success, reason)
        self.assertIn(scope, self.d.saved_vm_scopes)
        self.assertEqual(popen.call_count, 2)

    def test_cleanup_orders_hook_reclaim_stop_and_records_freed_state(self):
        path, _unit, pid = self.runtime_unit(
            hook=("save_state", ["virsh", "managedsave", "%(domain)s"])
        )
        order = []
        report = {
            "removed": True,
            "decisions": [{"action": "kill", "key": "qemu", "pid": pid}],
            "left": [],
            "stopped": [pid],
        }
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "no attachment for 120s")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=4096),
            mock.patch.object(
                self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(self.d, "_runtime_stop_preflight", return_value=True),
            mock.patch.object(
                self.d,
                "_run_runtime_hook",
                side_effect=lambda *args, **kwargs: (
                    order.append("hook") or True,
                    "saved",
                ),
            ),
            mock.patch.object(
                self.d,
                "_reclaim_one",
                side_effect=lambda *args, **kwargs: (
                    order.append("reclaim")
                    or {"status": "reclaimed", "reclaimed_bytes": 128}
                ),
            ) as reclaim,
            mock.patch.object(daemon.memory, "pressure", return_value={}),
            mock.patch.object(
                engine,
                "stop",
                side_effect=lambda *args, **kwargs: order.append("stop") or report,
            ),
            mock.patch.object(self.d, "note_stop", return_value=[pid]),
            mock.patch.object(self.d, "stopped_apps", return_value=[]),
        ):
            self.d.gc_pass()

        self.assertEqual(order, ["hook", "reclaim", "stop"])
        self.assertTrue(reclaim.call_args.kwargs["idle_grace_prevalidated"])
        events = self.log()
        quit_event = next(event for event in events if event["event"] == "gc_quit")
        freed_event = next(event for event in events if event["event"] == "freed")
        self.assertEqual(quit_event["before"]["memory_bytes"], 4096)
        self.assertEqual(freed_event["before"]["memory_bytes"], 4096)
        self.assertEqual(freed_event["after"]["memory_bytes"], 0)

    def test_generic_container_and_vm_units_use_save_state_cleanup(self):
        for index, resource_class in enumerate(("container", "vm")):
            with self.subTest(resource_class=resource_class):
                name = "app-generic-" + resource_class
                pid = 350 + index
                self.fp.add(
                    pid,
                    1,
                    comm="generic-runtime-worker",
                    born=self.fp.up - 300,
                )
                self.d.lineage.observe(self.fp.table())
                self.idle(pid)
                path = self.cg.leaf(name + "-abcdef12", [pid], cpu=100)
                unit = {
                    "unit": {
                        "name": name,
                        "kind": "app",
                        "class": resource_class,
                    },
                    "match": {"comm": "generic-runtime-*"},
                    "mem": {
                        "save_state": ["runtime-save", "%(name)s"],
                    },
                }
                self.d.units = [unit]
                self.assertIs(self.d._runtime_gc_unit(path), unit)
                leaf = cgroup.rel(path)
                self.d.cfg["mode"] = "enforce"
                self.d.idle_since[leaf] = time.time() - 601
                order = []
                report = {
                    "removed": True,
                    "decisions": [{"action": "kill", "key": "worker", "pid": pid}],
                    "left": [],
                    "stopped": [pid],
                }
                with (
                    mock.patch.object(self.d, "_review_memory", return_value=4096),
                    mock.patch.object(
                        self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
                    ),
                    mock.patch.object(
                        self.d, "_reclaim_safety_reason", return_value=""
                    ),
                    mock.patch.object(
                        self.d, "_runtime_stop_preflight", return_value=True
                    ),
                    mock.patch.object(
                        self.d,
                        "_run_runtime_hook",
                        side_effect=lambda *args, **kwargs: (
                            order.append("hook") or True,
                            "saved",
                        ),
                    ) as hook,
                    mock.patch.object(
                        self.d,
                        "_reclaim_one",
                        side_effect=lambda *args, **kwargs: (
                            order.append("reclaim")
                            or {"status": "reclaimed", "reclaimed_bytes": 128}
                        ),
                    ),
                    mock.patch.object(daemon.memory, "pressure", return_value={}),
                    mock.patch.object(
                        engine,
                        "stop",
                        side_effect=lambda *args, **kwargs: (
                            order.append("stop") or report
                        ),
                    ),
                    mock.patch.object(self.d, "note_stop", return_value=[pid]),
                    mock.patch.object(self.d, "stopped_apps", return_value=[]),
                ):
                    self.d.gc_pass()

                self.assertEqual(order, ["hook", "reclaim", "stop"])
                self.assertEqual(hook.call_args.args[1], unit)
                self.assertEqual(hook.call_args.kwargs["field"], "save_state")
                self.assertTrue(
                    any(
                        event["event"] == "gc_quit"
                        and event["runtime_class"] == resource_class
                        for event in self.log()
                    )
                )

    def test_failed_preservation_hook_prevents_reclaim_and_stop(self):
        path, _unit, _pid = self.runtime_unit(
            hook=("save_state", ["virsh", "managedsave", "%(domain)s"])
        )
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "no attachment for 120s")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=2048),
            mock.patch.object(
                self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(self.d, "_runtime_stop_preflight", return_value=True),
            mock.patch.object(
                self.d, "_run_runtime_hook", return_value=(False, "hook exited 1")
            ),
            mock.patch.object(self.d, "_reclaim_one") as reclaim,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "kept")
        reclaim.assert_not_called()
        stop.assert_not_called()
        self.assertTrue(any(event["event"] == "gc_refused" for event in self.log()))

    def test_preservation_waits_for_idle_reclaim_grace(self):
        path, _unit, _pid = self.runtime_unit(
            hook=("save_state", ["virsh", "managedsave", "%(domain)s"])
        )
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "QMP socket gone")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=2048),
            mock.patch.object(
                self.d,
                "_reclaim_idle",
                return_value=(False, "idle for 120s; needs 300s"),
            ),
            mock.patch.object(self.d, "_runtime_stop_preflight") as preflight,
            mock.patch.object(self.d, "_run_runtime_hook") as hook,
            mock.patch.object(self.d, "_reclaim_one") as reclaim,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "kept")
        preflight.assert_not_called()
        hook.assert_not_called()
        reclaim.assert_not_called()
        stop.assert_not_called()

    def test_refused_stop_preflight_blocks_preservation_and_cleanup(self):
        path, _unit, _pid = self.runtime_unit(
            hook=("save_state", ["virsh", "managedsave", "%(domain)s"])
        )
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "QMP socket gone")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=2048),
            mock.patch.object(
                self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(self.d, "_runtime_stop_preflight", return_value=False),
            mock.patch.object(self.d, "_run_runtime_hook") as hook,
            mock.patch.object(self.d, "_reclaim_one") as reclaim,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "kept")
        hook.assert_not_called()
        reclaim.assert_not_called()
        stop.assert_not_called()
        self.assertTrue(any(event["event"] == "gc_refused" for event in self.log()))

    def test_runtime_hook_rechecks_attachments_before_preservation(self):
        path, _unit, pid = self.runtime_unit(
            mode="enforce",
            hook=("pause", ["podman", "pause", "%(container)s"]),
        )
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "QMP socket gone")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=2048),
            mock.patch.object(
                self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(
                self.d,
                "_reclaim_safety_reason",
                return_value="scope has external dependency edges",
            ) as safety,
            mock.patch.object(self.d, "_run_runtime_hook") as hook,
            mock.patch.object(self.d, "_reclaim_one") as reclaim,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "kept")
        safety.assert_called_once_with("app-libvirt-qemu-abcdef12", path, [pid])
        hook.assert_not_called()
        reclaim.assert_not_called()
        stop.assert_not_called()

    def test_adopt_does_not_run_destructive_runtime_hook_without_stop_authority(self):
        path, _unit, _pid = self.runtime_unit(
            mode="adopt",
            hook=("pause", ["podman", "stop", "%(container)s"]),
        )
        with (
            mock.patch.object(
                engine,
                "gc_candidates",
                return_value=[(path, "no attachment for 120s")],
            ),
            mock.patch.object(self.d, "_review_memory", return_value=2048),
            mock.patch.object(self.d, "_run_runtime_hook") as hook,
            mock.patch.object(self.d, "_contain_runtime_gc_review") as contain,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "review")
        hook.assert_not_called()
        contain.assert_called_once()
        stop.assert_not_called()

    def test_reclaim_reuses_runtime_gc_idle_validation(self):
        path, _unit, _pid = self.runtime_unit()
        self.d.cfg["mem"] = {"enabled": True, "reclaim": True}
        with (
            mock.patch.object(self.d, "_reclaim_safety_reason", return_value=""),
            mock.patch.object(self.d, "_reclaim_warm", return_value=False),
            mock.patch.object(self.d, "_reclaim_idle") as idle,
            mock.patch.object(
                daemon.memory,
                "pressure",
                return_value={"full_avg10": 0, "some_avg10": 0},
            ),
        ):
            result = self.d._reclaim_one(
                "app-libvirt-qemu-abcdef12",
                path,
                time.time(),
                {"full_avg10": 0, "some_avg10": 0},
                stage="page_cache",
                idle_grace_prevalidated=True,
            )

        idle.assert_not_called()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(
            result["reason"], "global some pressure is below the reclaim gate"
        )

    def test_observe_does_not_run_runtime_hooks_or_reclaim(self):
        path, _unit, _pid = self.runtime_unit(
            mode="observe",
            hook=("pause", ["podman", "pause", "%(container)s"]),
        )
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "no attachment for 120s")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=1024),
            mock.patch.object(self.d, "_run_runtime_hook") as hook,
            mock.patch.object(self.d, "_reclaim_one") as reclaim,
            mock.patch.object(self.d, "_contain_runtime_gc_review") as contain,
            mock.patch.object(engine, "stop") as stop,
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "would")
        hook.assert_not_called()
        reclaim.assert_not_called()
        contain.assert_not_called()
        stop.assert_not_called()

    def test_adopt_contains_unauthorized_runtime_and_review_shows_memory(self):
        path, _unit, pid = self.runtime_unit(
            mode="adopt",
            hook=("save_state", ["virsh", "managedsave", "%(domain)s"]),
        )
        order = []
        with (
            mock.patch.object(
                engine, "gc_candidates", return_value=[(path, "no attachment for 120s")]
            ),
            mock.patch.object(self.d, "_review_memory", return_value=8192),
            mock.patch.object(
                self.d, "_reclaim_idle", return_value=(True, "idle for 300s")
            ),
            mock.patch.object(
                self.d,
                "_run_runtime_hook",
                side_effect=lambda *args, **kwargs: (
                    order.append("save") or True,
                    "saved",
                ),
            ) as hook,
            mock.patch.object(
                self.d,
                "_reclaim_one",
                side_effect=lambda *args, **kwargs: (
                    order.append("reclaim") or {"status": "skipped"}
                ),
            ),
            mock.patch.object(daemon.memory, "pressure", return_value={}),
        ):
            result = self.d.gc_pass()

        self.assertEqual(result[0][2], "review")
        self.assertEqual(order, ["reclaim"])
        hook.assert_not_called()
        quit_event = next(event for event in self.log() if event["event"] == "gc_quit")
        self.assertIn("stop authority is unavailable", quit_event["hook"]["result"])
        destination = "leftover/" + engine.leaf_slug("app-libvirt-qemu-abcdef12", pid)
        with open(os.path.join(self.cg.base, destination, "cgroup.procs")) as source:
            self.assertEqual(source.read().split(), [str(pid)])
        review = self.d.store.open_reviews()[0]
        self.assertEqual(review["scope"], destination)
        self.assertEqual(review["mem"], 8192)


class LeftoverGc(AutoCase):
    def leaf(self, pids=(301,), key="vite", origin="foo", cpu=100):
        for p in pids:
            self.fp.add(p, 1, comm=key, sid=p, born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        for p in pids:
            self.d.lineage.entry(p)["root_key"] = origin
        self.idle(*pids)
        self.cg.leaf("leftover/x", pids, cpu=cpu)

    def cands(self, t=0, auto=True):
        d = self.d
        return engine.gc_candidates(
            d.cfg,
            [],
            d.store,
            d.idle_since,
            now=lambda: t,
            usage=d.gc_usage,
            skip=d.gc_skip,
            noted=d.gc_noted,
            lin=d.lineage,
            auto=auto,
        )

    def test_pair_stop_candidate(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        ((path, why),) = self.cands()
        self.assertTrue(path.endswith("leftover/x"))
        self.assertTrue(why.startswith("pair stop"))

    def test_idle_for_learned_grace_then_stop(self):
        self.leaf()
        self.assertEqual(self.cands(t=0), [])
        self.assertEqual(self.cands(t=300), [])
        ((path, why),) = self.cands(t=601)
        self.assertTrue(why.startswith("idle"))

    def test_cpu_movement_restarts_idle_window(self):
        self.leaf()
        self.cands(t=0)
        self.cg.set_cpu("leftover/x", 999)
        self.cands(t=400)
        self.assertEqual(self.cands(t=700), [])

    def test_persist_seed_never_stopped(self):
        self.d.store.seeds["persist"] = ["tmux"]
        self.leaf(key="tmux")
        self.d.store.answer("foo", "tmux", "stop")
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])

    def test_held_cases(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "keep")  # pair decided keep
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])
        self.d.store.answer("foo", "vite", "stop")
        self.assertEqual(len(self.cands(t=0)), 1)
        self.d.lineage.entry(301)["host"] = True  # pty host
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])

    def test_share_seed_with_user_keep_held(self):
        self.d.store.seeds["share"] = ["adb"]
        self.leaf(key="adb")
        self.d.store.apply_op("keep", "adb")
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])

    def test_edges_are_not_idle(self):
        self.leaf()
        self.edges = {301: [{"kind": "tcp_server", "detail": "x", "peers": []}]}
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])

    def test_protected_member_held(self):
        self.leaf(key="niriapp")
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])

    def test_other_modes_only_remove_empty_leftover_leaves(self):
        self.leaf()
        self.assertEqual(
            self.cands(t=0, auto=False) + self.cands(t=9999, auto=False), []
        )
        self.cg.leaf("leftover/y", [])
        got = self.cands(auto=False)
        self.assertEqual([(os.path.basename(p), w) for p, w in got], [("y", "empty")])

    def test_gc_pass_stays_graceful_during_pair_probation(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        res = self.d.gc_pass()
        self.assertEqual(res[0][2], "stop")
        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args[1]["allow_sigkill"])
        self.assertEqual(len(self.d.auto_stops), 1)
        self.assertFalse(self.d.may_kill())

    def test_adopt_stops_an_explicitly_answered_leftover(self):
        self.d.cfg["mode"] = "adopt"
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")

        result = self.d.gc_pass()

        self.assertEqual(result[0][2], "stop")
        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args.kwargs["allow_sigkill"])
        self.assertEqual(self.stopm.call_args.kwargs["decision_authority"], "pair")

    def test_gc_can_sigkill_after_pair_probation(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        self.d.store._pair("foo", "vite")["probation"] = 3

        self.d.gc_pass()

        self.assertTrue(self.stopm.call_args.kwargs["allow_sigkill"])

    def test_adopt_answered_authority_refuses_a_learned_stop(self):
        self.d.cfg["mode"] = "adopt"
        self.leaf()
        self.d.cfg["learn"] = {"authority": "answered"}
        pair = self.d.store._pair("foo", "vite")
        now = self.d.store.now()
        pair.update(
            {
                "stop": 5.0,
                "kills": 5,
                "inferred_kills": 5.0,
                "closes": 20,
                "days": [int(now // knowledge.DAY) - day for day in (2, 1, 0)],
                "first_seen": now - 2 * knowledge.DAY,
            }
        )
        self.d.store.data["closes"] = 20

        result = self.d.gc_pass()

        self.assertNotIn("stop", [row[2] for row in result])
        self.stopm.assert_not_called()

    def test_adopt_learned_authority_allows_learned_stop_without_sigkill(self):
        self.d.cfg["mode"] = "adopt"
        self.d.cfg["learn"] = {"authority": "learned"}
        self.leaf()
        pair = self.d.store._pair("foo", "vite")
        now = self.d.store.now()
        pair.update(
            {
                "stop": 5.0,
                "kills": 5,
                "inferred_kills": 5.0,
                "closes": 20,
                "days": [int(now // knowledge.DAY) - day for day in (2, 1, 0)],
                "first_seen": now - 2 * knowledge.DAY,
            }
        )
        self.d.store.data["closes"] = 20

        result = self.d.gc_pass()

        self.assertEqual(result[0][2], "stop")
        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args.kwargs["allow_sigkill"])

    def test_gc_keeps_and_reviews_unlearned_idle_leftover(self):
        self.leaf()
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100
        res = self.d.gc_pass()
        self.stopm.assert_not_called()
        self.assertEqual(res[0][2], "review")
        (review,) = self.d.store.open_reviews()
        self.assertEqual(review["scope"], "leftover/x")
        self.assertEqual(review["owner"], "foo")
        self.assertTrue(self.d.store.review_holds_scope("leftover/x"))
        self.assertEqual(policy.timer(self.d.cfg, "leftover_expire_days", 0), 0)
        self.age_review("leftover/x", 30)
        self.d.gc_pass()
        self.stopm.assert_not_called()
        self.assertEqual(self.d.store.pair_decision("foo", "vite")[0], "keep")

    def age_review(self, scope, days):
        review = next(
            r for r in self.d.store.data["reviews"] if r.get("scope") == scope
        )
        review["created"] = time.time() - days * knowledge.DAY
        review["expires"] = time.time() - 1

    def test_leftover_expiry_setting_stops_only_after_expired_review_age(self):
        self.leaf()
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100
        self.d.gc_pass()  # First records an unanswered review.
        self.age_review("leftover/x", 30)
        self.d.cfg.setdefault("timers", {})["leftover_expire_days"] = 20

        self.d.gc_pass()

        self.stopm.assert_called_once()

    def test_leftover_expiry_applies_to_ownerless_scope_review(self):
        self.leaf()
        self.d.lineage.entry(301)["root_key"] = ""
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100

        result = self.d.gc_pass()

        self.stopm.assert_not_called()
        self.assertEqual(result[0][2], "review")
        (review,) = self.d.store.open_reviews()
        self.assertEqual((review["kind"], review["scope"]), ("scope", "leftover/x"))
        self.assertTrue(self.d.store.review_holds_scope("leftover/x"))
        self.age_review("leftover/x", 30)
        self.d.cfg.setdefault("timers", {})["leftover_expire_days"] = 20

        self.d.gc_pass()

        self.stopm.assert_called_once()

    def test_leftover_expiry_never_overrides_answered_keep(self):
        self.leaf()
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100
        self.d.gc_pass()
        self.d.store.answer("foo", "vite", "keep")
        self.age_review("leftover/x", 30)
        self.d.cfg.setdefault("timers", {})["leftover_expire_days"] = 20

        self.d.gc_pass()

        self.stopm.assert_not_called()

    def test_leftover_expiry_never_overrides_scope_veto(self):
        self.leaf()
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100
        self.d.gc_pass()
        self.age_review("leftover/x", 30)
        self.d.cfg.setdefault("timers", {})["leftover_expire_days"] = 20
        self.d.store.add_veto("scope", "leftover/x")

        self.d.gc_pass()

        self.stopm.assert_not_called()
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "gc_stop"
                for e in self.log()
            )
        )

    def test_auto_collects_idle_shared_and_missing_runtime_unit_after_safety_checks(
        self,
    ):
        self.fp.add(301, 1, comm="helper", born=self.fp.up - 100)
        self.fp.add(
            302,
            1,
            comm="catatonit",
            env={"XDG_RUNTIME_DIR": self.rt + "/gone"},
            born=self.fp.up - 100,
        )
        self.d.lineage.observe(self.fp.table())
        self.idle(301, 302)
        self.cg.leaf("shared/helper-301", [301], cpu=100)
        self.cg.leaf("app-podman-deadbeef", [302], cpu=100)
        self.d.units = [
            {
                "unit": {
                    "name": "app-podman",
                    "kind": "app",
                    "stop_when_unneeded": True,
                },
                "match": {"comm": "catatonit"},
                "gc": {
                    "env_dir_missing": "XDG_RUNTIME_DIR",
                    "keep_while_children": True,
                },
            }
        ]
        self.d.idle_since["shared/helper-301"] = time.time() - 601
        self.d.gc_usage["shared/helper-301"] = 100

        result = self.d.gc_pass()

        self.assertEqual(
            {row[0] for row in result}, {"shared/helper-301", "app-podman-deadbeef"}
        )
        self.assertEqual(self.stopm.call_count, 2)
        self.assertEqual(
            {
                os.path.relpath(call.args[0], self.cg.base)
                for call in self.stopm.call_args_list
            },
            {"shared/helper-301", "app-podman-deadbeef"},
        )

    def test_adopt_queues_scope_reviews_for_idle_shared_and_unit_scopes(self):
        self.d.cfg["mode"] = "adopt"
        self.fp.add(301, 1, comm="helper", born=self.fp.up - 100)
        self.fp.add(302, 1, comm="catatonit", born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        self.idle(301, 302)
        self.cg.leaf("shared/helper-301", [301], cpu=100)
        self.cg.leaf("app-podman-deadbeef", [302], cpu=100)
        self.d.units = [
            {
                "unit": {
                    "name": "app-podman",
                    "kind": "app",
                    "stop_when_unneeded": True,
                },
                "match": {"comm": "catatonit"},
            }
        ]
        self.d.idle_since.update(
            {
                "shared/helper-301": time.time() - 601,
                "app-podman-deadbeef": time.time() - 601,
            }
        )
        self.d.gc_usage.update({"shared/helper-301": 100, "app-podman-deadbeef": 100})

        result = self.d.gc_pass()

        self.stopm.assert_not_called()
        self.assertEqual(
            {row[0] for row in result}, {"shared/helper-301", "app-podman-deadbeef"}
        )
        self.assertEqual(
            {r["scope"] for r in self.d.store.open_reviews()},
            {"shared/helper-301", "app-podman-deadbeef"},
        )
        self.assertTrue(all(r["kind"] == "scope" for r in self.d.store.open_reviews()))
        restarted = knowledge.Store(self.d.store.dir, seeds=self.d.store.seeds)
        self.assertEqual(
            {r["scope"] for r in restarted.open_reviews()},
            {"shared/helper-301", "app-podman-deadbeef"},
        )
        out = io.StringIO()
        with (
            mock.patch.object(
                cli, "_load", return_value=(self.d.cfg, self.d.store, self.d.units)
            ),
            redirect_stdout(out),
        ):
            cli.cmd_review(argparse.Namespace())
        self.assertIn("scope=shared/helper-301", out.getvalue())
        self.assertIn("scope=app-podman-deadbeef", out.getvalue())
        self.stopm.assert_not_called()

    def test_pending_adopt_scope_reviews_do_not_block_auto_gc(self):
        self.d.cfg["mode"] = "adopt"
        for pid, comm in (
            (301, "helper"),
            (302, "catatonit"),
            (303, "helper"),
            (304, "niri"),
        ):
            self.fp.add(pid, 1, comm=comm, born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        self.idle(301, 302, 303, 304)
        scopes = {
            301: "shared/helper-301",
            302: "app-podman-deadbeef",
            303: "shared/helper-303",
            304: "shared/niri-304",
        }
        for pid, scope in scopes.items():
            self.cg.leaf(scope, [pid], cpu=100)
            self.d.idle_since[scope] = time.time() - 601
            self.d.gc_usage[scope] = 100
        self.d.units = [
            {
                "unit": {
                    "name": "app-podman",
                    "kind": "app",
                    "stop_when_unneeded": True,
                },
                "match": {"comm": "catatonit"},
            }
        ]

        self.d.gc_pass()

        self.assertEqual(
            {r["scope"] for r in self.d.store.open_reviews()}, set(scopes.values())
        )
        self.assertFalse(self.d.store.review_holds_scope(scopes[301]))
        self.stopm.assert_not_called()
        self.d.store.add_veto("scope", scopes[303])
        self.d.cfg["mode"] = "auto"

        self.d.gc_pass()

        stopped_scopes = {
            os.path.relpath(call.args[0], self.cg.base)
            for call in self.stopm.call_args_list
        }
        self.assertEqual(stopped_scopes, {scopes[301], scopes[302]})
        self.assertEqual(
            {r["scope"] for r in self.d.store.open_reviews()}, set(scopes.values())
        )
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("scope") == scopes[303]
                for e in self.log()
            )
        )
        self.assertTrue(
            any(
                e.get("event") == "auto_stop_refused"
                and e.get("scope") == scopes[304]
                and "protected" in e.get("why", "")
                for e in self.log()
            )
        )

    def test_missing_runtime_dir_does_not_override_live_unit_children(self):
        gone = self.rt + "/gone"
        self.fp.add(
            302,
            1,
            comm="catatonit",
            env={"XDG_RUNTIME_DIR": gone},
            born=self.fp.up - 100,
        )
        self.fp.add(
            303, 302, comm="conmon", env={"XDG_RUNTIME_DIR": gone}, born=self.fp.up - 90
        )
        self.d.lineage.observe(self.fp.table())
        self.idle(302, 303)
        self.cg.leaf("app-podman-deadbeef", [302, 303], cpu=100)
        self.d.units = [
            {
                "unit": {
                    "name": "app-podman",
                    "kind": "app",
                    "stop_when_unneeded": True,
                },
                "match": {"comm": "catatonit"},
                "gc": {
                    "env_dir_missing": "XDG_RUNTIME_DIR",
                    "keep_while_children": True,
                },
            }
        ]

        self.d.gc_pass()

        self.stopm.assert_not_called()

    def test_auto_gc_veto_keeps_an_idle_shared_scope(self):
        self.fp.add(301, 1, comm="helper", born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        self.idle(301)
        self.cg.leaf("shared/helper-301", [301], cpu=100)
        self.d.idle_since["shared/helper-301"] = time.time() - 601
        self.d.gc_usage["shared/helper-301"] = 100
        self.d.store.add_veto("scope", "shared/helper-301")

        result = self.d.gc_pass()

        self.stopm.assert_not_called()
        self.assertEqual(result[0][2], "would")
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "gc_stop"
                for e in self.log()
            )
        )

    def test_auto_gc_protection_check_keeps_an_idle_shared_scope(self):
        self.fp.add(301, 1, comm="niri", born=self.fp.up - 100)
        self.d.lineage.observe(self.fp.table())
        self.idle(301)
        self.cg.leaf("shared/niri-301", [301], cpu=100)
        self.d.idle_since["shared/niri-301"] = time.time() - 601
        self.d.gc_usage["shared/niri-301"] = 100

        self.d.gc_pass()

        self.stopm.assert_not_called()

    def test_gc_would_stop_is_deduplicated_for_a_day_of_passes(self):
        self.d.cfg["mode"] = "adopt"
        path = self.cg.leaf("shared/helper-301", [301], cpu=100)
        start = time.time()
        now = [start]
        self.d.store.now = lambda: now[0]
        with mock.patch.object(
            engine, "gc_candidates", return_value=[(path, "idle 600s >= grace 600s")]
        ):
            for minute in range(24 * 60):
                now[0] = start + minute * 60
                self.d.gc_pass()
            now[0] = start + knowledge.DAY
            self.d.gc_pass()

        events = [e for e in self.log() if e.get("event") == "gc_would_stop"]
        self.assertEqual(len(events), 1)

    def test_would_stop_is_deduplicated_for_an_unchanged_scope(self):
        self.d.cfg["mode"] = "observe"
        self.cg.leaf("scope-foo", [301])
        start = time.time()
        now = [start]
        self.d.store.now = lambda: now[0]
        for minute in range(24 * 60):
            now[0] = start + minute * 60
            self.d.stop_leaf("scope-foo", "owner exited")

        events = [
            e
            for e in self.log()
            if e.get("event") == "would_stop" and e.get("scope") == "scope-foo"
        ]
        self.assertEqual(len(events), 1)
        now[0] = start + knowledge.DAY
        self.d.stop_leaf("scope-foo", "owner exited")
        events = [
            e
            for e in self.log()
            if e.get("event") == "would_stop" and e.get("scope") == "scope-foo"
        ]
        self.assertEqual(len(events), 1)

    def test_gc_pass_dry_run_stops_nothing(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        self.d.gc_pass(dry_run=True)
        self.stopm.assert_not_called()

    def test_empty_leftover_leaf_removed_on_second_pass(self):
        os.makedirs(self.cg.base + "/leftover/z")
        self.d.gc_pass()
        self.assertTrue(os.path.isdir(self.cg.base + "/leftover/z"))
        self.d.gc_pass()
        self.assertFalse(os.path.isdir(self.cg.base + "/leftover/z"))


# ---- 6. logout --------------------------------------------------------------------------------


class Logout(AutoCase):
    def test_auto_keeps_everything_but_confident_stop_pairs(self):
        up = self.fp.up
        self.fp.add(200, 1, comm="foo", born=up - 100)
        self.fp.add(201, 200, comm="tmux", born=up - 90)
        self.fp.add(301, 1, comm="vite", sid=301, born=up - 100)
        self.fp.add(302, 1, comm="nohup", sid=302, born=up - 100)
        self.d.lineage.observe(self.fp.table())
        for p in (301, 302):
            self.d.lineage.entry(p)["root_key"] = "foo"
        self.idle(200, 201, 301, 302)
        self.cg.leaf("app-foo-abc123", [200, 201])
        self.cg.leaf("leftover/a", [301])
        self.cg.leaf("leftover/b", [302])
        self.cg.leaf("shared/s", [])
        self.d.store.answer("foo", "vite", "stop")  # leftover/a: confident
        self.d.store.answer("foo", "nohup", "keep")  # leftover/b: keep
        self.d.store.answer(
            "foo", "tmux", "stop"
        )  # app scope still holds its root: kept
        self.d.end_session()
        stopped = [c[0][0] for c in self.stopm.call_args_list]
        self.assertEqual(
            [os.path.relpath(p, self.cg.base) for p in stopped], ["leftover/a"]
        )
        kept = [e["scope"] for e in self.log() if e["event"] == "session_end_kept"]
        self.assertIn("app-foo-abc123", kept)
        self.assertIn("leftover/b", kept)
        self.assertFalse(self.d.session_seen)

    def test_other_modes_unchanged(self):
        self.d.cfg["mode"] = "observe"
        self.cg.leaf("app-foo-abc123", [200])
        self.d.end_session()
        self.stopm.assert_not_called()
        self.assertIn("would_stop", [e["event"] for e in self.log()])
        self.d.cfg["mode"] = "enforce"
        self.d.end_session()
        self.stopm.assert_called_once()


# ---- 7. attach command, cli fallback, status --------------------------------------------------


class Attach(ProcCase):
    def setUp(self):
        super().setUp()
        self.d = daemon.Daemon(make_cfg(tmp(), mode="auto"))
        self.fp.add(20, 1, comm="bash", sid=20, born=1000.0)
        self.fp.add(21, 20, comm="x", born=1000.0)

    def att(self, **kw):
        return self.d.handle(
            dict({"cmd": "attach", "scope": "scope-foo", "pids": [20]}, **kw)
        )

    def test_valid_attach_calls_helper_per_pid(self):
        with mock.patch.object(engine, "helper_attach") as ha:
            r = self.att(pids=[20, 21, 20])
        self.assertEqual(r, {"ok": True, "attached": [20, 21]})
        self.assertEqual(
            [c[0][1:] for c in ha.call_args_list], [(20, "foo"), (21, "foo")]
        )
        with mock.patch.object(engine, "helper_attach"):
            self.assertTrue(self.att(scope="foo")["ok"])

    def test_shapes_and_foreign_pids_refused(self):
        bad = [
            {"scope": 5},
            {"scope": "Scope-X"},
            {"scope": "scope-a/b"},
            {"scope": "../x"},
            {"scope": "scope-" + "a" * 40},
            {"pids": []},
            {"pids": "20"},
            {"pids": [True]},
            {"pids": [1]},
            {"pids": [0]},
            {"pids": ["20"]},
            {"pids": list(range(2, 67))},
            {"pids": None},
        ]
        with mock.patch.object(engine, "helper_attach") as ha:
            for patch in bad:
                self.assertIn("error", self.att(**patch), patch)
            self.assertIn("error", self.att(pids=[20, 999999]))  # gone / not ours
            self.assertIn("error", self.d.handle({"cmd": "attach"}))
            ha.assert_not_called()

    def test_foreign_uid_refused(self):
        with (
            mock.patch.object(inspect, "uid_of", return_value=UID + 1),
            mock.patch.object(engine, "helper_attach") as ha,
        ):
            self.assertIn("not yours", self.att()["error"])
            ha.assert_not_called()

    def test_helper_refusal_is_an_error(self):
        with mock.patch.object(
            engine, "helper_attach", side_effect=engine.Refused("nope")
        ):
            self.assertIn("nope", self.att()["error"])


class CliRun(unittest.TestCase):
    def run_cmd(self, err, reply):
        cg = FakeCg()
        cg.__enter__()
        self.addCleanup(cg.__exit__)
        a = argparse.Namespace(
            name="foo", join=False, owner=None, bind=False, cmd=["true"]
        )
        asks = []
        cfg = make_cfg(tmp())
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
            mock.patch.object(
                cli,
                "ask",
                side_effect=lambda c, m, timeout=3.0: asks.append(m) or reply,
            ),
            mock.patch.object(engine, "helper_attach", side_effect=err),
            mock.patch.object(os, "execvp") as ex,
            mock.patch("sys.stderr", new=io.StringIO()),
        ):
            rc = cli.cmd_run(a)
        return rc, asks, ex

    def test_sudo_failure_falls_back_to_daemon(self):
        rc, asks, ex = self.run_cmd(
            engine.Refused("sudo: a password is required"), {"ok": True}
        )
        self.assertEqual(
            asks[-1], {"cmd": "attach", "scope": "scope-foo", "pids": [os.getpid()]}
        )
        ex.assert_called_once()

    def test_daemon_refusal_fails_the_run(self):
        rc, asks, ex = self.run_cmd(
            engine.Refused("sudo: a password is required"), {"error": "no"}
        )
        self.assertEqual(rc, 1)
        ex.assert_not_called()

    def test_helper_own_refusal_does_not_use_daemon(self):
        rc, asks, ex = self.run_cmd(engine.Refused("pid is not yours"), {"ok": True})
        self.assertEqual(rc, 1)
        self.assertFalse([m for m in asks if m["cmd"] == "attach"])


class AdoptAll(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.session = self.cg.root + "/2"
        os.makedirs(self.session)
        self.cfg = make_cfg(tmp(), mode="adopt", protected={"comm": ["niri*"]})
        self.cfg["paths"]["session_cgroup"] = self.session
        self.fp.add(100, 1, comm="niri", sid=100, born=100.0)
        self.fp.add(200, 100, comm="firefox", born=100.0)
        self.fp.add(201, 200, comm="web", born=101.0)
        with open(self.session + "/cgroup.procs", "w") as f:
            f.write("200\n201\n")
        self.store = knowledge.Store(tmp(), {}, read_only=True)

    def test_adopt_all_includes_unknown_app_roots_and_honors_dry_run(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(engine, "helper_move") as hm,
            mock.patch.object(cgroup, "proc_cgroup", return_value="/2"),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.main(["adopt", "--all", "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertIn("app-firefox-", out.getvalue())
            self.assertIn("nothing moved", out.getvalue())
            self.assertEqual(
                [name for name in os.listdir(self.cg.base) if name.startswith("app-")],
                [],
            )
            hm.assert_not_called()

            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.main(["adopt", "--all"])
        self.assertEqual(rc, 0)
        self.assertIn("done", out.getvalue())
        scopes = [name for name in os.listdir(self.cg.base) if name.startswith("app-")]
        self.assertEqual(len(scopes), 1)
        hm.assert_called_once()


class StatusAndModes(ProcCase):
    def test_status_shows_auto_block_and_authority(self):
        d = daemon.Daemon(make_cfg(tmp(), mode="auto"))
        d.store.answer("npm", "vite", "stop")
        d.store.answer("npm", "tool", "standalone")
        for i in range(7):
            d.note_auto_stop("s%d" % i, "why %d" % i, [("npm", "vite")])
        r = d.handle({"cmd": "status"})
        self.assertEqual(r["mode"], "auto")
        self.assertEqual(r["authority"], "learned")
        self.assertEqual(r["authority_source"], "mode default for auto")
        self.assertEqual(
            [s["scope"] for s in r["auto"]["auto_stops"]],
            ["s%d" % i for i in range(2, 7)],
        )
        self.assertEqual(
            (r["pairs"][0]["action"], r["pairs"][0]["confidence"]), ("stop", 1.0)
        )
        self.assertEqual(r["standalone"], ["tool"])
        out = io.StringIO()
        with redirect_stdout(out):
            cli.print_auto(r["auto"])
        self.assertIn("0 auto-adopted scopes", out.getvalue())
        self.assertEqual(out.getvalue().count("auto stop "), 5)
        self.assertIn("why 6", out.getvalue())

    def test_status_prints_auto_scope_count_in_every_mode(self):
        expected_authorities = {
            "observe": "learned",
            "adopt": "answered",
            "enforce": "unit",
            "auto": "learned",
        }
        for mode in ("observe", "adopt", "enforce", "auto"):
            cfg = make_cfg(tmp(), mode=mode)
            d = daemon.Daemon(cfg)
            d.auto_scopes.add("app-firefox-deadbeef")
            reply = d.handle({"cmd": "status"})
            out = io.StringIO()
            with (
                mock.patch.object(cli, "_load_status", return_value=(cfg, d.store)),
                mock.patch.object(cli, "ask", return_value=reply),
                redirect_stdout(out),
            ):
                rc = cli.cmd_status(argparse.Namespace())
            self.assertEqual(rc, 0, mode)
            self.assertIn("1 auto-adopted scopes", out.getvalue(), mode)
            self.assertIn("authority: " + expected_authorities[mode], out.getvalue())
            self.assertIn(
                "mode default" if mode != "enforce" else "unit rules", out.getvalue()
            )

    def test_status_avoids_guard_import_when_daemon_reports_guard(self):
        cfg = make_cfg(tmp(), mode="auto")
        d = daemon.Daemon(cfg)
        reply = d.handle({"cmd": "status"})
        self.assertIn("guard", reply)
        saved_module = sys.modules.pop("taema.governor.guard", None)
        saved_global = cli._pressure_guard
        cli._pressure_guard = cli._LazyModule("_pressure_guard", "taema.governor.guard")
        try:
            out = io.StringIO()
            with (
                mock.patch.object(cli, "_load_status", return_value=(cfg, d.store)),
                mock.patch.object(cli, "ask", return_value=reply),
                redirect_stdout(out),
            ):
                rc = cli.cmd_status(argparse.Namespace())
            self.assertEqual(rc, 0)
            self.assertNotIn("taema.governor.guard", sys.modules)
            self.assertIsInstance(cli._pressure_guard, cli._LazyModule)
        finally:
            cli._pressure_guard = saved_global
            if saved_module is not None:
                sys.modules["taema.governor.guard"] = saved_module

    def _complete_status_reply(self):
        cfg = make_cfg(tmp(), mode="auto")
        d = daemon.Daemon(cfg)
        reply = d.handle({"cmd": "status"})
        for key in (
            "mode",
            "authority",
            "authority_source",
            "profile",
            "profile_reason",
            "feedback_invalid",
            "hold",
            "hold_state",
            "guard",
            "config",
            "mem_enabled",
        ):
            self.assertIn(key, reply)
        return reply

    def _unload_cli_modules(self, *names):
        saved_modules = {}
        saved_globals = {}
        global_names = {
            "taema.config.policy": "policy",
            "taema.store.knowledge": "knowledge",
            "taema.governor.guard": "_pressure_guard",
        }
        for name in names:
            saved_modules[name] = sys.modules.pop(name, None)
            global_name = global_names[name]
            saved_globals[name] = getattr(cli, global_name)
            setattr(cli, global_name, cli._LazyModule(global_name, name))
        return saved_modules, saved_globals

    def _restore_cli_modules(self, saved_modules, saved_globals):
        global_names = {
            "taema.config.policy": "policy",
            "taema.store.knowledge": "knowledge",
            "taema.governor.guard": "_pressure_guard",
        }
        for name, module in saved_modules.items():
            setattr(cli, global_names[name], saved_globals[name])
            if module is not None:
                sys.modules[name] = module
            else:
                sys.modules.pop(name, None)

    def test_status_fast_path_skips_config_load(self):
        from taema.cli import framework

        reply = self._complete_status_reply()
        saved = self._unload_cli_modules(
            "taema.config.policy", "taema.store.knowledge", "taema.governor.guard"
        )
        try:
            out = io.StringIO()
            with (
                mock.patch.object(cli, "_ask_paths", return_value=reply),
                mock.patch.object(cli, "_load_status") as loader,
                redirect_stdout(out),
            ):
                rc = cli.cmd_status(framework._fast_status_args(["status"]))
            self.assertEqual(rc, 0)
            loader.assert_not_called()
            self.assertNotIn("taema.config.policy", sys.modules)
            self.assertNotIn("taema.store.knowledge", sys.modules)
            self.assertNotIn("taema.governor.guard", sys.modules)
            self.assertIn("auto", out.getvalue())
        finally:
            self._restore_cli_modules(*saved)

    def test_status_fast_path_falls_back_when_probe_misses(self):
        from taema.cli import framework

        reply = self._complete_status_reply()
        cfg = make_cfg(tmp(), mode="auto")
        out = io.StringIO()
        with (
            mock.patch.object(cli, "_ask_paths", return_value=None),
            mock.patch.object(cli, "_load_status", return_value=(cfg, None)) as loader,
            mock.patch.object(cli, "ask", return_value=reply),
            redirect_stdout(out),
        ):
            rc = cli.cmd_status(framework._fast_status_args(["status"]))
        self.assertEqual(rc, 0)
        loader.assert_called_once()
        self.assertIn("auto", out.getvalue())

    def test_status_fast_path_skipped_with_overrides(self):
        from taema.cli import framework

        reply = self._complete_status_reply()
        cfg = make_cfg(tmp(), mode="auto")
        for argv in (
            ["status", "--socket", "/tmp/x.sock"],
            ["status", "--config", "/tmp/y.toml"],
        ):
            out = io.StringIO()
            with (
                mock.patch.object(cli, "_ask_paths") as probe,
                mock.patch.object(cli, "_load_status", return_value=(cfg, None)),
                mock.patch.object(cli, "ask", return_value=reply),
                redirect_stdout(out),
            ):
                rc = cli.cmd_status(framework._fast_status_args(argv))
            self.assertEqual(rc, 0)
            probe.assert_not_called()
        with mock.patch.dict(os.environ, {"TAEMA_CONFIG": "/tmp/z.toml"}):
            out = io.StringIO()
            with (
                mock.patch.object(cli, "_ask_paths") as probe,
                mock.patch.object(cli, "_load_status", return_value=(cfg, None)),
                mock.patch.object(cli, "ask", return_value=reply),
                redirect_stdout(out),
            ):
                rc = cli.cmd_status(framework._fast_status_args(["status"]))
            self.assertEqual(rc, 0)
            probe.assert_not_called()

    def test_status_fast_path_falls_back_on_incomplete_reply(self):
        from taema.cli import framework

        reply = self._complete_status_reply()
        del reply["guard"]
        cfg = make_cfg(tmp(), mode="auto")
        out = io.StringIO()
        with (
            mock.patch.object(cli, "_ask_paths", return_value=reply),
            mock.patch.object(cli, "_load_status", return_value=(cfg, None)) as loader,
            mock.patch.object(cli, "ask", return_value=reply),
            redirect_stdout(out),
        ):
            rc = cli.cmd_status(framework._fast_status_args(["status"]))
        self.assertEqual(rc, 0)
        loader.assert_called_once()

    def test_status_fast_path_matches_slow_path_output(self):
        import copy
        from taema.cli import framework

        reply = self._complete_status_reply()
        cfg = make_cfg(tmp(), mode="auto")
        fast_out = io.StringIO()
        with (
            mock.patch.object(cli, "_ask_paths", return_value=copy.deepcopy(reply)),
            mock.patch.object(cli, "_load_status") as loader,
            redirect_stdout(fast_out),
        ):
            fast_rc = cli.cmd_status(framework._fast_status_args(["status"]))
        loader.assert_not_called()
        slow_out = io.StringIO()
        with (
            mock.patch.object(cli, "_ask_paths", return_value=None),
            mock.patch.object(cli, "_load_status", return_value=(cfg, None)),
            mock.patch.object(cli, "ask", return_value=copy.deepcopy(reply)),
            redirect_stdout(slow_out),
        ):
            slow_rc = cli.cmd_status(framework._fast_status_args(["status"]))
        self.assertEqual((fast_rc, fast_out.getvalue()), (slow_rc, slow_out.getvalue()))

    def test_status_fast_path_honors_mem_disabled(self):
        from taema.cli import framework

        reply = self._complete_status_reply()
        reply["mem_enabled"] = False
        out = io.StringIO()
        with (
            mock.patch.object(cli, "_ask_paths", return_value=reply),
            mock.patch.object(
                cli, "_memory_snapshot", wraps=cli._memory_snapshot
            ) as snapshot,
            redirect_stdout(out),
        ):
            rc = cli.cmd_status(framework._fast_status_args(["status"]))
        self.assertEqual(rc, 0)
        snapshot.assert_called_once()
        self.assertEqual(snapshot.call_args[0][0], {"mem": {"enabled": False}})

    def test_mode_gates(self):
        want = {
            "observe": (False, False),
            "adopt": (True, False),
            "enforce": (True, True),
            "auto": (True, False),
        }
        for mode, (mv, kl) in want.items():
            d = daemon.Daemon(make_cfg(tmp(), mode=mode))
            self.assertEqual((d.may_move(), d.may_kill()), (mv, kl), mode)

    def test_status_marks_invalid_owner_pairs(self):
        d = daemon.Daemon(make_cfg(tmp(), mode="auto"))
        for k in ("sh", "sort", "head"):
            d.store.data["pairs"][d.store.pkey("MainThread", k)] = {
                "first_seen": 1000.0,
                "ex_stop": knowledge.W_ANSWER,
                "ex_last": "stop",
            }
        r = d.handle({"cmd": "status"})
        rows = {(p["owner"], p["leftover"]): p for p in r["pairs"]}
        for k in ("sh", "sort", "head"):
            self.assertEqual(rows[("MainThread", k)]["action"], "invalid", k)
            self.assertIn("invalid owner", rows[("MainThread", k)]["why"], k)
        out = io.StringIO()
        with redirect_stdout(out):
            cli.print_pairs(r["pairs"])
        self.assertIn("invalid", out.getvalue())

    def test_load_config_accepts_auto_and_default_stays_observe(self):
        p = tmp() + "/c.toml"
        with open(p, "w") as f:
            f.write('mode = "auto"\n')
        self.assertEqual(policy.load_config(p)["mode"], "auto")
        with open(p, "w") as f:
            f.write("")
        self.assertEqual(policy.load_config(p)["mode"], "observe")
        with open(p, "w") as f:
            f.write('mode = "yolo"\n')
        with self.assertRaises(ValueError):
            policy.load_config(p)

    def test_adopt_pass_auto_adopts_in_adopt_enforce_and_auto_modes(self):
        for mode in ("adopt", "enforce", "auto"):
            d = daemon.Daemon(make_cfg(tmp(), mode=mode))
            with (
                mock.patch.object(d, "auto_adopt") as aa,
                mock.patch.object(
                    inspect.ProcTable, "scan", return_value=inspect.ProcTable()
                ),
            ):
                d.adopt_pass()
            aa.assert_called_once()

    def test_cpu_pct_from_samples(self):
        lin = Lineage(make_cfg(tmp()))
        self.fp.add(5, 1, comm="x")
        lin.observe(self.fp.table(), now=self.fp.up, uptime=self.fp.up)
        e = lin.entry(5)
        e["cpu"] = [(0.0, 0), (60.0, 60 * HZ)]
        self.assertAlmostEqual(lin.cpu_pct(5), 100.0)
        e["cpu"] = [(0.0, 0), (60.0, 30 * HZ // 100)]
        self.assertAlmostEqual(lin.cpu_pct(5), 0.5)
        e["cpu"] = [(50.0, 0), (60.0, 5)]  # 10 s of history: unknown
        self.assertIsNone(lin.cpu_pct(5))
        self.assertIsNone(lin.cpu_pct(99))

    def test_proc_stat_cpu_ticks_are_parsed(self):
        row = inspect._parse_stat(
            b"7 (a b) S 1 7 7 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 4242 0 0\n"
        )
        self.assertEqual((row.cpu, row.start), (150, 4242))


if __name__ == "__main__":
    unittest.main()
