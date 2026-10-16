"""Phase 4 tests (auto mode): app-root adoption, pair authority, auto stops, leftover leaves, logout,
the attach socket command and status. Fake /proc and cgroup trees; no real signal is ever sent."""
import argparse
import io
import json
import os
import time
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema import cgroup, cli, daemon, engine, inspect, knowledge, policy
from taema.lineage import HZ, Lineage
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
        s.data["pairs"][s.pkey("npm", "vite")]["first_seen"] = t[0] - 2 * DAY
        return s

    def test_explicit_stop_acts(self):
        s = store()
        s.answer("npm", "vite", "stop")
        self.assertTrue(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        self.assertTrue(s.pair_explicit("npm", "vite"))

    def test_ask_keep_standalone_never_act(self):
        s = store()
        self.assertFalse(engine.auto_stop_ok(s, "npm", "vite", mi())[0])         # no evidence: ask
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
        young = self.silent_store(age_days=1)           # store younger than 7 days and < 20 closes
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
        self.assertFalse(ok(cpu=5.0)[0])                # busier than 1 %
        self.assertFalse(ok(cpu=None)[0])               # unknown keeps
        self.assertFalse(ok(edges=[{"kind": "unix_server"}])[0])
        self.assertFalse(ok(edges=None)[0])
        self.assertFalse(ok(protected="protected comm niri")[0])
        self.assertFalse(ok(ptmx=True)[0])
        self.assertFalse(ok(origin="")[0])
        self.assertFalse(ok("tmux")[0])                 # persist seed, even answered stop
        self.assertTrue(ok("adb")[0])                   # share seed alone may stop ...
        s.apply_op("keep", "adb")
        self.assertFalse(ok("adb")[0])                  # ... not once the user keeps it

    def test_regret_suspends_the_pair(self):
        s = store()
        s.answer("npm", "vite", "stop")
        s.auto_stopped("npm", "vite")
        self.assertTrue(s.regret("npm", "vite"))
        self.assertEqual(s.pair_decision("npm", "vite")[0], "ask")
        self.assertFalse(engine.auto_stop_ok(s, "npm", "vite", mi())[0])
        self.assertFalse(s.regret("npm", "vite"))       # only once per auto stop

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
        plan = [{"pid": 5, "comm": "x", "key": "x", "edges": [], "action": "kill", "why": "t"}]
        with mock.patch.object(engine, "plan_stop", return_value=plan), \
             mock.patch.object(engine, "self_guard"), \
             mock.patch.object(engine.inspect.ProcTable, "scan", return_value=inspect.ProcTable()), \
             mock.patch.object(engine, "_signal_all", side_effect=lambda p, pids, sig, cfg: sent.append(sig) or []), \
             mock.patch.object(engine, "_wait_each", return_value={}), \
             mock.patch.object(engine.cgroup, "rmdir_tree", side_effect=OSError("busy")), \
             mock.patch.object(engine.cgroup, "tree_procs", return_value=[5]):
            rep = engine.stop("/x/user/1/y", {"timers": {}}, store(), timeout=1, allow_sigkill=allow)
        return sent, rep

    def test_sigkill_only_when_allowed(self):
        import signal
        sent, rep = self.run_stop(False)
        self.assertEqual(sent, [signal.SIGTERM])        # one pass, no SIGKILL
        self.assertEqual(rep["unkilled"], [5])
        sent, _ = self.run_stop(True)
        self.assertIn(signal.SIGKILL, sent)


# ---- 3. auto adoption of app roots ------------------------------------------------------------

class AutoAdopt(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.session = self.cg.root + "/2"
        os.makedirs(self.session)
        self.cfg = make_cfg(tmp(), mode="auto", protected={"comm": ["niri*", "niriapp"]})
        self.cfg["paths"]["session_cgroup"] = self.session
        self.fp.add(100, 1, comm="niri", sid=100, born=100.0)       # compositor: session leader, protected
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
        return engine.auto_adopt_plan(self.cfg, list(units), self.fp.table(), lin, store(), cap=cap)

    def test_root_and_descendants_get_one_scope(self):
        self.add(200, comm="firefox")
        self.add(201, 200, comm="web")
        ops = self.plan()
        self.assertEqual(len(ops), 1)
        self.assertRegex(ops[0]["scope"], r"^app-firefox-[0-9a-f]{6}$")
        self.assertEqual(ops[0]["pids"], [200, 201])
        self.assertTrue(cgroup.valid_rel(ops[0]["scope"]))
        self.assertEqual(ops[0]["scope"], self.plan()[0]["scope"])      # stable across passes

    def test_skips(self):
        self.add(210, comm="leader", sid=210)                           # session leader
        self.add(220, comm="niriapp")                                   # protected
        self.add(230, comm="young", born=self.fp.up - 2)                # younger than 5 s
        self.add(240, comm="host", fds=("/dev/ptmx",))                  # pty host
        self.add(250, comm="viewer", tty=34816)                         # on a tty: a terminal job
        self.fp.add(260, 1, comm="bash", sid=260, tty=34816, born=1000.0)
        self.pids.append(260)
        self.add(261, 260, comm="server")                               # child of an interactive shell
        self.add(270, comm="tagged", env={"TAEMA_JOB": "260.1"})        # carries a job tag
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
        unit = {"unit": {"name": "ff", "kind": "app"}, "match": {"exe": "/usr/lib/firefox/firefox"}}
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
        with mock.patch.object(engine, "helper_move") as hm, \
             mock.patch.object(cgroup, "proc_cgroup", return_value="/2"):
            d.auto_adopt(pt)
        self.assertEqual(hm.call_args[0][2], [200, 201])
        self.assertEqual(len(d.auto_scopes), 1)
        self.assertEqual(d.auto_status()["auto_adopted_scopes"], 1)


# ---- 4. job survivors, GUI closes, regret, standalone -----------------------------------------

class AutoCase(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.rt = tmp()
        self.cgmap, self.edges = {}, {}
        for p in (mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.rt}),
                  mock.patch.object(cgroup, "proc_cgroup",
                                    side_effect=lambda p: self.cgmap.get(p, "/user/%d/app-host" % UID)),
                  mock.patch.object(inspect, "Snapshot", return_value=types.SimpleNamespace(ok=True)),
                  mock.patch.object(inspect, "edges", side_effect=lambda m, s=None, pids_info=None: self.edges)):
            p.start()
            self.addCleanup(p.stop)
        self.d = daemon.Daemon(make_cfg(tmp(), mode="auto", seeds={"persist": ["gpg-agent"]},
                                        protected={"comm": ["niri*"]}))
        self.fp.add(20, 1, comm="bash", sid=20, tty=34816, born=1000.0)
        stop = mock.patch.object(engine, "stop", return_value={"removed": True, "decisions": [], "left": []})
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
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "npm"})
        self.d.deadlines.clear()
        if cpu_idle:
            self.idle(30)
        self.d.decide_job("20.1")

    def prime(self):
        self.fp.add(21, 20, comm="npm", env={"TAEMA_JOB": "20.1"}, born=self.fp.up - 6.0, pgrp=21)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)

    def refusals(self):
        return [e["why"] for e in self.log() if e["event"] == "auto_stop_refused"]

    def test_explicit_stop_carves_and_stops_with_sigkill(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.stopm.assert_called_once()
        path, kw = self.stopm.call_args[0][0], self.stopm.call_args[1]
        self.assertTrue(path.endswith("/app-host/job-20-1"), path)
        self.assertTrue(kw["allow_sigkill"])
        self.assertTrue(5 <= kw["timeout"] <= 30)
        with open(path + "/cgroup.procs") as f:
            self.assertEqual(f.read().split(), ["30"])      # carved, no sudo
        self.assertGreater(self.d.store.data["pairs"][knowledge.Store.pkey("npm", "vite")]["last_auto_stop"], 0)
        st = self.d.handle({"cmd": "status"})["auto"]
        self.assertEqual(len(st["auto_stops"]), 1)
        self.assertIn("answered stop", st["auto_stops"][0]["why"])
        self.assertEqual(self.d.auto_recent["vite"][0], "npm")

    def test_silent_pair_never_sigkills(self):
        s = self.d.store
        s.data["created"] -= 30 * DAY
        for day in range(4):
            for _ in range(2):
                s.observe_kill_inferred("npm", "vite", day=day)
        s.data["pairs"][s.pkey("npm", "vite")]["first_seen"] -= 5 * DAY
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
        self.prime()                                    # no cpu history at all: unknown keeps
        self.d.lineage.entry(30)["cpu"] = []
        self.again(cpu_idle=False)
        self.stopm.assert_not_called()
        self.assertIn("cpu unknown", self.refusals())
        self.prime()
        self.edges = {30: [{"kind": "tcp_server", "detail": "x", "peers": [9]}]}
        self.again()
        self.stopm.assert_not_called()
        self.assertIn("has edges", self.refusals())
        self.assertFalse(os.path.exists("%s/app-host/job-20-1" % self.cg.base))   # nothing was carved

    def test_not_under_user_scope_is_signalled_in_place(self):
        self.d.store.answer("npm", "vite", "stop")
        self.cgmap[30] = "/2"
        with mock.patch.object(engine, "signal_survivors") as sig:
            self.job()
        self.stopm.assert_not_called()
        self.assertEqual([i["pid"] for i in sig.call_args[0][1]], [30])
        self.assertTrue(sig.call_args[0][3])            # explicit: SIGKILL allowed

    def test_standalone_adopted_never_stopped(self):
        self.d.store.answer("npm", "vite", "standalone")
        self.cgmap[30] = "/2"
        with mock.patch.object(engine, "helper_move") as hm:
            self.job()
        self.stopm.assert_not_called()
        self.assertEqual(hm.call_args[0][2], [30])
        self.assertRegex(hm.call_args[0][1], r"^app-vite-[0-9a-f]{6}$")
        self.assertEqual(len(self.d.auto_scopes), 1)

    def test_regret_when_key_comes_back_under_any_owner(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")
        self.fp.remove(30)
        self.d.lineage.observe(self.fp.table())
        self.fp.add(60, 1, comm="vite", born=self.fp.up - 1)           # same key, another owner
        self.d.lineage.observe(self.fp.table())
        self.d.after_observe()
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "ask")      # suspended 7 days
        self.assertNotIn("vite", self.d.auto_recent)
        self.assertEqual([e["event"] for e in self.log()].count("regret"), 1)

    def test_regret_window_expires(self):
        self.d.store.answer("npm", "vite", "stop")
        self.d.note_auto_stop("s", "w", [("npm", "vite")])
        self.d.auto_recent["vite"] = ("npm", time.time() - knowledge.REGRET_WINDOW - 5)
        self.fp.add(60, 1, comm="vite", born=self.fp.up - 1)
        self.d.lineage.observe(self.fp.table())
        self.d.check_regret(self.d.lineage, time.time())
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")


class GuiClose(AutoCase):
    def close_gui(self, **root_kw):
        up = self.fp.up
        self.fp.add(100, 1, comm="niri", sid=100, born=100.0)       # parent: roots need a parent entry
        self.fp.add(200, 100, comm="firefox", born=up - 100, **root_kw)
        self.fp.add(201, 200, comm="helper", born=up - 90)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(200)
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

    def test_other_modes_do_not_carve(self):
        self.d.cfg["mode"] = "adopt"
        self.close_gui()
        self.d.after_observe()
        self.assertFalse(os.path.exists(self.cg.base + "/leftover"))

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


# ---- 5. GC rules for leftover/* --------------------------------------------------------------

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
        return engine.gc_candidates(d.cfg, [], d.store, d.idle_since, now=lambda: t, usage=d.gc_usage,
                                    skip=d.gc_skip, noted=d.gc_noted, lin=d.lineage, auto=auto)

    def test_pair_stop_candidate(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        (path, why), = self.cands()
        self.assertTrue(path.endswith("leftover/x"))
        self.assertTrue(why.startswith("pair stop"))

    def test_idle_for_learned_grace_then_stop(self):
        self.leaf()
        self.assertEqual(self.cands(t=0), [])
        self.assertEqual(self.cands(t=300), [])
        (path, why), = self.cands(t=601)
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
        self.d.store.answer("foo", "vite", "keep")              # pair decided keep
        self.assertEqual(self.cands(t=0) + self.cands(t=9999), [])
        self.d.store.answer("foo", "vite", "stop")
        self.assertEqual(len(self.cands(t=0)), 1)
        self.d.lineage.entry(301)["host"] = True                # pty host
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
        self.assertEqual(self.cands(t=0, auto=False) + self.cands(t=9999, auto=False), [])
        self.cg.leaf("leftover/y", [])
        got = self.cands(auto=False)
        self.assertEqual([(os.path.basename(p), w) for p, w in got], [("y", "empty")])

    def test_gc_pass_stops_by_pair_with_sigkill_only_if_explicit(self):
        self.leaf()
        self.d.store.answer("foo", "vite", "stop")
        res = self.d.gc_pass()
        self.assertEqual(res[0][2], "stop")
        self.stopm.assert_called_once()
        self.assertTrue(self.stopm.call_args[1]["allow_sigkill"])
        self.assertEqual(len(self.d.auto_stops), 1)
        self.assertFalse(self.d.may_kill())

    def test_gc_pass_idle_stop_never_sigkills(self):
        self.leaf()
        self.d.idle_since["leftover/x"] = time.time() - 5000
        self.d.gc_usage["leftover/x"] = 100
        self.d.gc_pass()
        self.stopm.assert_called_once()
        self.assertFalse(self.stopm.call_args[1]["allow_sigkill"])

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
        self.d.store.answer("foo", "vite", "stop")          # leftover/a: confident
        self.d.store.answer("foo", "nohup", "keep")         # leftover/b: keep
        self.d.store.answer("foo", "tmux", "stop")          # app scope still holds its root: kept
        self.d.end_session()
        stopped = [c[0][0] for c in self.stopm.call_args_list]
        self.assertEqual([os.path.relpath(p, self.cg.base) for p in stopped], ["leftover/a"])
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
        return self.d.handle(dict({"cmd": "attach", "scope": "scope-foo", "pids": [20]}, **kw))

    def test_valid_attach_calls_helper_per_pid(self):
        with mock.patch.object(engine, "helper_attach") as ha:
            r = self.att(pids=[20, 21, 20])
        self.assertEqual(r, {"ok": True, "attached": [20, 21]})
        self.assertEqual([c[0][1:] for c in ha.call_args_list], [(20, "foo"), (21, "foo")])
        with mock.patch.object(engine, "helper_attach"):
            self.assertTrue(self.att(scope="foo")["ok"])

    def test_shapes_and_foreign_pids_refused(self):
        bad = [{"scope": 5}, {"scope": "Scope-X"}, {"scope": "scope-a/b"}, {"scope": "../x"},
               {"scope": "scope-" + "a" * 40}, {"pids": []}, {"pids": "20"}, {"pids": [True]}, {"pids": [1]},
               {"pids": [0]}, {"pids": ["20"]}, {"pids": list(range(2, 67))}, {"pids": None}]
        with mock.patch.object(engine, "helper_attach") as ha:
            for patch in bad:
                self.assertIn("error", self.att(**patch), patch)
            self.assertIn("error", self.att(pids=[20, 999999]))      # gone / not ours
            self.assertIn("error", self.d.handle({"cmd": "attach"}))
            ha.assert_not_called()

    def test_foreign_uid_refused(self):
        with mock.patch.object(inspect, "uid_of", return_value=UID + 1), \
             mock.patch.object(engine, "helper_attach") as ha:
            self.assertIn("not yours", self.att()["error"])
            ha.assert_not_called()

    def test_helper_refusal_is_an_error(self):
        with mock.patch.object(engine, "helper_attach", side_effect=engine.Refused("nope")):
            self.assertIn("nope", self.att()["error"])


class CliRun(unittest.TestCase):
    def run_cmd(self, err, reply):
        cg = FakeCg()
        cg.__enter__()
        self.addCleanup(cg.__exit__)
        a = argparse.Namespace(name="foo", join=False, owner=None, bind=False, cmd=["true"])
        asks = []
        cfg = make_cfg(tmp())
        with mock.patch.object(cli, "_load", return_value=(cfg, None, [])), \
             mock.patch.object(cli, "ask", side_effect=lambda c, m, timeout=3.0: asks.append(m) or reply), \
             mock.patch.object(engine, "helper_attach", side_effect=err), \
             mock.patch.object(os, "execvp") as ex, \
             mock.patch("sys.stderr", new=io.StringIO()):
            rc = cli.cmd_run(a)
        return rc, asks, ex

    def test_sudo_failure_falls_back_to_daemon(self):
        rc, asks, ex = self.run_cmd(engine.Refused("sudo: a password is required"), {"ok": True})
        self.assertEqual(asks[-1], {"cmd": "attach", "scope": "scope-foo", "pids": [os.getpid()]})
        ex.assert_called_once()

    def test_daemon_refusal_fails_the_run(self):
        rc, asks, ex = self.run_cmd(engine.Refused("sudo: a password is required"), {"error": "no"})
        self.assertEqual(rc, 1)
        ex.assert_not_called()

    def test_helper_own_refusal_does_not_use_daemon(self):
        rc, asks, ex = self.run_cmd(engine.Refused("pid is not yours"), {"ok": True})
        self.assertEqual(rc, 1)
        self.assertFalse([m for m in asks if m["cmd"] == "attach"])


class StatusAndModes(ProcCase):
    def test_status_shows_auto_block_and_authority(self):
        d = daemon.Daemon(make_cfg(tmp(), mode="auto"))
        d.store.answer("npm", "vite", "stop")
        d.store.answer("npm", "tool", "standalone")
        for i in range(7):
            d.note_auto_stop("s%d" % i, "why %d" % i, [("npm", "vite")])
        r = d.handle({"cmd": "status"})
        self.assertEqual(r["mode"], "auto")
        self.assertEqual([s["scope"] for s in r["auto"]["auto_stops"]], ["s%d" % i for i in range(2, 7)])
        self.assertEqual((r["pairs"][0]["action"], r["pairs"][0]["confidence"]), ("stop", 1.0))
        self.assertEqual(r["standalone"], ["tool"])
        out = io.StringIO()
        with redirect_stdout(out):
            cli.print_auto(r["auto"])
        self.assertIn("0 auto-adopted scopes", out.getvalue())
        self.assertEqual(out.getvalue().count("auto stop "), 5)
        self.assertIn("why 6", out.getvalue())

    def test_mode_gates(self):
        want = {"observe": (False, False), "adopt": (True, False), "enforce": (True, True), "auto": (True, False)}
        for mode, (mv, kl) in want.items():
            d = daemon.Daemon(make_cfg(tmp(), mode=mode))
            self.assertEqual((d.may_move(), d.may_kill()), (mv, kl), mode)

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

    def test_non_auto_adopt_pass_never_auto_adopts(self):
        d = daemon.Daemon(make_cfg(tmp(), mode="adopt"))
        with mock.patch.object(d, "auto_adopt") as aa, \
             mock.patch.object(inspect.ProcTable, "scan", return_value=inspect.ProcTable()):
            d.adopt_pass()
        aa.assert_not_called()

    def test_cpu_pct_from_samples(self):
        lin = Lineage(make_cfg(tmp()))
        self.fp.add(5, 1, comm="x")
        lin.observe(self.fp.table(), now=self.fp.up, uptime=self.fp.up)
        e = lin.entry(5)
        e["cpu"] = [(0.0, 0), (60.0, 60 * HZ)]
        self.assertAlmostEqual(lin.cpu_pct(5), 100.0)
        e["cpu"] = [(0.0, 0), (60.0, 30 * HZ // 100)]
        self.assertAlmostEqual(lin.cpu_pct(5), 0.5)
        e["cpu"] = [(50.0, 0), (60.0, 5)]           # 10 s of history: unknown
        self.assertIsNone(lin.cpu_pct(5))
        self.assertIsNone(lin.cpu_pct(99))

    def test_proc_stat_cpu_ticks_are_parsed(self):
        row = inspect._parse_stat(b"7 (a b) S 1 7 7 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 4242 0 0\n")
        self.assertEqual((row.cpu, row.start), (150, 4242))


if __name__ == "__main__":
    unittest.main()
