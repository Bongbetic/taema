"""Phase 2 tests: interpreter-aware keys, lineage, knowledge schema v2, pair decisions, job_done flow."""
import json
import os
import time
import unittest
from unittest import mock

from taema import daemon, inspect, knowledge, lineage, policy
from taema.lineage import HZ, Lineage
from tests.test_phase0 import FakeCg, make_cfg, tmp

DAY = 86400.0


# ---- fake /proc ---------------------------------------------------------------------------------

class FakeProc:
    """A /proc under a temp dir. add(pid, ppid, ...) writes stat/comm/exe/cmdline/environ/fd."""

    def __init__(self):
        self.root = tmp()
        self.patch = mock.patch.object(inspect, "PROC", self.root)
        self.patch.start()
        self.up = 10000.0
        self.set_uptime(self.up)

    def stop(self):
        self.patch.stop()

    def set_uptime(self, up):
        self.up = up
        with open(self.root + "/uptime", "w") as f:
            f.write("%.2f 0.0\n" % up)

    def add(self, pid, ppid, comm="x", exe=None, argv=None, env=None, born=None, sid=None, pgrp=None,
            tty=0, state="S", fds=()):
        """born: seconds since boot at which the process started (default: 100 s ago)."""
        d = "%s/%d" % (self.root, pid)
        os.makedirs(d + "/fd", exist_ok=True)
        start = int((self.up - 100 if born is None else born) * HZ)
        with open(d + "/stat", "w") as f:
            f.write("%d (%s) %s %d %d %d %d -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n" % (
                pid, comm, state, ppid, pgrp or pid, 7 if sid is None else sid, tty, start))
        with open(d + "/comm", "w") as f:
            f.write(comm + "\n")
        for n in ("exe",):
            if os.path.lexists(d + "/exe"):
                os.unlink(d + "/exe")
            os.symlink(exe or "/usr/bin/" + comm, d + "/exe")
        with open(d + "/cmdline", "wb") as f:
            f.write(b"\0".join(a.encode() for a in (argv or [comm])) + b"\0")
        with open(d + "/environ", "wb") as f:
            f.write(b"\0".join(("%s=%s" % kv).encode() for kv in (env or {}).items()) + b"\0")
        for i, t in enumerate(fds):
            os.symlink(t, "%s/fd/%d" % (d, i + 3))
        return start

    def remove(self, pid):
        import shutil
        shutil.rmtree("%s/%d" % (self.root, pid))

    def table(self):
        return inspect.ProcTable.scan()


class ProcCase(unittest.TestCase):
    def setUp(self):
        self.fp = FakeProc()
        self.addCleanup(self.fp.stop)


def lin(cfg=None, **kw):
    return Lineage(cfg or make_cfg(tmp()), **kw)


# ---- 1. app_key -------------------------------------------------------------------------------------

class AppKey(ProcCase):
    def key(self, comm, exe, argv):
        self.fp.add(50, 1, comm=comm, exe=exe, argv=argv)
        return policy.app_key(50)

    def test_node_script(self):
        self.assertEqual(self.key("node", "/usr/bin/node", ["node", "--inspect", "/x/y/vite.js", "dev"]), "node:vite.js")

    def test_python_module_and_script(self):
        self.assertEqual(self.key("python3.12", "/usr/bin/python3.12", ["python3", "-u", "-m", "http.server", "8"]),
                         "python3:http.server")
        self.assertEqual(self.key("python3", "/usr/bin/python3", ["python3", "/a/b/run.py"]), "python3:run.py")

    def test_java_jar_and_class(self):
        self.assertEqual(self.key("java", "/usr/bin/java", ["java", "-Xmx1g", "-jar", "/o/app.jar"]), "java:app.jar")
        self.assertEqual(self.key("java", "/usr/bin/java", ["java", "-cp", "lib/*", "com.Main"]), "java:com.Main")

    def test_inline_code_and_bare_interpreter(self):
        self.assertEqual(self.key("bash", "/usr/bin/bash", ["bash", "-c", "echo hi"]), "bash")
        self.assertEqual(self.key("node", "/usr/bin/node", ["node"]), "node")

    def test_process_title_wins(self):
        self.assertEqual(self.key("eslint_d", "/usr/bin/node", ["eslint_d", "x.js"]), "eslint_d")

    def test_not_an_interpreter_and_exe_key_unchanged(self):
        self.assertEqual(self.key("firefox", "/usr/lib/firefox/firefox", ["firefox"]), "firefox")
        self.assertEqual(policy.exe_key(50), "firefox")
        self.fp.add(51, 1, comm="node", exe="/usr/bin/node", argv=["node", "vite.js"])
        self.assertEqual(policy.exe_key(51), "node")        # v1 key still the bare interpreter

    def test_exe_gone_falls_back_to_comm(self):
        self.fp.add(52, 1, comm="kthing")
        os.unlink(self.fp.root + "/52/exe")
        self.assertEqual(policy.app_key(52), "kthing")


# ---- 2. lineage ----------------------------------------------------------------------------------------

class LineageTests(ProcCase):
    def obs(self, l, up=None):
        if up is not None:
            self.fp.set_uptime(up)
        l.observe(self.fp.table(), now=self.fp.up, uptime=self.fp.up)

    def shell(self, pid=20):
        self.fp.add(pid, 1, comm="bash", sid=pid, tty=34816, born=1000)

    def test_prune_and_pid_reuse(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="app", born=9000)
        self.obs(l)
        self.assertIn((21, int(9000 * HZ)), l.entries)
        self.fp.add(21, 20, comm="other", born=9500)        # same pid, new start
        self.obs(l)
        self.assertEqual(list(e for e in l.entries if e[0] == 21), [(21, int(9500 * HZ))])
        v = l.vanished()
        self.assertEqual([(x["pid"], x["start"], x["key"]) for x in v], [(21, int(9000 * HZ), "app")])
        self.fp.remove(21)
        self.obs(l)
        self.assertEqual([x["pid"] for x in l.vanished()], [21])
        self.assertIsNone(l.entry(21))

    def test_root_inherited_session_leader_and_unowned_parent(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="npm", born=9900)
        self.fp.add(22, 21, comm="vite", born=9901)
        self.fp.add(30, 1, comm="daemon", born=9000)         # parent is pid 1: not the user's
        self.obs(l)
        self.assertEqual(l.root_for(22), 21)
        self.assertEqual(l.root_for(21), 21)
        self.assertIsNone(l.root_for(20))                    # session leader
        self.assertIsNone(l.root_for(30))
        self.assertEqual(l.entry(22)["root_key"], "npm")
        self.assertEqual(l.entry(22)["chain"][:2], ["npm", "bash"])

    def test_nothing_younger_than_five_seconds(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="npm", born=self.fp.up - 3)
        self.fp.add(22, 21, comm="vite", born=self.fp.up - 2)
        self.obs(l)
        self.assertIsNone(l.root_for(21))
        self.assertIsNone(l.root_for(22))
        self.obs(l, self.fp.up + 5)
        self.assertEqual(l.root_for(22), 21)

    def test_cobirth_within_two_seconds(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="fuzzel", born=9990.0)
        self.fp.add(40, 1, comm="firefox", born=9991.5)      # ppid 1, 1.5 s after the root
        self.fp.add(41, 1, comm="late", born=9993.0)         # 3 s after: no
        self.fp.add(42, 1, comm="early", born=9989.0)        # before the root: no
        self.obs(l, 10010.0)
        self.assertEqual(l.root_for(40), 21)
        self.assertIsNone(l.root_for(41))
        self.assertIsNone(l.root_for(42))

    def test_old_ppid1_process_never_joins(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="app", born=9000.0)
        self.fp.add(40, 1, comm="old", born=9000.5)
        self.obs(l)         # first seen long after birth: not a newcomer
        self.assertIsNone(l.root_for(40))

    def test_wrapper_root_exits_young_reroots_to_oldest_member(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="appimage", born=9998.0)
        self.fp.add(22, 21, comm="real", born=9998.5)
        self.fp.add(23, 21, comm="helper", born=9999.0)
        self.obs(l, 10000.0)
        self.fp.remove(21)
        self.obs(l, 10001.0)
        self.assertEqual(l.reroots, [((21, int(9998 * HZ)), (22, int(9998.5 * HZ)))])
        self.assertEqual(l.closed, [])
        self.obs(l, 10010.0)
        self.assertEqual(l.root_for(23), 22)
        self.assertEqual(l.entry(23)["root_key"], "real")

    def test_old_root_exit_leaves_leftovers(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="app", born=9000.0)
        self.fp.add(22, 21, comm="worker", born=9001.0)
        self.obs(l)
        self.obs(l, 10020.0)
        self.fp.remove(21)
        self.obs(l, 10040.0)
        self.assertEqual(len(l.closed), 1)
        self.assertEqual(l.root_for(22), 21)                 # dead root id kept
        left = l.leftovers_of(21)
        self.assertEqual([x["key"] for x in left], ["worker"])
        self.assertEqual(left[0]["root_key"], "app")

    def test_self_update_relaunch_reroots_not_leftover(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="code", exe="/opt/code/code", born=9000.0)
        self.fp.add(22, 21, comm="helper", born=9001.0)
        self.obs(l)
        self.obs(l, 10020.0)
        self.fp.remove(21)
        self.fp.add(23, 22, comm="code", exe="/opt/code/code", born=10025.0)   # relaunched under the helper
        self.obs(l, 10030.0)
        self.assertEqual(l.closed, [])
        self.assertEqual(len(l.reroots), 1)
        self.assertEqual(l.entry(22)["root"][0], 23)         # the relaunch is the oldest same-key survivor
        self.assertEqual(l.leftovers_of(21), [])

    def test_cap_and_foreign_processes(self):
        l = lin()
        self.shell()
        with mock.patch.object(lineage, "MAX_ENTRIES", 2):
            self.fp.add(21, 20, comm="a")
            self.fp.add(22, 20, comm="b")
            self.obs(l)
        self.assertEqual(len(l.entries), 2)
        self.assertEqual(l.overflow, 1)
        l2 = lin(uid=os.getuid() + 1)
        self.obs(l2)
        self.assertEqual(l2.entries, {})

    def test_job_tag_found_by_byte_search(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="npm", born=9990.0, env={"A": "1", "TAEMA_JOB": "20.7", "B": "2"})
        self.fp.add(22, 21, comm="old", born=1000.0, env={"TAEMA_JOB": "20.8"})   # outside the job window
        self.fp.add(23, 21, comm="bad", born=9995.0, env={"TAEMA_JOB": "x;y"})
        self.fp.add(24, 21, comm="first", born=9995.0, env={})
        with open(self.fp.root + "/24/environ", "wb") as f:
            f.write(b"TAEMA_JOB=20.7\0A=1\0")
        self.obs(l)
        self.assertEqual(l.job_of(21), "20.7")
        self.assertEqual(l.job_of(24), "20.7")
        self.assertIsNone(l.entry(22)["job"])
        self.assertEqual(l.job_of(22), "sid:7")
        self.assertIsNone(l.entry(23)["job"])
        self.assertEqual(l.job_info("20.7")["root_key"], "npm")

    def test_job_fallback_to_pgrp(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="npm", born=9990.0, pgrp=21, env={"TAEMA_JOB": "20.1"})
        self.fp.add(22, 21, comm="notag", born=9991.0, pgrp=21)
        self.obs(l)
        self.assertEqual(l.job_of(22), "20.1")
        self.assertEqual(sorted(e["pid"] for e in l.job_members("20.1")), [21, 22])

    def left_setup(self, **kw):
        cfg = make_cfg(tmp(), **kw)
        l = lin(cfg)
        self.shell()
        self.fp.add(21, 20, comm="npm", born=9990.0, env={"TAEMA_JOB": "20.1"})
        return l

    def test_leftovers_exclude_zombie_shell_children_seeds_protected_hosts(self):
        l = self.left_setup(seeds={"persist": ["gpg-agent"], "share": ["adb"]}, protected={"comm": ["niri*"]})
        env = {"TAEMA_JOB": "20.1"}
        self.fp.add(30, 1, comm="vite", born=9990.0, env=env, sid=30)             # survivor (kept)
        self.fp.add(31, 1, comm="gpg-agent", born=9990.0, env=env, sid=31)         # persist seed
        self.fp.add(32, 1, comm="adb", born=9990.0, env=env, sid=32)               # share seed
        self.fp.add(33, 1, comm="niri-x", born=9990.0, env=env, sid=33)            # protected comm
        self.fp.add(34, 1, comm="tmux", born=9990.0, env=env, sid=34, fds=["/dev/null", "/dev/ptmx"])  # pty host
        self.fp.add(35, 1, comm="zomb", born=9990.0, env=env, sid=35, state="Z")   # zombie
        self.fp.add(36, 20, comm="bg", born=9990.0, env=env)                       # child of the live shell
        self.fp.add(37, 1, comm="watcher", born=9990.0, env=env, sid=37)
        self.fp.add(38, 1, comm="other", born=9990.0, env={"TAEMA_JOB": "20.2"}, sid=38)    # other job
        self.obs(l)
        left = l.leftovers_of("20.1")
        self.assertEqual(sorted(x["key"] for x in left), ["vite", "watcher"])
        self.assertTrue(l.ptmx_host(34))
        self.assertFalse(l.ptmx_host(30))

    def test_ptmx_host_cached_per_pid_start(self):
        l = lin()
        self.shell()
        self.fp.add(21, 20, comm="term", fds=["/dev/pts/ptmx"], born=9000)
        self.obs(l)
        self.assertTrue(l.ptmx_host(21))
        with mock.patch.object(l, "_scan_ptmx", side_effect=AssertionError):
            self.assertTrue(l.ptmx_host(21))
        self.assertFalse(l.ptmx_host(999))

    def test_runtime_socket_daemon_is_never_a_leftover(self):
        l = self.left_setup()
        env = {"TAEMA_JOB": "20.1"}
        rd = tmp()
        os.makedirs(self.fp.root + "/net")
        with open(self.fp.root + "/net/unix", "w") as f:
            f.write("Num RefCount Protocol Flags Type St Inode Path\n"
                    "0: 2 0 00010000 0001 01 777 %s/S.agent\n0: 2 0 00000000 0001 03 778 %s/conn\n" % (rd, rd))
        self.fp.add(30, 1, comm="agentd", born=9990.0, env=env, sid=30, fds=["socket:[777]"])
        self.fp.add(31, 1, comm="setsidsleep", born=9990.0, env=env, sid=31)
        self.fp.add(32, 1, comm="client", born=9990.0, env=env, sid=32, fds=["socket:[778]"])
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": rd}):
            self.obs(l)
            self.assertEqual(sorted(x["key"] for x in l.leftovers_of("20.1")), ["client", "setsidsleep"])
            self.assertTrue(l.holds_runtime_listener(30))


# ---- 3. knowledge v2 ---------------------------------------------------------------------------------------

class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class KnowledgeV2(unittest.TestCase):
    def setUp(self):
        self.d = tmp()
        self.c = Clock()
        self.s = knowledge.Store(self.d, {"persist": ["tmux"]}, self.c)

    def fresh(self):
        return knowledge.Store(self.d, {}, self.c)

    def test_v1_file_migrates_keeping_exes(self):
        d = tmp()
        v1 = {"last_decay": self.c(), "exes": {"adb": {"user_keep": 3.0, "seen": 2.0, "term_exit_ms": [5]}}}
        with open(d + "/knowledge.json", "w") as f:
            json.dump(v1, f)
        s = knowledge.Store(d, {}, self.c)
        self.assertEqual(s.data["version"], 2)
        self.assertEqual(s.data["exes"]["adb"]["user_keep"], 3.0)
        self.assertEqual(s.data["pairs"], {})
        self.assertEqual(s.data["standalone"], {})
        self.assertIn("asked", s.data)
        self.assertTrue(s.dirty)
        s.save()
        with open(d + "/knowledge.json") as f:
            self.assertEqual(json.load(f)["version"], 2)
        self.assertEqual(knowledge.Store(d, {}, self.c).peek("adb")["user_keep"], 3.0)

    def test_bad_section_shapes_are_reset(self):
        d = tmp()
        with open(d + "/knowledge.json", "w") as f:
            json.dump({"exes": {}, "pairs": [], "standalone": 3, "version": 2}, f)
        s = knowledge.Store(d, {}, self.c)
        self.assertEqual((s.data["pairs"], s.data["standalone"]), ({}, {}))

    def test_explicit_answer_weight_and_no_decay(self):
        self.s.answer("npm", "vite", "stop")
        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "stop")
        self.s.observe_kill_inferred("npm", "vite")
        self.s.bump("npm", "seen", 5)
        self.c.t += 70 * DAY
        self.s.decay()
        p = self.s.data["pairs"][self.s.pkey("npm", "vite")]
        self.assertEqual(p["ex_stop"], 3.0)
        self.assertLess(p["stop"], 0.25)            # inferred evidence decayed
        self.assertLess(self.s.peek("npm")["seen"], 5)
        self.assertEqual(self.s.pair_decision("npm", "vite")[:2], ("stop", 1.0))

    def test_explicit_keep_and_standalone(self):
        self.s.answer("npm", "vite", "keep")
        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "keep")
        self.assertEqual(self.s.pair_decision("npm", "other")[0], "ask")
        self.assertFalse(self.s.standalone("tool"))
        self.s.answer("npm", "tool", "standalone")
        self.assertTrue(self.s.standalone("tool"))
        self.assertEqual(self.s.pair_decision("whatever", "tool")[0], "standalone")
        self.assertFalse(self.s.answer("npm", "tool", "bogus"))
        self.assertFalse(self.s.answer("a\0b", "tool", "stop"))

    def test_contrary_evidence_overturns_answer_and_new_answer_resets(self):
        self.s.answer("o", "l", "stop")
        self.s.auto_stopped("o", "l")
        self.assertTrue(self.s.regret("o", "l"))
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")     # suspended
        self.c.t += 8 * DAY
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")     # keep 3.0 (decay aside) >= answer 3
        self.s.answer("o", "l", "stop")
        self.assertEqual(self.s.pair_decision("o", "l")[0], "stop")

    def silent(self, n=5, days=3, owner="o", leftover="l"):
        for i in range(n):
            self.s.observe_kill_inferred(owner, leftover, day=100 + i % days)

    def test_silent_stop_thresholds_and_burn_in(self):
        self.silent()
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")       # pair and store too young
        self.c.t += 2 * DAY
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")       # burn-in (7 days) not passed
        self.s.data["closes"] = 20                                       # 20 closes pass it
        a, conf, why = self.s.pair_decision("o", "l")
        self.assertEqual((a, conf), ("stop", 1.0), why)
        self.assertIn("silent", why)

    def test_silent_stop_needs_five_kills_three_days_and_no_keep(self):
        self.s.data["closes"] = 99
        self.silent(n=4)
        self.c.t += 2 * DAY
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")       # only 4 kills
        self.silent(n=1)
        self.assertEqual(self.s.pair_decision("o", "l")[0], "stop")
        self.silent(n=5, days=2, owner="o2")
        self.assertEqual(self.s.pair_decision("o2", "l")[0], "ask")      # only 2 distinct days
        p = self.s.data["pairs"][self.s.pkey("o", "l")]
        p["keep"], p["last_keep"] = 0.1, self.c.t - 5 * DAY              # a keep within 30 days
        self.assertNotEqual(self.s.pair_decision("o", "l")[0], "stop")
        p["keep"], p["last_keep"] = 0.0, self.c.t - 40 * DAY
        self.assertEqual(self.s.pair_decision("o", "l")[0], "stop")
        p["keep"] = 0.5                                                   # ratio 1.25/1.75 < 0.9
        self.assertNotEqual(self.s.pair_decision("o", "l")[0], "stop")

    def test_burn_in_by_age(self):
        self.silent()
        self.c.t += 8 * DAY
        self.assertEqual(self.s.pair_decision("o", "l")[0], "stop")

    def test_pair_must_be_older_than_24h(self):
        self.s.data["closes"] = 99
        self.silent()
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")
        self.c.t += DAY + 1
        self.assertEqual(self.s.pair_decision("o", "l")[0], "stop")

    def test_regret_adds_keep_and_suspends_seven_days(self):
        self.s.answer("o", "l", "stop")
        self.assertFalse(self.s.regret("o", "l"))                         # never auto-stopped
        self.s.auto_stopped("o", "l")
        self.c.t += 31 * 60
        self.assertFalse(self.s.regret("o", "l"))                         # too late
        self.s.auto_stopped("o", "l")
        self.c.t += 10 * 60
        self.assertTrue(self.s.regret("o", "l"))
        p = self.s.data["pairs"][self.s.pkey("o", "l")]
        self.assertEqual(p["keep"], 3.0)
        self.assertAlmostEqual(p["suspended_until"], self.c.t + 7 * DAY)
        self.assertEqual(self.s.pair_decision("o", "l")[0], "ask")
        self.assertFalse(self.s.regret("o", "l"))                         # once per auto-stop

    def test_can_ask_limits(self):
        pairs = [("o", "l%d" % i) for i in range(5)]
        self.assertTrue(self.s.can_ask(pairs[0]))
        for p in pairs[:3]:
            self.s.mark_asked([p])
        self.assertFalse(self.s.can_ask(pairs[4]))                        # 3 per day
        self.c.t += DAY
        self.assertTrue(self.s.can_ask(pairs[4]))
        self.assertFalse(self.s.can_ask(pairs[0]))                        # same pair within 7 days
        self.c.t += 7 * DAY
        self.assertTrue(self.s.can_ask(pairs[0]))

    def test_respawn_counts_only_other_owner_or_self_started(self):
        self.assertFalse(self.s.respawn("k", same_owner=True))
        self.assertEqual(self.s.peek("k")["respawned"], 0)
        self.assertTrue(self.s.respawn("k", same_owner=False))
        self.assertEqual(self.s.peek("k")["respawned"], 1)

    def test_caps(self):
        for i in range(40):
            self.s.observe_close("o", "l%d" % i)
        self.assertEqual(sum(1 for k in self.s.data["pairs"] if k.startswith("o\0")), knowledge.MAX_PER_OWNER)
        self.s.answer("o", "keepme", "keep")
        for i in range(40):
            self.s.observe_close("o", "z%d" % i)
        self.assertIn(self.s.pkey("o", "keepme"), self.s.data["pairs"])   # explicit pair outweighs the rest
        for i in range(300):
            self.s.observe_close("own%d" % i, "x")
        self.assertLessEqual(len(self.s.data["pairs"]), knowledge.MAX_PAIRS)

    def test_launcher_close_counts_noise_and_owners_of(self):
        self.s.observe_close("zsh-job", "app", launcher=True)
        self.assertEqual(self.s.data["noise"], {"app": 1})            # launcher: no pair at all
        self.assertNotIn(self.s.pkey("zsh-job", "app"), self.s.data["pairs"])
        self.assertEqual(self.s.pair_decision("zsh-job", "app")[0], "ask")
        self.s.answer("code", "app", "stop")
        self.assertEqual(self.s.owners_of("app")[0], "code")

    def test_explain_and_summary_include_pairs(self):
        self.s.answer("npm", "vite", "stop")
        ex = self.s.explain("vite")
        self.assertEqual(ex["pairs"][0]["owner"], "npm")
        self.assertEqual(self.s.pairs_summary()[0]["action"], "stop")
        self.assertIn("standalone", ex)

    def test_roundtrip(self):
        self.s.answer("npm", "vite", "stop")
        self.s.answer("npm", "tool", "standalone")
        self.s.save()
        s2 = self.fresh()
        self.assertEqual(s2.pair_decision("npm", "vite")[0], "stop")
        self.assertTrue(s2.standalone("tool"))

    def legacy(self, owner, leftover, **extra):
        """A pair record written by an older release (invalid owners included)."""
        p = {"first_seen": self.c()}
        p.update(extra)
        self.s.data["pairs"][self.s.pkey(owner, leftover)] = p

    def test_invalid_owner_close_counts_noise_without_a_pair(self):
        for owner in ("MainThread", "sleep", "3.12", ""):
            self.assertTrue(self.s.observe_close(owner, "vite"), owner)
        self.assertFalse(self.s.observe_close("MainThread", ""))    # malformed leftover
        self.assertEqual(self.s.data["noise"], {"vite": 4})
        self.assertEqual(self.s.data["pairs"], {})
        self.assertEqual(self.s.data["closes"], 0)

    def test_launcher_close_counts_noise_without_a_pair(self):
        self.assertTrue(self.s.observe_close("npm", "vite", launcher=True))
        self.assertEqual(self.s.data["noise"], {"vite": 1})
        self.assertNotIn(self.s.pkey("npm", "vite"), self.s.data["pairs"])
        self.assertEqual(self.s.pair_decision("npm", "vite")[0], "ask")

    def test_configured_deny_extends_the_defaults_in_the_store(self):
        s = knowledge.Store(self.d, {}, self.c, deny=["gpu-*"])
        self.assertTrue(s.observe_close("gpu-render", "x"))      # denied -> noise, not a pair
        self.assertTrue(s.observe_close("MainThread", "x"))      # built-in class -> noise
        self.assertEqual(s.data["pairs"], {})
        self.assertEqual(s.data["noise"], {"x": 2})
        self.assertFalse(s.observe_kill_inferred("gpu-render", "y"))
        self.assertEqual(s.data["pairs"], {})

    def test_noise_survives_save_and_migration(self):
        self.s.observe_close("sleep", "vite")
        self.s.save()
        self.assertEqual(knowledge.Store(self.d, {}, self.c).data["noise"], {"vite": 1})
        d = tmp()
        with open(d + "/knowledge.json", "w") as f:
            json.dump({"last_decay": self.c(), "exes": {}, "pairs": {}, "version": 2}, f)
        self.assertEqual(knowledge.Store(d, {}, self.c).data["noise"], {})

    def test_legacy_invalid_owner_pair_never_asks_answers_or_stops(self):
        for k in ("sh", "sort", "head"):
            self.legacy("MainThread", k, ex_stop=3.0, ex_last="stop")
            self.assertEqual(self.s.pair_decision("MainThread", k)[0], "invalid")
            self.assertIn("invalid owner", self.s.pair_decision("MainThread", k)[2])
            self.assertFalse(self.s.can_ask(("MainThread", k)))
            self.assertFalse(self.s.pair_explicit("MainThread", k))
            self.assertFalse(self.s.answer("MainThread", k, "keep"))
        self.assertEqual([r["action"] for r in self.s.pairs_summary()], ["invalid"] * 3)
        self.assertIn("invalid owner", self.s.pairs_summary()[0]["why"])

    def test_invalid_owner_never_gets_new_pair_state(self):
        self.s.mark_asked([("MainThread", "vite")])
        self.s.auto_stopped("MainThread", "vite")
        self.assertFalse(self.s.regret("MainThread", "vite"))
        self.assertFalse(self.s.observe_kill_inferred("MainThread", "vite"))
        self.assertEqual(self.s.data["pairs"], {})

    def test_legacy_launcher_pair_still_keeps(self):
        self.legacy("npm", "code", launches=3)
        self.assertEqual(self.s.pair_decision("npm", "code")[0], "keep")


# ---- 4. daemon: job_done -> question flow ------------------------------------------------------------------

class JobFlow(ProcCase):
    def setUp(self):
        super().setUp()
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.rt = tmp()
        p = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.rt})
        p.start()
        self.addCleanup(p.stop)
        self.d = daemon.Daemon(make_cfg(tmp(), seeds={"persist": ["gpg-agent"]}, protected={"comm": ["niri*"]}))
        self.fp.add(20, 1, comm="bash", sid=20, tty=34816, born=1000.0)

    def log(self):
        with open(self.d.store.log_path) as f:
            return [json.loads(l) for l in f]

    def job(self, tag="20.1", survivors=(("vite", 5.0),), status=0, word="npm", extra=(), npm_age=6.0):
        """npm (child of the shell, gone by the settle) plus setsid'd survivors carrying the tag."""
        env = {"TAEMA_JOB": tag}
        up = self.fp.up
        self.fp.add(21, 20, comm="npm", env=env, born=up - npm_age, pgrp=21)
        pid = 30
        for comm, age in survivors:
            self.fp.add(pid, 1, comm=comm, env=env, born=up - age, sid=pid)
            pid += 1
        for kw in extra:
            self.fp.add(pid, 1, env=env, sid=pid, born=up - 5.0, **kw)
            pid += 1
        self.d.lineage.observe(self.fp.table())          # an adopt pass saw npm and the survivors
        self.fp.remove(21)
        return self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": tag, "status": status, "word": word})

    def settle(self, tag="20.1"):
        self.d.decide_job(tag)

    def ask(self):
        return self.d.handle({"cmd": "ask", "shell_pid": 20})

    def test_job_done_validation(self):
        h = self.d.handle
        good = {"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "ls"}
        for patch in ({"shell_pid": "20"}, {"shell_pid": True}, {"shell_pid": 1}, {"shell_pid": 999999},
                      {"tag": 5}, {"tag": "21.1"}, {"tag": "20.x"}, {"status": "0"}, {"status": 300},
                      {"status": -1}, {"word": "x" * 33}, {"word": 3}):
            self.assertIn("error", h(dict(good, **patch)), patch)
        self.assertEqual(h(good), {"ok": True})
        self.assertEqual(len(self.d.deadlines), 1)
        self.assertEqual(self.d.deadlines[0][1:], ("job", "20.1"))

    def test_word_is_sanitized(self):
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "n\x1b[2Jpm\n"})
        self.assertEqual(self.d.jobs["20.1"]["word"], "n[2Jpm")

    def test_ctrl_z_is_not_a_close(self):
        for st in (148, 149, 150):
            r = self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": st, "word": "vim"})
            self.assertEqual(r.get("ignored"), "stopped, not closed")
        self.assertEqual((self.d.jobs, self.d.deadlines), ({}, []))
        self.assertTrue(self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 147, "word": "v"})["ok"])

    def test_deadline_not_sleep_and_next_timeout(self):
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "ls"})
        self.assertLessEqual(self.d.next_timeout(), daemon.JOB_SETTLE)
        with mock.patch.object(self.d, "decide_job") as dj:
            self.d.run_deadlines()
            dj.assert_not_called()
            self.d.deadlines = [(time.time() - 1, "job", "20.1")]
            self.d.run_deadlines()
            dj.assert_called_once_with("20.1")
        self.assertEqual(self.d.deadlines, [])

    def test_survivors_produce_question_and_answer_flow(self):
        self.job()
        self.d.deadlines.clear()
        self.settle()
        self.assertEqual(len(self.d.pending), 1)
        q = self.d.pending[1]
        qf = "%s/taema/q.20" % self.rt
        self.assertEqual(oct(os.stat(qf).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(os.path.dirname(qf)).st_mode & 0o777), "0o700")
        r = self.ask()["question"]
        self.assertEqual(r["candidates"][0], {"id": 1, "kind": "job", "key": "npm", "label": "npm"})
        self.assertEqual([c["key"] for c in r["candidates"] if c["kind"] == "ancestor"], [])   # bash is a shell
        self.assertEqual(r["leftovers"], [{"key": "vite", "comm": "vite", "count": 1}])
        self.assertEqual(r["nonce"], q["nonce"])
        self.assertEqual(r["choices"], ["stop", "keep", "standalone"])
        ans = lambda **m: self.d.handle(dict({"cmd": "answer"}, **m))
        for bad in ({"nonce": "nope", "choice": "stop"}, {"nonce": 5, "choice": "stop"}, {"choice": "stop"},
                    {"nonce": r["nonce"], "choice": "kill"}, {"nonce": r["nonce"], "choice": "stop", "owner": "evil"},
                    {"nonce": r["nonce"], "choice": "stop", "owner": 3}):
            self.assertIn("error", ans(**bad), bad)
        self.assertTrue(os.path.exists(qf))
        self.assertEqual(ans(nonce=r["nonce"], choice="stop")["ok"], True)
        self.assertFalse(os.path.exists(qf))
        self.assertIn("error", ans(nonce=r["nonce"], choice="stop"))          # one-time nonce
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "stop")
        self.assertEqual(knowledge.Store(self.d.store.dir, {}).pair_decision("npm", "vite")[0], "stop")   # saved at once
        self.assertEqual(self.ask(), {"question": None, "reason": "none"})

    def test_standalone_and_owner_choice(self):
        self.job()
        self.settle()
        r = self.ask()["question"]
        self.assertEqual(self.d.handle({"cmd": "answer", "nonce": r["nonce"], "choice": "standalone"})["ok"], True)
        self.assertTrue(self.d.store.standalone("vite"))

    def test_logs_would_attribute_and_would_stop_only(self):
        self.d.store.answer("npm", "vite", "stop")
        self.job()
        self.settle()
        ev = self.log()
        self.assertEqual([e["leftover"] for e in ev if e["event"] == "would_attribute"], ["vite"])
        ws = [e for e in ev if e["event"] == "would_stop"]
        self.assertEqual((ws[0]["owner"], ws[0]["leftover"]), ("npm", "vite"))
        self.assertEqual(self.d.pending, {})                 # decided: no question
        self.assertFalse([e for e in ev if e["event"] in ("stopped", "stop")])

    def test_never_ask_seed_protected_zombie_host(self):
        self.job(survivors=(("vite", 5.0),), extra=(
            {"comm": "gpg-agent"}, {"comm": "niri-x"}, {"comm": "zz", "state": "Z"},
            {"comm": "tmux", "fds": ["/dev/ptmx"]}))
        self.settle()
        q = self.d.pending[1]
        self.assertEqual([l["key"] for l in q["leftovers"]], ["vite"])

    def test_only_nonleftover_survivors_means_no_question(self):
        self.job(survivors=(), extra=({"comm": "gpg-agent"},))
        self.settle()
        self.assertEqual(self.d.pending, {})

    def test_launcher_pattern_learned_silently(self):
        self.job(survivors=(("code", 0.3),), word="code", npm_age=0.5)
        self.fp.set_uptime(self.fp.up)
        self.settle()
        self.assertEqual(self.d.pending, {})
        self.assertFalse(os.path.exists("%s/taema/q.20" % self.rt))
        # launcher closes are noise: counted, never a pair
        self.assertEqual(self.d.store.data["pairs"], {})
        self.assertEqual(self.d.store.data["noise"], {"code": 1})
        ev = [e["event"] for e in self.log()]
        self.assertIn("launcher_learned", ev)

    def test_standalone_leftover_is_not_asked(self):
        self.d.store.answer("x", "vite", "standalone")
        self.job()
        self.settle()
        self.assertEqual(self.d.pending, {})

    def test_question_expires(self):
        self.job()
        self.settle()
        self.assertTrue(self.d.deadlines and self.d.deadlines[-1][1] == "expire")
        self.d.pending[1]["created"] -= daemon.PENDING_TTL + 1
        self.assertEqual(self.ask()["question"], None)
        self.assertEqual(self.d.pending, {})
        self.assertFalse(os.path.exists("%s/taema/q.20" % self.rt))

    def test_expired_nonce_rejected_and_file_removed(self):
        self.job()
        self.settle()
        nonce = self.ask()["question"]["nonce"]
        self.d.pending[1]["created"] -= daemon.PENDING_TTL + 1
        self.assertIn("error", self.d.handle({"cmd": "answer", "nonce": nonce, "choice": "stop"}))
        self.assertFalse(os.path.exists("%s/taema/q.20" % self.rt))
        self.assertEqual(self.d.store.pair_decision("npm", "vite")[0], "ask")

    def test_expire_deadline_drops_question(self):
        self.job()
        self.settle()
        self.d.pending[1]["created"] -= daemon.PENDING_TTL
        self.d.expire_question(1)
        self.assertEqual(self.d.pending, {})

    def test_pending_cap(self):
        for i in range(daemon.MAX_PENDING + 5):
            self.d.make_question({"shell": 20 + i, "word": "w"}, "t", "o", [], ["k"])
        self.assertEqual(len(self.d.pending), daemon.MAX_PENDING)
        self.assertNotIn(1, self.d.pending)

    def test_one_pending_per_shell(self):
        self.d.make_question({"shell": 20, "word": "a"}, "20.1", "o", [], ["k"])
        self.d.make_question({"shell": 20, "word": "b"}, "20.2", "o", [], ["k"])
        self.assertEqual([q["word"] for q in self.d.pending.values()], ["b"])
        self.assertTrue(os.path.exists("%s/taema/q.20" % self.rt))

    def test_rate_limits_at_ask(self):
        for i in range(3):
            self.d.store.mark_asked([("o", "z%d" % i)])
        self.job()
        self.d.store.data["pairs"].clear()
        self.settle()
        self.assertEqual(self.d.pending, {})                 # daily limit stops it at creation
        self.d.store.data["asked"] = {"day": 0, "n": 0}
        self.job()
        self.settle()
        self.assertEqual(len(self.d.pending), 1)
        self.d.store.data["asked"] = {"day": int(time.time() // DAY), "n": 3}
        self.assertEqual(self.ask(), {"question": None, "reason": "rate_limited"})
        self.assertEqual(self.d.pending, {})

    def test_ask_validation_and_repeat_does_not_recount(self):
        self.assertIn("error", self.d.handle({"cmd": "ask", "shell_pid": "x"}))
        self.assertIn("error", self.d.handle({"cmd": "ask", "shell_pid": 999999}))
        self.job()
        self.settle()
        a, b = self.ask(), self.ask()
        self.assertEqual(a["question"]["nonce"], b["question"]["nonce"])
        self.assertEqual(self.d.store.data["asked"]["n"], 1)

    def test_candidates_ancestors_and_history(self):
        self.d.store.answer("code", "vite", "stop")
        self.fp.add(25, 20, comm="code", born=self.fp.up - 50, pgrp=25)
        self.fp.add(26, 25, comm="mid", born=self.fp.up - 49, pgrp=25)
        env = {"TAEMA_JOB": "20.1"}
        self.fp.add(30, 26, comm="vite", env=env, born=self.fp.up - 5, sid=30)
        self.d.lineage.observe(self.fp.table())
        self.d.jobs["20.1"] = {"shell": 20, "status": 0, "word": "npm", "t": time.time()}
        self.fp.add(21, 20, comm="npm", env=env, born=self.fp.up - 6, pgrp=21)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.d.decide_job("20.1")
        keys = [(c["kind"], c["key"]) for c in self.d.pending[1]["candidates"]]
        self.assertEqual(keys[0], ("job", "npm"))
        self.assertIn(("ancestor", "mid"), keys)
        self.assertIn(("ancestor", "code"), keys)
        self.assertEqual(sum(1 for k in keys if k[1] == "code"), 1)       # deduplicated against history

    def test_status_has_pairs_and_confidence(self):
        self.d.store.answer("npm", "vite", "stop")
        st = self.d.handle({"cmd": "status"})
        self.assertEqual((st["pairs"][0]["owner"], st["pairs"][0]["confidence"]), ("npm", 1.0))
        self.assertIn("lineage", st)

    def test_malformed_requests_do_not_crash(self):
        for m in ({"cmd": "job_done"}, {"cmd": "ask"}, {"cmd": "answer"}, {"cmd": "answer", "nonce": []},
                  {"cmd": "job_done", "shell_pid": 20, "tag": None}):
            self.assertIn("error", self.d.handle(m))

    def test_close_seen_by_a_job_settle_is_not_lost(self):
        up = self.fp.up
        self.fp.add(21, 20, comm="app", born=up - 100, pgrp=21)
        self.fp.add(22, 21, comm="worker", born=up - 99, pgrp=21)
        self.d.lineage.observe(self.fp.table())
        self.fp.set_uptime(up + 20)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.fp.set_uptime(up + 40)
        self.d.jobs["20.9"] = {"shell": 20, "status": 0, "word": "ls", "t": time.time()}
        self.d.decide_job("20.9")                       # unrelated tag; its observe sees the close
        self.assertEqual([(e["owner"], e["leftover"]) for e in self.log() if e["event"] == "would_attribute"],
                         [("app", "worker")])

    def test_closed_gui_root_logs_attribution_and_counts_close(self):
        up = self.fp.up
        self.fp.add(21, 20, comm="app", born=up - 100, pgrp=21)
        self.fp.add(22, 21, comm="worker", born=up - 99, pgrp=21)
        self.d.lineage.observe(self.fp.table())
        self.fp.set_uptime(up + 20)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.fp.set_uptime(up + 40)
        self.d.lineage.observe(self.fp.table())
        self.d.after_observe()
        self.assertEqual(self.d.store.data["pairs"][knowledge.Store.pkey("app", "worker")]["closes"], 1)
        ev = self.log()
        self.assertEqual([(e["owner"], e["leftover"]) for e in ev if e["event"] == "would_attribute"], [("app", "worker")])


class OwnerHygiene(JobFlow):
    """Ticket #6 at the daemon level: rejected owner classes, the launcher path, unresolved
    ancestry and the legacy MainThread answer all stay out of pairs and questions."""

    REJECTED = ("MainThread", "Thread-1", "pool-3", "GC", "Finalizer",
                "3.12", "2024.1",
                "sh", "bash", "dash", "zsh", "fish",
                "sleep", "cat", "head", "sort", "grep", "true",
                "python3", "python3.12", "node", "java", "perl")

    def junk_job(self, comm, word=None):
        """A terminal job whose root is `comm`, plus one setsid'd survivor. A fresh daemon every
        round keeps lineage/store state from bleeding between cases."""
        for pid in (21, 30):
            if os.path.isdir("%s/%d" % (self.fp.root, pid)):
                self.fp.remove(pid)
        self.d = daemon.Daemon(make_cfg(tmp(), seeds={"persist": ["gpg-agent"]},
                                        protected={"comm": ["niri*"]}))
        env = {"TAEMA_JOB": "20.1"}
        up = self.fp.up
        self.fp.add(21, 20, comm=comm, env=env, born=up - 6.0, pgrp=21)
        self.fp.add(30, 1, comm="vite", env=env, born=up - 5.0, sid=30)
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0,
                       "word": word or comm})
        self.d.decide_job("20.1")

    def test_every_rejected_owner_class_is_noise_not_a_pair(self):
        for comm in self.REJECTED:
            with self.subTest(comm=comm):
                self.junk_job(comm)
                self.assertEqual(self.d.store.data["pairs"], {}, comm)
                self.assertEqual(self.d.store.data["noise"], {"vite": 1}, comm)
                self.assertEqual(self.d.pending, {}, comm)
                self.assertIsNone(self.ask()["question"], comm)
                ev = [e for e in self.log() if e["event"] == "launcher_learned"]
                self.assertEqual([e.get("why") for e in ev], ["no application ancestor"], comm)

    def test_unresolved_job_is_noise_even_when_the_typed_word_is_an_app(self):
        self.junk_job("sleep", word="code")       # ancestry is junk: the word never becomes the owner
        self.assertEqual(self.d.store.data["pairs"], {})
        self.assertEqual(self.d.store.data["noise"], {"vite": 1})
        self.assertEqual(self.d.pending, {})

    def test_job_resolves_through_the_chain_to_a_real_application(self):
        env = {"TAEMA_JOB": "20.1"}
        up = self.fp.up
        self.fp.add(21, 20, comm="MainThread", env=env, born=up - 6.0, pgrp=21)   # junk wrapper root
        self.fp.add(22, 21, comm="code", env=env, born=up - 5.5, pgrp=21)         # the real app below it
        self.fp.add(30, 22, comm="vite", env=env, born=up - 5.0, sid=30)          # setsid'd survivor
        self.d.lineage.observe(self.fp.table())
        self.fp.remove(21)
        self.d.handle({"cmd": "job_done", "shell_pid": 20, "tag": "20.1", "status": 0, "word": "code"})
        self.d.decide_job("20.1")
        pairs = self.d.store.data["pairs"]
        self.assertIn(knowledge.Store.pkey("code", "vite"), pairs)
        self.assertFalse([k for k in pairs if k.startswith("MainThread\0")], pairs)
        # the junk wrapper's own root close is noise; the job close resolves to "code"
        self.assertEqual(self.d.store.data["noise"], {"code": 1})
        self.assertEqual(self.d.pending[1]["owner"], "code")

    def test_configured_deny_entry_turns_the_job_into_noise(self):
        self.d = daemon.Daemon(make_cfg(tmp(), seeds={"persist": ["gpg-agent"]},
                                        protected={"comm": ["niri*"]},
                                        learner={"deny_owners": ["npm"]}))
        self.job()                                  # normal job; its root key "npm" is denied by config
        self.settle()
        self.assertEqual(self.d.store.data["pairs"], {})
        self.assertEqual(self.d.store.data["noise"], {"vite": 1})
        self.assertEqual(self.d.pending, {})

    def test_answered_mainthread_pair_is_never_offered_or_asked(self):
        for k in ("sh", "sort", "head", "vite"):
            self.d.store.data["pairs"][knowledge.Store.pkey("MainThread", k)] = {
                "first_seen": time.time(), "ex_stop": 3.0, "ex_last": "stop"}
        self.job()                                  # owner npm, leftover vite
        self.settle()
        q = self.d.pending[1]
        self.assertEqual(q["owner"], "npm")
        self.assertNotIn("MainThread", [c["key"] for c in q["candidates"]])
        for k in ("sh", "sort", "head"):
            self.assertEqual(self.d.store.pair_decision("MainThread", k)[0], "invalid")
            self.assertFalse(self.d.store.can_ask(("MainThread", k)))


class Misc(ProcCase):
    def test_keys_have_no_control_characters(self):
        self.fp.add(50, 1, comm="ev\x1b[2Jil", exe="/usr/bin/ev\x1b[2Jil")
        self.assertEqual(policy.app_key(50), "ev[2Jil")

    def test_children_follow_a_root_key_that_settles(self):
        l = lin()
        self.fp.add(20, 1, comm="bash", sid=20, tty=1, born=1000.0)
        self.fp.add(21, 20, comm="wrapper", exe="/usr/bin/bash", argv=["bash"], born=self.fp.up - 2)
        self.fp.add(22, 21, comm="c", born=self.fp.up - 1)
        l.observe(self.fp.table(), now=self.fp.up, uptime=self.fp.up)
        self.assertEqual(l.entry(22)["root_key"], "wrapper")
        self.fp.add(21, 20, comm="realapp", exe="/usr/bin/realapp", born=self.fp.up - 2)
        l.observe(self.fp.table(), now=self.fp.up + 1, uptime=self.fp.up + 1)
        self.assertEqual(l.entry(22)["root_key"], "realapp")


# ---- 5. respawn / gc_outcome wiring ------------------------------------------------------------------------------

class RespawnWiring(ProcCase):
    def setUp(self):
        super().setUp()
        self.d = daemon.Daemon(make_cfg(tmp(), timers={"respawn_window": 60}))
        self.fp.add(20, 1, comm="bash", sid=20, tty=34816, born=1000.0)
        self.fp.add(21, 1, comm="sup", born=1000.0)

    def stop(self, key="k"):
        self.d.note_stop({"decisions": [{"action": "kill", "key": key}, {"action": "share", "key": "z"}]})
        self.assertEqual(list(self.d.stopped), [key])

    def pass_(self):
        self.d.lineage.observe(self.fp.table())
        self.d.after_observe()

    def test_reappearance_under_supervisor_counts(self):
        self.pass_()
        self.stop()
        self.fp.add(40, 21, comm="k", born=self.fp.up - 3)
        self.pass_()
        self.assertEqual(self.d.store.peek("k")["respawned"], 1)
        self.assertEqual(self.d.store.peek("k")["idle_grace_scale"], 2.0)
        self.assertEqual(self.d.stopped, {})

    def test_rerun_from_shell_is_not_a_respawn_nor_gc_evidence(self):
        self.pass_()
        self.stop()
        self.fp.add(40, 20, comm="k", born=self.fp.up - 3)
        self.pass_()
        self.assertEqual(self.d.store.peek("k")["respawned"], 0)
        self.assertEqual(self.d.store.peek("k")["idle_grace_scale"], 1.0)
        self.assertEqual(self.d.stopped, {})

    def test_window_expiry_is_a_good_stop(self):
        self.stop()
        self.d.expire_respawns()
        self.assertIn("k", self.d.stopped)
        self.d.stopped["k"] -= 61
        self.d.expire_respawns()
        self.assertEqual(self.d.stopped, {})
        self.assertAlmostEqual(self.d.store.peek("k")["idle_grace_scale"], 0.9)

    def test_late_reappearance_is_not_counted(self):
        self.pass_()
        self.stop()
        self.d.stopped["k"] -= 120
        self.fp.add(40, 21, comm="k", born=self.fp.up - 3)
        self.pass_()
        self.assertEqual(self.d.store.peek("k")["respawned"], 0)

    def test_adopt_pass_observes_lineage_without_units(self):
        self.d.units = []
        with mock.patch.object(inspect.ProcTable, "scan", return_value=self.fp.table()) as sc:
            self.d.adopt_pass()
        self.assertEqual(sc.call_count, 1)
        self.assertIn(20, self.d.lineage.by_pid)


if __name__ == "__main__":
    unittest.main()
