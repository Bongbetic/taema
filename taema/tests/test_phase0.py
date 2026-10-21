"""Phase 0 regression tests: fake /proc and cgroup trees, malformed sockets, learner fixes."""

import json
import io
import os
import socket
import stat
import subprocess
import tempfile
import time
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema.daemon import service as daemon
import taema.cli.commands as cli
from taema.core import cgroup, process as inspect
from taema.governor import engine
from taema.store import knowledge

UID = os.getuid()


def tmp():
    return tempfile.mkdtemp()


def make_cfg(state, **extra):
    cfg = {
        "mode": "observe",
        "paths": {
            "state_dir": state,
            "units_dir": tmp(),
            "hooks_dir": tmp(),
            "socket": os.path.join(state, "a.sock"),
            "socket_fallback": os.path.join(state, "b.sock"),
        },
        "timers": {},
        "protected": {},
        "seeds": {},
        "_sources": [],
    }
    cfg.update(extra)
    return cfg


class FakeCg:
    """A cgroup root under a temp dir with user/<uid>/ in place."""

    def __init__(self):
        self.root = tmp()
        os.makedirs(self.base)
        self.patch = mock.patch.object(cgroup, "CG", self.root)

    @property
    def base(self):
        return "%s/user/%d" % (self.root, UID)

    def leaf(self, rel, pids=(), cpu=None):
        d = "%s/%s" % (self.base, rel)
        os.makedirs(d, exist_ok=True)
        self.set_procs(rel, pids)
        if cpu is not None:
            self.set_cpu(rel, cpu)
        return d

    def set_procs(self, rel, pids):
        with open("%s/%s/cgroup.procs" % (self.base, rel), "w") as f:
            f.write("".join("%d\n" % p for p in pids))

    def set_cpu(self, rel, usec):
        with open("%s/%s/cpu.stat" % (self.base, rel), "w") as f:
            f.write("usage_usec %d\nuser_usec 1\n" % usec)

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *a):
        self.patch.stop()


class OkSnap:
    ok = True


class BadSnap:
    ok = False


# ---- inspect / injectable roots -----------------------------------------------------------


class ProcRoot(unittest.TestCase):
    def test_fake_proc_tree(self):
        root = tmp()
        os.makedirs(root + "/77")
        with open(root + "/77/comm", "w") as f:
            f.write("my app\n")
        with open(root + "/77/stat", "w") as f:
            f.write(
                "77 (my (app)) S 5 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0\n"
            )
        with mock.patch.object(inspect, "PROC", root):
            self.assertEqual(inspect.comm(77), "my app")
            self.assertEqual(inspect.ppid_map(), {77: 5})
            self.assertEqual(inspect.starttime(77), 4242)
            self.assertIsNone(inspect.starttime(78))
            self.assertEqual(inspect.uid_of(78), -1)

    def test_ss_failure_marks_snapshot_not_ok(self):
        with mock.patch.object(inspect, "_ss", return_value=None):
            self.assertFalse(inspect.Snapshot().ok)
        self.assertTrue(inspect.Snapshot("", "", "").ok)

    def test_ss_nonzero_rc_is_unknown(self):
        r = types.SimpleNamespace(returncode=1, stdout="")
        with mock.patch.object(inspect.subprocess, "run", return_value=r):
            self.assertIsNone(inspect._ss("-xpn"))
        with mock.patch.object(
            inspect.subprocess, "run", side_effect=subprocess.TimeoutExpired("ss", 1)
        ):
            self.assertIsNone(inspect._ss("-xpn"))


# ---- plan_stop with failed ss ---------------------------------------------------------------


def plan(snap, members=(10, 11), protected=(), hard=False):
    store = knowledge.Store(tmp(), {})
    with (
        mock.patch.object(engine.cgroup, "tree_procs", return_value=list(members)),
        mock.patch.object(
            engine.inspect.ProcTable,
            "scan",
            return_value=engine.inspect.ProcTable.from_ppid({p: 1 for p in members}),
        ),
        mock.patch.object(engine.inspect, "Snapshot", return_value=snap),
        mock.patch.object(engine.inspect, "edges", return_value={}),
        mock.patch.object(engine.inspect, "comm", side_effect=lambda p: "p%d" % p),
        mock.patch.object(
            engine.policy, "app_key", side_effect=lambda p, **kw: "p%d" % p
        ),
        mock.patch.object(
            engine.policy,
            "protected_reason",
            side_effect=lambda p, c, pp=None: "protected" if p in protected else None,
        ),
    ):
        out = engine.plan_stop("/x/user/1/y", {}, store, hard=hard)
    return {d["pid"]: (d["action"], d["why"]) for d in out}


class EdgeScanFailed(unittest.TestCase):
    def test_failed_scan_keeps_members(self):
        out = plan(BadSnap())
        self.assertEqual(out[10], ("share", "edge scan failed"))
        self.assertEqual(out[11][0], "share")

    def test_ok_scan_kills(self):
        self.assertEqual(plan(OkSnap())[10][0], "kill")

    def test_hard_overrides_and_protected_still_skipped(self):
        self.assertEqual(plan(BadSnap(), hard=True)[10][0], "kill")
        self.assertEqual(plan(BadSnap(), protected={10})[10][0], "skip")


# ---- stop: tautology, signalling, hook -------------------------------------------------------


class StopAccounting(unittest.TestCase):
    def run_stop(self, pids, keys, term_survivors, grace=0.3):
        """Fake scope: SIGTERM removes every pid except term_survivors; SIGKILL removes the rest."""
        store = knowledge.Store(tmp(), {})
        with FakeCg() as cg:
            path = cg.leaf("scope-t", pids)
            sent = []

            def fake_signal(p, pids_, sig, cfg):
                sent.append((sig, sorted(pids_)))
                cur = [
                    x
                    for x in cgroup.tree_procs(p)
                    if sig == engine.signal.SIGTERM and x in term_survivors
                ]
                cg.set_procs("scope-t", cur)
                return list(pids_)

            with (
                mock.patch.object(engine, "_signal_all", side_effect=fake_signal),
                mock.patch.object(engine, "self_guard"),
                mock.patch.object(engine, "_wait_each", wraps=engine._wait_each),
                mock.patch.object(
                    engine.inspect.ProcTable,
                    "scan",
                    return_value=engine.inspect.ProcTable.from_ppid(
                        {p: 1 for p in pids}
                    ),
                ),
                mock.patch.object(engine.inspect, "Snapshot", return_value=OkSnap()),
                mock.patch.object(engine.inspect, "edges", return_value={}),
                mock.patch.object(
                    engine.inspect, "comm", side_effect=lambda p: keys[p]
                ),
                mock.patch.object(
                    engine.policy, "app_key", side_effect=lambda p, **kw: keys[p]
                ),
                mock.patch.object(engine.policy, "protected_reason", return_value=None),
            ):
                engine.stop(path, make_cfg(tmp()), store, timeout=grace, passes=1)
        return store, sent

    def test_only_survivors_count_as_sigkill_needed(self):
        store, sent = self.run_stop(
            [4001, 4002], {4001: "polite", 4002: "stubborn"}, {4002}
        )
        self.assertEqual(store.peek("polite")["sigkill_needed"], 0)
        self.assertEqual(store.peek("stubborn")["sigkill_needed"], 1)
        self.assertEqual(store.peek("polite")["killed"], 1)
        self.assertEqual(sent[1][0], engine.signal.SIGKILL)
        self.assertEqual(sent[1][1], [4002])

    def test_killed_once_per_key_and_per_pid_term_ms(self):
        store, _ = self.run_stop([4001, 4002], {4001: "k", 4002: "k"}, {4002})
        self.assertEqual(store.peek("k")["killed"], 1)
        self.assertEqual(store.peek("k")["sigkill_needed"], 1)
        self.assertEqual(len(store.peek("k")["term_exit_ms"]), 2)
        self.assertEqual(store.peek("k")["stops"], 1)

    def test_all_exit_means_no_sigkill(self):
        store, sent = self.run_stop([4001], {4001: "ok"}, set())
        self.assertEqual(store.peek("ok")["sigkill_needed"], 0)
        self.assertEqual(len(sent), 1)


class SignalAll(unittest.TestCase):
    def patched(self, members, protected=None, send=None):
        fd = os.open(os.devnull, os.O_RDONLY)
        send = send or mock.Mock()
        return (
            fd,
            send,
            [
                mock.patch.object(engine.os, "pidfd_open", return_value=fd),
                mock.patch.object(engine.signal, "pidfd_send_signal", send),
                mock.patch.object(engine.cgroup, "tree_procs", return_value=members),
                mock.patch.object(
                    engine.policy, "protected_reason", return_value=protected
                ),
            ],
        )

    def run_it(self, members, protected=None, send=None):
        fd, send, ps = self.patched(members, protected, send)
        for p in ps:
            p.start()
        try:
            return engine._signal_all("/x", [123], 15, {}), send
        finally:
            for p in ps:
                p.stop()

    def test_signals_member(self):
        sent, send = self.run_it([123])
        self.assertEqual(sent, [123])
        send.assert_called_once()

    def test_non_member_not_signalled(self):
        sent, send = self.run_it([5])
        self.assertEqual(sent, [])
        send.assert_not_called()

    def test_protected_not_signalled(self):
        sent, send = self.run_it([123], protected="protected comm x")
        self.assertEqual(sent, [])
        send.assert_not_called()

    def test_permission_and_lookup_errors_caught(self):
        for exc in (PermissionError, ProcessLookupError):
            sent, _ = self.run_it([123], send=mock.Mock(side_effect=exc))
            self.assertEqual(sent, [])

    def test_fallback_to_os_kill(self):
        with (
            mock.patch.object(
                engine.os, "pidfd_open", side_effect=OSError(38, "nosys")
            ),
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[123]),
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
            mock.patch.object(engine.os, "kill", side_effect=PermissionError) as k,
        ):
            self.assertEqual(engine._signal_all("/x", [123], 15, {}), [])
            k.assert_called_once_with(123, 15)


class Hook(unittest.TestCase):
    def test_hook_timeout_kills_group_and_returns(self):
        d = tmp()
        script = os.path.join(d, "h.stop")
        with open(script, "w") as f:
            f.write("#!/bin/sh\nsleep 30\n")
        os.chmod(script, 0o755)
        t0 = time.monotonic()
        with mock.patch.object(engine, "HOOK_TIMEOUT", 0.3):
            engine._run_hook(script)
        self.assertLess(time.monotonic() - t0, 5)

    def test_missing_hook_does_not_raise(self):
        engine._run_hook("/nonexistent/hook")


# ---- knowledge ---------------------------------------------------------------------------------


class KnowledgeHardening(unittest.TestCase):
    def test_graceful_floor_and_reprobe(self):
        s = knowledge.Store(tmp(), {})
        r = s.rec("k")
        r["killed"], r["sigkill_needed"] = 10, 10
        self.assertEqual(s.graceful_timeout("k", 0), (2.0, True))
        self.assertEqual(s.graceful_timeout("k", 10), (2.0, True))
        s.rec("k")["stops"] = 9  # the 10th stop re-probes with the full grace
        self.assertEqual(s.graceful_timeout("k", 10), (10.0, True))
        s2 = knowledge.Store(tmp(), {})
        self.assertEqual(s2.graceful_timeout("fresh", 0.5), (2.0, True))
        for v in (0.0, 1.0, 3.0):
            self.assertGreater(s2.graceful_timeout("fresh", v)[0], 0)

    def test_state_database_and_log_are_private(self):
        d = os.path.join(tmp(), "state")
        s = knowledge.Store(d, {})
        s.bump("x", "seen")
        s.save()
        self.assertEqual(knowledge.Store(d, {}).peek("x")["seen"], 1)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(s.path).st_mode), 0o600)
        s.log(event="t")
        self.assertEqual(stat.S_IMODE(os.stat(s.log_path).st_mode), 0o600)

    def test_legacy_json_is_left_untouched_for_the_importer(self):
        d = tmp()
        path = os.path.join(d, "knowledge.json")
        with open(path, "w") as f:
            f.write("{not json")
        s = knowledge.Store(d, {})
        self.assertEqual(s.data["exes"], {})
        self.assertTrue(os.path.isfile(s.path))
        with open(path) as f:
            self.assertEqual(f.read(), "{not json")

    def test_dirty_flag(self):
        s = knowledge.Store(tmp(), {})
        self.assertFalse(s.save_if_dirty())
        s.bump("x", "seen")
        self.assertTrue(s.dirty)
        self.assertTrue(s.save_if_dirty())
        self.assertFalse(s.dirty)
        s.forget("x")
        self.assertTrue(s.dirty)

    def test_read_only_store_never_writes(self):
        d = tmp()
        s = knowledge.Store(d, {}, read_only=True)
        s.bump("x", "seen")
        s.save()
        self.assertFalse(os.path.exists(s.path))

    def test_feedback_replay_truncates(self):
        d = tmp()
        s = knowledge.Store(d, {})
        s.bump("gone", "seen")
        with open(s.feedback_path, "w") as f:
            f.write(json.dumps({"op": "keep", "key": "adb"}) + "\n")
            f.write("garbage\n")
            f.write(json.dumps({"op": "forget", "key": "gone"}) + "\n")
            f.write(json.dumps({"op": "kill", "key": "foo"}) + "\n")
            f.write(json.dumps({"op": "bogus", "key": "foo"}) + "\n")
            f.write(json.dumps([1]) + "\n")
        self.assertEqual(s.apply_feedback(), 3)
        self.assertEqual(s.peek("adb")["user_keep"], 3.0)
        self.assertEqual(s.peek("foo")["user_kill"], 1.0)
        self.assertNotIn("gone", s.data["exes"])
        self.assertFalse(os.path.exists(s.feedback_path))
        self.assertEqual(s.apply_feedback(), 0)

    def test_cli_feedback_falls_back_to_file(self):
        d = tmp()
        s = knowledge.Store(d, {}, read_only=True)
        cfg = make_cfg(d)
        self.assertEqual(cli.feedback(cfg, s, "keep", "adb"), "queued")
        self.assertEqual(cli.feedback(cfg, s, "forget", "x"), "queued")
        with open(s.feedback_path) as f:
            ops = [json.loads(l) for l in f]
        self.assertEqual([op["v"] for op in ops], [2, 2])
        self.assertEqual([op["op"] for op in ops], ["keep", "forget"])
        self.assertEqual([op["key"] for op in ops], ["adb", "x"])
        self.assertEqual(len({op["id"] for op in ops}), 2)
        self.assertEqual(stat.S_IMODE(os.stat(s.feedback_path).st_mode), 0o600)
        self.assertEqual(knowledge.Store(d, {}).apply_feedback(), 2)

    def test_cli_status_counts_invalid_queued_feedback(self):
        state = tmp()
        store = knowledge.Store(state, {}, read_only=True)
        with open(store.feedback_path, "w") as queue:
            queue.write('{"v":2,"id":"bad","op":"mode","value":"auto"}\n')
            queue.write("{truncated\n")
        cfg = make_cfg(state)
        out = io.StringIO()
        with (
            mock.patch.object(cli, "_load_status", return_value=(cfg, store)),
            mock.patch.object(cli, "ask", return_value=None),
            redirect_stdout(out),
        ):
            self.assertEqual(cli.cmd_status(types.SimpleNamespace()), 3)
        self.assertIn("feedback_invalid: 2", out.getvalue())

    def test_persist_seed(self):
        s = knowledge.Store(tmp(), {"persist": ["tmux"]})
        self.assertTrue(s.is_persistent("tmux"))
        self.assertFalse(s.is_persistent("vim"))
        self.assertEqual(s.default_action("tmux")[0], "share")


# ---- engine: matches, names, gc ----------------------------------------------------------------


class MatchesAndNames(unittest.TestCase):
    def test_empty_match_table_rejected(self):
        engine._warned.clear()
        with (
            mock.patch.object(engine.inspect, "exe", return_value="/x"),
            mock.patch.object(engine.sys, "stderr") as err,
        ):
            self.assertFalse(engine._matches({}, 1))
            self.assertFalse(engine._matches({"env_exclude": {"A": "b"}}, 1))
            self.assertFalse(engine._matches({}, 1))
        self.assertEqual(len(engine._warned), 2)  # logged once per table
        self.assertTrue(err.write.called)

    def test_known_key_matches(self):
        with mock.patch.object(engine.inspect, "comm", return_value="foo"):
            self.assertTrue(engine._matches({"comm": "foo"}, 1))
            self.assertFalse(engine._matches({"comm": "bar"}, 1))

    def test_unit_for_leaf_prefix(self):
        units = [
            {"unit": {"name": "claude-desktop", "kind": "app"}},
            {"unit": {"name": "vm", "kind": "scope"}},
        ]
        self.assertIs(engine.unit_for_leaf(units, "claude-desktop"), units[0])
        self.assertIs(engine.unit_for_leaf(units, "claude-desktop-ab12cd34"), units[0])
        self.assertIsNone(engine.unit_for_leaf(units, "vm-1"))
        self.assertIsNone(engine.unit_for_leaf(units, "claude-desktopx"))

    def test_leaf_slug_always_valid(self):
        seen = set()
        for name in (
            "Xwayland",
            "g++",
            "my app",
            "",
            "UPPER_case.x",
            "plain-name",
            "ünï",
            "a" * 80,
        ):
            for pid in (None, 42):
                slug = engine.leaf_slug(name, pid)
                self.assertTrue(cgroup.valid_rel("shared/" + slug), slug)
                self.assertTrue(cgroup.valid_rel(slug), slug)
            seen.add(engine.leaf_slug(name))
        self.assertEqual(engine.leaf_slug("plain-name", 7), "plain-name-7")
        self.assertNotEqual(engine.leaf_slug("g++"), engine.leaf_slug("g--"))
        self.assertNotEqual(engine.leaf_slug("Xwayland"), "xwayland")


class GcRules(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)
        self.store = knowledge.Store(tmp(), {"share": ["adb"], "persist": ["tmux"]})
        self.t = [1000.0]
        self.keys = {}

    def run_gc(
        self,
        cfg=None,
        idle=None,
        usage=None,
        skip=None,
        noted=None,
        snap=None,
        units=(),
        edge_map=None,
    ):
        cfg = cfg or make_cfg(tmp(), seeds={"share": ["adb"], "persist": ["tmux"]})
        with (
            mock.patch.object(
                engine.inspect.ProcTable,
                "scan",
                return_value=engine.inspect.ProcTable.from_ppid({}),
            ),
            mock.patch.object(
                engine.inspect, "Snapshot", return_value=snap or OkSnap()
            ),
            mock.patch.object(
                engine.inspect,
                "edges",
                return_value={} if edge_map is None else edge_map,
            ),
            mock.patch.object(
                engine.policy,
                "app_key",
                side_effect=lambda p, **kw: self.keys.get(p, "x"),
            ),
        ):
            return engine.gc_candidates(
                cfg,
                list(units),
                self.store,
                {} if idle is None else idle,
                now=lambda: self.t[0],
                usage=usage,
                skip=skip,
                noted=noted,
            )

    def test_persist_and_share_seed_leaves_never_candidates(self):
        self.cg.leaf("shared/tmux-5", [5], cpu=1)
        self.cg.leaf("shared/adb-6", [6], cpu=1)
        self.keys = {5: "tmux", 6: "adb"}
        noted, idle = set(), {}
        self.t[0] = 1e6
        self.assertEqual(self.run_gc(idle=idle, noted=noted), [])
        self.t[0] = 2e6
        self.assertEqual(self.run_gc(idle=idle, noted=noted), [])
        self.assertEqual(noted, {"shared/tmux-5", "shared/adb-6"})
        with open(self.store.log_path) as f:
            self.assertEqual(f.read().count("gc_skip"), 2)  # logged once each

    def test_user_keep_leaf_skipped(self):
        self.cg.leaf("shared/foo-7", [7], cpu=1)
        self.keys = {7: "foo"}
        self.store.bump("foo", "user_keep", 3.0)
        idle = {}
        self.assertEqual(self.run_gc(idle=idle), [])
        self.t[0] += 10000
        self.assertEqual(self.run_gc(idle=idle), [])

    def test_plain_shared_leaf_drains_after_grace(self):
        self.cg.leaf("shared/foo-8", [8], cpu=1)
        self.keys = {8: "foo"}
        idle, usage = {}, {}
        self.assertEqual(self.run_gc(idle=idle, usage=usage), [])
        self.t[0] += 601
        out = self.run_gc(idle=idle, usage=usage)
        self.assertEqual([cgroup.rel(p) for p, _ in out], ["shared/foo-8"])

    def test_cpu_activity_resets_idle_window(self):
        self.cg.leaf("shared/foo-8", [8], cpu=100)
        self.keys = {8: "foo"}
        idle, usage = {}, {}
        self.run_gc(idle=idle, usage=usage)
        self.t[0] += 400
        self.cg.set_cpu("shared/foo-8", 99999)  # busy: window restarts
        self.assertEqual(self.run_gc(idle=idle, usage=usage), [])
        self.t[0] += 400  # 800 s since first sight, 400 since restart
        self.assertEqual(self.run_gc(idle=idle, usage=usage), [])
        self.t[0] += 300  # flat for 700 s >= 600
        self.assertEqual(len(self.run_gc(idle=idle, usage=usage)), 1)

    def test_missing_cpu_stat_falls_back_to_edges_only(self):
        self.cg.leaf("shared/foo-8", [8])
        self.keys = {8: "foo"}
        idle = {}
        self.run_gc(idle=idle)
        self.t[0] += 601
        self.assertEqual(len(self.run_gc(idle=idle)), 1)

    def test_failed_edge_scan_is_not_idle(self):
        self.cg.leaf("shared/foo-8", [8], cpu=1)
        idle = {}
        self.run_gc(idle=idle, snap=BadSnap())
        self.t[0] += 5000
        self.assertEqual(self.run_gc(idle=idle, snap=BadSnap()), [])

    def test_runtime_unit_uses_configured_no_attachment_grace(self):
        path = self.cg.leaf("app-vm-test", [42], cpu=1)
        unit = {
            "unit": {"name": "app-vm", "kind": "app", "stop_when_unneeded": True},
            "gc": {"no_attach_grace": 120},
        }
        idle = {}

        self.assertEqual(self.run_gc(idle=idle, units=[unit]), [])
        self.t[0] += 119
        self.assertEqual(self.run_gc(idle=idle, units=[unit]), [])
        self.t[0] += 1
        candidates = self.run_gc(idle=idle, units=[unit])
        self.assertEqual(candidates, [(path, "no attachment for 120s")])

    def test_detached_runtime_grace_ignores_cpu_activity_and_child_processes(self):
        path = self.cg.leaf("app-podman-test", [42, 43], cpu=1)
        unit = {
            "unit": {
                "name": "app-podman",
                "kind": "app",
                "stop_when_unneeded": True,
            },
            "match": {"comm": "catatonit"},
            "children": [{"name": "conmon", "comm": "conmon"}],
            "gc": {"keep_while_children": True, "no_attach_grace": 120},
        }
        idle, usage = {}, {}

        self.assertEqual(self.run_gc(idle=idle, usage=usage, units=[unit]), [])
        self.t[0] += 60
        self.cg.set_cpu("app-podman-test", 10000)
        self.assertEqual(self.run_gc(idle=idle, usage=usage, units=[unit]), [])
        self.t[0] += 60

        self.assertEqual(
            self.run_gc(idle=idle, usage=usage, units=[unit]),
            [(path, "no attachment for 120s")],
        )

    def test_runtime_socket_peers_hold_the_scope_past_no_attachment_grace(self):
        self.cg.leaf("app-vm-test", [42], cpu=1)
        unit = {
            "unit": {"name": "app-vm", "kind": "app", "stop_when_unneeded": True},
            "gc": {"no_attach_grace": 10},
        }
        idle = {}
        self.run_gc(idle=idle, units=[unit], edge_map={42: [{"kind": "qmp"}]})
        self.t[0] += 20
        self.assertEqual(
            self.run_gc(idle=idle, units=[unit], edge_map={42: [{"kind": "qmp"}]}),
            [],
        )

    def test_missing_qmp_socket_is_a_runtime_quit_signal(self):
        path = self.cg.leaf("app-vm-test", [42], cpu=1)
        unit = {
            "unit": {"name": "app-vm", "kind": "app", "stop_when_unneeded": True},
            "gc": {"qmp_socket": True},
        }
        with mock.patch.object(
            engine.inspect, "qmp_socket_paths", return_value=[path + ".monitor"]
        ):
            candidates = self.run_gc(units=[unit])
        self.assertEqual(candidates[0][0], path)
        self.assertTrue(candidates[0][1].startswith("QMP socket gone:"))

    def test_missing_podman_api_socket_is_a_runtime_quit_signal(self):
        path = self.cg.leaf("app-podman-test", [42], cpu=1)
        runtime = os.path.join(self.cg.root, "runtime")
        os.makedirs(runtime)
        unit = {
            "unit": {"name": "app-podman", "kind": "app", "stop_when_unneeded": True},
            "gc": {
                "socket_env": "XDG_RUNTIME_DIR",
                "socket_path": "podman/podman.sock",
            },
        }
        with mock.patch.object(
            engine.inspect,
            "environ",
            return_value={"XDG_RUNTIME_DIR": runtime},
        ):
            candidates = self.run_gc(units=[unit])
        self.assertEqual(candidates[0][0], path)
        self.assertTrue(candidates[0][1].startswith("runtime socket gone:"))

    def test_libvirt_unit_groups_qemu_roots_by_qmp_socket(self):
        unit = {
            "unit": {"name": "app-libvirt-qemu", "kind": "app", "group_by_qmp": True},
            "match": {"cmdline_contains": "qemu-system-"},
        }
        table = engine.inspect.ProcTable.from_ppid({42: 1, 43: 1})
        with (
            mock.patch.object(
                engine.policy, "session_cgroups", return_value=["session"]
            ),
            mock.patch.object(engine.cgroup, "procs", return_value=[42, 43]),
            mock.patch.object(engine.inspect.ProcTable, "scan", return_value=table),
            mock.patch.object(engine, "_matches", return_value=True),
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
            mock.patch.object(
                engine.inspect,
                "qmp_socket_paths",
                side_effect=lambda pid: [
                    "/run/user/1000/libvirt/qemu/vm-%d.monitor" % pid
                ],
            ),
        ):
            ops = engine.adopt_plan(make_cfg(tmp()), [unit])

        self.assertEqual(len(ops), 2)
        self.assertEqual({tuple(op["pids"]) for op in ops}, {(42,), (43,)})
        self.assertEqual(len({op["scope"] for op in ops}), 2)

    def test_libvirt_roots_without_qmp_sockets_do_not_merge_by_session(self):
        unit = {
            "unit": {"name": "app-libvirt-qemu", "kind": "app", "group_by_qmp": True},
            "match": {"cmdline_contains": "qemu-system-"},
        }
        table = engine.inspect.ProcTable.from_ppid({42: 1, 43: 1})
        with (
            mock.patch.object(
                engine.policy, "session_cgroups", return_value=["session"]
            ),
            mock.patch.object(engine.cgroup, "procs", return_value=[42, 43]),
            mock.patch.object(engine.inspect.ProcTable, "scan", return_value=table),
            mock.patch.object(engine, "_matches", return_value=True),
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
            mock.patch.object(engine.inspect, "qmp_socket_paths", return_value=[]),
            mock.patch.object(engine.cgroup, "proc_cgroup", return_value="/session-1"),
        ):
            ops = engine.adopt_plan(make_cfg(tmp()), [unit])

        self.assertEqual(len(ops), 2)
        self.assertEqual(len({op["scope"] for op in ops}), 2)

    def test_stop_why_names_the_management_client(self):
        path = self.cg.leaf("app-vm-42", [42])
        unit = {"unit": {"name": "app-vm", "kind": "app"}}
        for edge_kind, detail in (
            ("qmp", "/run/user/1000/libvirt/qemu/vm.monitor"),
            ("podman_api", "/run/user/1000/podman/podman.sock"),
        ):
            with self.subTest(edge_kind=edge_kind):
                with (
                    mock.patch.object(engine, "vetoes_for_scope", return_value=[]),
                    mock.patch.object(
                        engine.policy, "protected_reason", return_value=None
                    ),
                    mock.patch.object(
                        engine.inspect.ProcTable,
                        "scan",
                        return_value=engine.inspect.ProcTable.from_ppid({}),
                    ),
                    mock.patch.object(
                        engine.inspect,
                        "LazySnapshot",
                        return_value=types.SimpleNamespace(get=lambda: OkSnap()),
                    ),
                    mock.patch.object(
                        engine.inspect,
                        "edges",
                        return_value={
                            42: [
                                {
                                    "kind": edge_kind,
                                    "detail": detail,
                                    "peers": [43],
                                }
                            ]
                        },
                    ),
                    mock.patch.object(
                        engine.inspect,
                        "comm",
                        side_effect={
                            42: "qemu-system-x86",
                            43: "virt-manager",
                        }.__getitem__,
                    ),
                    mock.patch.object(engine.policy, "app_key", return_value="qemu"),
                ):
                    [decision] = engine.plan_stop(
                        path, make_cfg(tmp()), self.store, unit, force=True
                    )

                self.assertEqual(decision["action"], "share")
                self.assertIn(edge_kind, decision["why"])
                self.assertIn("virt-manager (pid 43)", decision["why"])

    def test_skip_set_leaves_ignored_and_pruned(self):
        self.cg.leaf("shared/foo-8", [], cpu=1)
        skip = {"shared/foo-8", "shared/gone-1"}
        self.assertEqual(self.run_gc(skip=skip), [])
        self.assertEqual(skip, {"shared/foo-8"})


# ---- daemon ------------------------------------------------------------------------------------


class DaemonSocket(unittest.TestCase):
    def setUp(self):
        self.state = tmp()
        self.d = daemon.Daemon(make_cfg(self.state))
        self.addCleanup(self.close)

    def close(self):
        for fd in list(self.d.owners):
            os.close(fd)
        if self.d.srv:
            self.d.srv.close()

    def test_bad_shapes(self):
        for msg in (
            [],
            "x",
            None,
            5,
            1.5,
            {"cmd": 5},
            {"cmd": None},
            {},
            {"cmd": "register"},
            {"cmd": "register", "scope": 5, "owner": 1},
            {"cmd": "register", "scope": "scope-x"},
            {"cmd": "register", "scope": "scope-x", "owner": "7"},
            {"cmd": "register", "scope": "scope-x", "owner": True},
            {"cmd": "feedback", "op": 1, "key": []},
            {"cmd": "feedback"},
        ):
            r = self.d.handle(msg)
            self.assertIn("error", r, msg)

    def test_register_validation(self):
        me = os.getpid()
        for scope, owner in (
            ("scope-x", 1),
            ("scope-x", 0),
            ("scope-x", -4),
            ("../etc", me),
            ("Scope-X", me),
            ("a//b", me),
            ("", me),
        ):
            self.assertIn(
                "error",
                self.d.handle({"cmd": "register", "scope": scope, "owner": owner}),
                (scope, owner),
            )
        with mock.patch.object(daemon.inspect, "uid_of", return_value=UID + 1):
            self.assertIn(
                "error",
                self.d.handle({"cmd": "register", "scope": "scope-x", "owner": me}),
            )
        self.assertEqual(self.d.owners, {})

    def test_register_ok_and_deduped(self):
        msg = {"cmd": "register", "scope": "scope-x", "owner": os.getpid()}
        self.assertEqual(self.d.handle(msg), {"watching": True})
        self.assertEqual(self.d.handle(msg), {"watching": True})
        self.assertEqual(len(self.d.owners), 1)
        self.assertEqual(
            self.d.handle({"cmd": "status"})["owners"],
            [{"scope": "scope-x", "owner": os.getpid()}],
        )

    def test_feedback_command(self):
        self.assertEqual(
            self.d.handle({"cmd": "feedback", "op": "keep", "key": "adb"}), {"ok": True}
        )
        self.assertEqual(self.d.store.peek("adb")["user_keep"], 3.0)
        self.assertFalse(self.d.store.dirty)  # saved
        self.assertIn(
            "error", self.d.handle({"cmd": "feedback", "op": "nuke", "key": "adb"})
        )

    def converse(self, payload, send_close=False):
        """One real round trip over a unix socket pair against Daemon.serve."""
        path = os.path.join(tmp(), "s.sock")
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
        srv.listen(1)
        self.addCleanup(srv.close)
        c = socket.socket(socket.AF_UNIX)
        self.addCleanup(c.close)
        c.connect(path)
        if payload:
            c.sendall(payload)
        if send_close:
            c.shutdown(socket.SHUT_WR)
        self.d.serve(srv)
        c.settimeout(2)
        return json.loads(c.recv(65536))

    def test_serve_survives_junk(self):
        for payload in (
            b"[1,2\n",
            b"\xff\xfe\n",
            b"[]\n",
            b"5\n",
            b'"x"\n',
            b"null\n",
            b'{"cmd": []}\n',
            b'{"cmd":"register","scope":{},"owner":[]}\n',
        ):
            self.assertIn("error", self.converse(payload), payload)

    def test_serve_accepts_eof_framed_and_valid(self):
        self.assertIn("mode", self.converse(b'{"cmd":"status"}', send_close=True))
        self.assertIn("mode", self.converse(b'{"cmd":"status"}\n'))

    def test_slow_client_times_out(self):
        t0 = time.monotonic()
        r = self.converse(b"")
        self.assertLess(time.monotonic() - t0, 2)
        self.assertIn("error", r)

    def test_oversize_request_is_capped(self):
        r = self.converse(b"x" * 200000)
        self.assertIn("error", r)

    def test_foreign_uid_rejected(self):
        fake = mock.patch.object(daemon.os, "getuid", return_value=UID + 1)
        with fake:
            r = self.converse(b'{"cmd":"status"}\n')
        self.assertEqual(r, {"error": "forbidden"})

    def test_socket_rebound_when_vanished_and_private(self):
        path = os.path.join(tmp(), "t.sock")
        with mock.patch.dict(os.environ, {"TAEMA_SOCKET": path}):
            self.d.check_socket()
            self.assertEqual(
                stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0
            )  # owner only
            os.unlink(path)
            self.d.check_socket()
            self.assertTrue(os.path.exists(path))
            first = self.d.srv
            self.d.check_socket()
            self.assertIs(self.d.srv, first)  # untouched while the path is there

    def test_guarded_logs_instead_of_raising(self):
        def boom():
            raise RuntimeError("x")

        self.d.guarded(boom)
        self.d.guarded(lambda: 1 / 0)
        with open(self.d.store.log_path) as f:
            self.assertIn("RuntimeError", f.read())


class DaemonActions(unittest.TestCase):
    def setUp(self):
        self.state = tmp()
        cfg = make_cfg(self.state, mode="enforce")
        self.d = daemon.Daemon(cfg)
        self.cg = FakeCg()
        self.cg.__enter__()
        self.addCleanup(self.cg.__exit__)

    def log(self):
        with open(self.d.store.log_path) as f:
            return f.read()

    def test_stop_leaf_uses_prefix_unit_and_hook(self):
        unit = {"unit": {"name": "claude-desktop", "kind": "app"}}
        self.d.units = [unit]
        self.cg.leaf("claude-desktop-ab12cd34", [])
        with (
            mock.patch.object(daemon.engine, "stop") as st,
            mock.patch.object(daemon.policy, "hook_for", return_value="/h"),
        ):
            self.d.stop_leaf("claude-desktop-ab12cd34", "t")
        self.assertIs(st.call_args[0][3], unit)
        self.assertEqual(st.call_args[1]["hook"], "/h")

    def test_stop_leaf_broad_errors_caught(self):
        self.cg.leaf("scope-x", [])
        with mock.patch.object(
            daemon.engine, "stop", side_effect=PermissionError("no")
        ):
            self.d.stop_leaf("scope-x", "t")
        self.assertIn("stop_error", self.log())

    def test_end_session_keeps_daemon_running_and_uses_prefix_unit(self):
        unit = {"unit": {"name": "app", "kind": "app"}}
        self.d.units = [unit]
        self.cg.leaf("app-1234", [])
        with mock.patch.object(daemon.engine, "stop") as st:
            self.d.end_session()
        self.assertFalse(self.d.stopping)
        self.assertIs(st.call_args[0][3], unit)
        self.assertIn("hook", st.call_args[1])

    def test_gc_stopped_only_when_removed(self):
        self.cg.leaf("shared/foo-1", [])
        path = self.cg.base + "/shared/foo-1"
        rep = {
            "scope": "shared/foo-1",
            "removed": False,
            "left": [1],
            "decisions": [{"action": "skip", "pid": 1}],
        }
        with (
            mock.patch.object(
                daemon.engine, "gc_candidates", return_value=[(path, "idle")]
            ),
            mock.patch.object(daemon.engine, "stop", return_value=rep),
        ):
            self.d.gc_pass()
        out = self.log()
        self.assertNotIn("gc_stopped", out)
        self.assertIn("kept: protected member", out)
        self.assertIn("shared/foo-1", self.d.gc_skip)
        rep2 = dict(rep, removed=True)
        with (
            mock.patch.object(
                daemon.engine, "gc_candidates", return_value=[(path, "idle")]
            ),
            mock.patch.object(daemon.engine, "stop", return_value=rep2),
        ):
            self.d.gc_pass()
        self.assertIn("gc_stopped", self.log())


class CliRun(unittest.TestCase):
    def test_owner_gone_dies_before_attach(self):
        with FakeCg() as cg:
            args = types.SimpleNamespace(
                name="x", join=False, owner=2**22 + 12345, bind=False, cmd=["true"]
            )
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(cli.engine, "helper_attach") as att,
                mock.patch.object(cli.os, "execvp") as ex,
                mock.patch.object(inspect, "PROC", tmp()),
            ):
                rc = cli.cmd_run(args)
            self.assertNotEqual(rc, 0)
            att.assert_not_called()
            ex.assert_not_called()
            self.assertFalse(os.path.isdir(cg.base + "/scope-x"))

    def test_register_before_attach(self):
        order = []
        with FakeCg():
            args = types.SimpleNamespace(
                name="x", join=False, owner=os.getpid(), bind=False, cmd=["true"]
            )
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli,
                    "ask",
                    side_effect=lambda *a, **k: (
                        order.append("ask") or {"watching": True}
                    ),
                ),
                mock.patch.object(
                    cli.engine,
                    "helper_attach",
                    side_effect=lambda *a: order.append("attach"),
                ),
                mock.patch.object(cli.os, "execvp"),
            ):
                cli.cmd_run(args)
        self.assertEqual(order, ["ask", "attach"])


if __name__ == "__main__":
    unittest.main()
