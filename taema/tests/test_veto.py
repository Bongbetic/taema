"""Veto and undo behavior through the CLI and daemon command boundary."""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from taema.daemon import service as daemon
import taema.cli.commands as cli
from taema.cli import targets
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg, tmp


class VetoCommands(unittest.TestCase):
    def run_cli_offline(self, argv, store):
        cfg = make_cfg(store.dir, mode="auto")
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(cli, "ask", return_value=None),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def queued(self, store):
        with open(store.feedback_path) as f:
            return [json.loads(line) for line in f]

    def test_do_not_kill_alias_queues_a_matching_app_veto(self):
        for argv in (
            ["dnk", "firefox"],
            ["never", "app:firefox"],
            ["--do-not-kill", "firefox"],
        ):
            with self.subTest(argv=argv):
                s = knowledge.Store(tmp(), {})
                rc, out, _err = self.run_cli_offline(argv, s)
                self.assertEqual(rc, 0)
                self.assertIn("vetoed app firefox", out)
                self.assertEqual(self.queued(s)[0]["op"], "veto")
                self.assertEqual(self.queued(s)[0]["target"]["value"], "firefox")

    def test_no_target_veto_uses_the_latest_automatic_stop(self):
        s = knowledge.Store(tmp(), {})
        action = s.record_auto_action(
            "leftover/firefox", "pair stop", [("browser", "firefox")], ["firefox"]
        )
        rc, out, _err = self.run_cli_offline(["do-not-kill"], s)
        self.assertEqual(rc, 0)
        self.assertIn("vetoed app firefox", out)
        self.assertEqual(self.queued(s)[0]["op"], "veto")
        self.assertEqual(action["scope"], "leftover/firefox")

    def test_undo_and_forget_veto_queue_explicit_operations(self):
        s = knowledge.Store(tmp(), {})
        s.record_auto_action("leftover/vite", "pair stop", [("npm", "vite")], ["vite"])
        rc, out, _err = self.run_cli_offline(["undo"], s)
        self.assertEqual(rc, 0)
        self.assertIn("undo: leftover/vite", out)
        self.assertEqual(self.queued(s)[0]["op"], "undo")

        s.add_veto("app", "vite")
        self.assertEqual(
            s.match_veto(members=[{"pid": 7, "apps": ["vite"]}])["value"], "vite"
        )
        rc, out, _err = self.run_cli_offline(["forget", "--veto", "vite"], s)
        self.assertEqual(rc, 0)
        self.assertIn("forgot veto", out)
        self.assertEqual(self.queued(s)[1]["op"], "unveto")
        self.assertIsNone(s.match_veto(members=[{"pid": 7, "apps": ["vite"]}]))

    def test_plain_forget_does_not_remove_a_veto(self):
        s = knowledge.Store(tmp(), {})
        s.add_veto("app", "firefox")
        rc, _out, _err = self.run_cli_offline(["forget", "firefox"], s)
        self.assertEqual(rc, 0)
        self.assertEqual(self.queued(s)[0]["op"], "forget")
        self.assertEqual(
            s.match_veto(members=[{"pid": 7, "apps": ["firefox"]}])["value"], "firefox"
        )

    def test_forget_can_remove_a_veto_for_a_dead_pid(self):
        s = knowledge.Store(tmp(), {})
        s.add_veto("pid", "42", start=1234)
        rc, _out, _err = self.run_cli_offline(["forget", "--veto", "pid:42"], s)
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.queued(s)[0]["target"], {"kind": "pid", "value": "42", "start": 1234}
        )

    def test_kill_refuses_a_pending_offline_scope_veto_with_exit_four(self):
        s = knowledge.Store(tmp(), {})
        with FakeCg() as cg:
            cg.leaf("scope-x")
            cfg = make_cfg(s.dir, mode="enforce")
            with open(s.feedback_path, "w") as f:
                f.write(
                    json.dumps(
                        {
                            "v": 1,
                            "id": "pending-1",
                            "op": "veto",
                            "target": {"kind": "scope", "value": "scope-x"},
                        }
                    )
                    + "\n"
                )
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, s, [])),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                rc = cli.main(["kill", "scope-x"])
        self.assertEqual(rc, 4)
        self.assertIn("vetoed", err.getvalue())

    def test_kill_refuses_a_pending_offline_hold_with_exit_four(self):
        s = knowledge.Store(tmp(), {})
        with FakeCg() as cg:
            cgroup_scope = "scope-x"
            cg.leaf(cgroup_scope)
            cfg = make_cfg(s.dir, mode="enforce")
            with open(s.feedback_path, "w") as queue:
                queue.write(
                    json.dumps(
                        {
                            "v": 2,
                            "id": "hold-scope-x",
                            "op": "hold",
                            "scope": cgroup_scope,
                            "held": True,
                        }
                    )
                    + "\n"
                )
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, s, [])),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                rc = cli.main(["kill", cgroup_scope])
        self.assertEqual(rc, 4)
        self.assertIn("held", err.getvalue())

    def test_daemon_accepts_versioned_veto_action_once(self):
        d = daemon.Daemon(make_cfg(tmp(), mode="auto"))
        msg = {
            "cmd": "feedback",
            "v": 1,
            "id": "veto-1",
            "op": "veto",
            "target": {"kind": "app", "value": "firefox", "start": None},
        }
        d.store.defer_writes = True
        self.assertTrue(d.handle(msg)["ok"])
        self.assertTrue(d.handle(msg)["duplicate"])
        self.assertEqual(
            d.store.match_veto(members=[{"pid": 9, "start": 10, "apps": ["firefox"]}])[
                "value"
            ],
            "firefox",
        )
        reopened = knowledge.Store(d.store.dir, {}, read_only=True)
        self.assertEqual(
            reopened.match_veto(members=[{"pid": 9, "start": 10, "apps": ["firefox"]}])[
                "value"
            ],
            "firefox",
        )

    def test_pid_target_captures_the_current_process_instance(self):
        s = knowledge.Store(tmp(), {})
        with (
            mock.patch.object(cli.inspect, "starttime", return_value=456),
            mock.patch.object(cli.inspect, "uid_of", return_value=os.getuid()),
        ):
            self.assertEqual(
                cli.veto_target("pid:42", s),
                {"kind": "pid", "value": "42", "start": 456},
            )

    def test_pid_veto_uses_selected_process_instance_and_rejects_reuse(self):
        target = targets.Target(
            "pid", "42", "pid:42", scope="scope-x", pid=42, start=1234
        )
        store = knowledge.Store(tmp(), {})
        with (
            mock.patch.object(cli, "_target_candidates", return_value=[target]),
            mock.patch.object(cli.inspect, "starttime", return_value=1234),
        ):
            rc, _out, _err = self.run_cli_offline(["do-not-kill", "pid:42"], store)
        self.assertEqual(rc, 0)
        self.assertEqual(self.queued(store)[0]["target"]["start"], 1234)

        stale = knowledge.Store(tmp(), {})
        with (
            mock.patch.object(cli, "_target_candidates", return_value=[target]),
            mock.patch.object(cli.inspect, "starttime", return_value=5678),
        ):
            rc, _out, err = self.run_cli_offline(["do-not-kill", "pid:42"], stale)
        self.assertEqual(rc, 2)
        self.assertIn("changed since target selection", err)
        self.assertFalse(os.path.exists(stale.feedback_path))


class DaemonStopPaths(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.d = daemon.Daemon(make_cfg(tmp(), mode="enforce"))

    def events(self):
        with open(self.d.store.log_path) as f:
            return [json.loads(line) for line in f]

    def test_owner_exit_scope_veto_stops_at_authorization(self):
        self.cg.leaf("scope-owner")
        self.d.store.add_veto("scope", "scope-owner")
        with mock.patch.object(daemon.engine, "stop") as stop:
            self.d.stop_leaf("scope-owner", "owner exited")
        stop.assert_not_called()
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "owner_exit"
                for e in self.events()
            )
        )

    def test_owner_exit_stop_is_available_to_undo(self):
        self.cg.leaf("scope-owner")
        report = {"decisions": [{"key": "firefox", "action": "kill"}], "removed": True}
        with mock.patch.object(daemon.engine, "stop", return_value=report):
            self.d.stop_leaf("scope-owner", "owner exited")
        action = self.d.store.auto_action()
        self.assertEqual(action["scope"], "scope-owner")
        self.assertEqual(action["apps"], ["firefox"])

    def test_gc_scope_veto_keeps_the_candidate(self):
        path = self.cg.leaf("scope-gc")
        self.d.store.add_veto("scope", "scope-gc")
        with (
            mock.patch.object(
                daemon.engine, "gc_candidates", return_value=[(path, "idle")]
            ),
            mock.patch.object(self.d, "sync_leaf_watches"),
            mock.patch.object(daemon.engine, "stop") as stop,
        ):
            result = self.d.gc_pass()
        stop.assert_not_called()
        self.assertEqual(result, [["scope-gc", "idle", "would"]])
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "gc_stop"
                for e in self.events()
            )
        )

    def test_session_end_scope_veto_keeps_the_scope(self):
        self.cg.leaf("scope-session")
        self.d.store.add_veto("scope", "scope-session")
        with mock.patch.object(daemon.engine, "stop") as stop:
            self.d.end_session()
        stop.assert_not_called()
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "session_end"
                for e in self.events()
            )
        )

    def test_session_end_stop_is_available_to_undo(self):
        self.cg.leaf("scope-session")
        report = {"decisions": [{"key": "firefox", "action": "kill"}], "removed": True}
        with mock.patch.object(daemon.engine, "stop", return_value=report):
            self.d.end_session()
        action = self.d.store.auto_action()
        self.assertEqual(action["scope"], "scope-session")
        self.assertEqual(action["apps"], ["firefox"])

    def test_vetoed_job_survivor_is_not_signalled_after_pair_stop_decision(self):
        self.d.store.add_veto("app", "vite")
        survivor = {"key": "vite", "pid": 42, "start": 100}
        with (
            mock.patch.object(daemon.engine, "signal_survivors") as signal_survivors,
            mock.patch.object(daemon.engine, "stop") as stop,
        ):
            self.d.auto_stop_survivors(
                "20.1", "npm", [survivor], {"vite": ("stop", 1.0, "answered stop")}
            )
        signal_survivors.assert_not_called()
        stop.assert_not_called()
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "job_survivors"
                for e in self.events()
            )
        )

    def test_gui_survivor_veto_is_enforced_when_gc_routes_its_close(self):
        path = self.cg.leaf("leftover/gui-77", [42])
        self.d.store.add_veto("app", "firefox")
        left = {"key": "firefox", "pid": 42, "start": 100}
        rid = (77, 1)
        self.d.lineage.closed = [rid]
        self.d.lineage.born = []
        self.d.lineage.ghosts = {rid: {"key": "niri", "terminal": False}}
        self.d.lineage.vanished = mock.Mock(return_value=[])
        self.d.lineage.leftovers_of = mock.Mock(return_value=[left])
        with (
            mock.patch.object(
                self.d,
                "attribute",
                return_value={"firefox": ("stop", 1.0, "answered stop")},
            ),
            mock.patch.object(
                daemon.engine,
                "run_ops",
                return_value=[{"done": True, "scope": "leftover/gui-77", "pids": [42]}],
            ),
            mock.patch.object(
                daemon.engine, "gc_candidates", return_value=[(path, "pair stop")]
            ),
            mock.patch.object(self.d, "sync_leaf_watches"),
            mock.patch.object(daemon.inspect, "starttime", return_value=100),
            mock.patch.object(daemon.policy, "app_key", return_value="firefox"),
            mock.patch.object(daemon.engine, "stop") as stop,
        ):
            self.d.after_observe()  # GUI close contains the survivor in leftover/gui-77.
            result = (
                self.d.gc_pass()
            )  # Its later automatic stop is denied by the app veto.
        stop.assert_not_called()
        self.assertEqual(result, [["leftover/gui-77", "pair stop", "would"]])
        self.assertTrue(
            any(
                e.get("event") == "vetoed" and e.get("trigger") == "gc_stop"
                for e in self.events()
            )
        )
