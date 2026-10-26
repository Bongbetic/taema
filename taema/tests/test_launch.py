"""Launch-time scoping tests (issue #62).

`taema launch` reserves an app scope through `launch_prepare`, moves
itself in, registers the instance through `launch_claim`, and execs.
Reservations expire after 5 seconds; the empty leaf is removed.
"""

import os
import unittest
from unittest import mock

from tests.test_phase0 import FakeCg, make_cfg
from tests.test_windows import make_daemon, register


def make_launch_daemon(**over):
    from taema.daemon import service

    cg = FakeCg().__enter__()
    cfg = make_cfg(os.path.join(cg.root, "state"), mode="enforce", **over)
    daemon = service.Daemon(cfg)
    daemon._launch_cg = cg
    register(daemon)
    return daemon


class LaunchPrepareTest(unittest.TestCase):
    def test_prepare_reserves_scope_and_leaf(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        with mock.patch("time.time", return_value=1000.0):
            reply = daemon.launch_prepare(
                {
                    "cmd": "launch_prepare",
                    "app": "x",
                    "pid": os.getpid(),
                    "session": "elsewhere",
                }
            )
        self.assertTrue(reply.get("ok"), reply)
        self.assertEqual(reply["scope"], "app-x")
        self.assertEqual(reply["via"], "helper")
        self.assertEqual(reply["expires"], 1005.0)
        from taema.core import cgroup

        self.assertTrue(os.path.isdir(os.path.join(cgroup.base(), "app-x")))
        reservation = daemon.launch_reservations["app-x"]
        self.assertEqual(reservation["app"], "x")
        self.assertEqual(reservation["expires"], 1005.0)

    def test_prepare_routes_via_agent_when_session_agent_is_up(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.agents["s1"] = {"state": "up", "pid": os.getpid()}
        reply = daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        self.assertEqual(reply.get("via"), "agent")

    def test_prepare_rejects_bad_requests(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        for msg in (
            {"cmd": "launch_prepare", "app": "../evil", "pid": os.getpid()},
            {"cmd": "launch_prepare", "app": "x", "pid": 999999999},
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "unit": 42},
            {"cmd": "launch_prepare", "pid": os.getpid()},
        ):
            reply = daemon.launch_prepare(msg)
            self.assertIn("error", reply, msg)

    def test_prepare_suffixes_a_live_collision(self):
        from taema.core import cgroup

        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon._launch_cg.leaf("app-x", [os.getpid()], cpu=0)
        reply = daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        self.assertEqual(reply.get("scope"), "app-x-2")
        self.assertTrue(os.path.isdir(os.path.join(cgroup.base(), "app-x-2")))


class LaunchClaimTest(unittest.TestCase):
    def test_claim_registers_instance_and_drops_reservation(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        from taema.core import cgroup

        leaf = os.path.join(cgroup.base(), "app-x")
        with open(os.path.join(leaf, "cgroup.procs"), "w") as handle:
            handle.write("%d\n" % os.getpid())
        reply = daemon.launch_claim(
            {
                "cmd": "launch_claim",
                "scope": "app-x",
                "pid": os.getpid(),
                "app": "x",
            }
        )
        self.assertTrue(reply.get("ok"), reply)
        self.assertNotIn("app-x", daemon.launch_reservations)
        mapping = daemon.store.data.get("launch_apps", {}).get("app-x", {})
        self.assertEqual(mapping.get("app"), "x")
        instance = daemon.store.latest_app_instance("x")
        self.assertIsNotNone(instance)
        self.assertEqual(instance.get("launched_by"), "launch")
        self.assertEqual(instance.get("scope"), "app-x")

    def test_claim_rejects_pid_outside_scope(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        reply = daemon.launch_claim(
            {"cmd": "launch_claim", "scope": "app-x", "pid": os.getpid(), "app": "x"}
        )
        self.assertIn("error", reply)

    def test_claim_rejects_unknown_scope(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        reply = daemon.launch_claim(
            {"cmd": "launch_claim", "scope": "app-nope", "pid": os.getpid(), "app": "x"}
        )
        self.assertIn("error", reply)

    def test_claim_with_bind_watches_owner(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.launch_prepare(
            {
                "cmd": "launch_prepare",
                "app": "x",
                "pid": os.getpid(),
                "session": "s1",
                "owner": os.getpid(),
            }
        )
        from taema.core import cgroup

        leaf = os.path.join(cgroup.base(), "app-x")
        with open(os.path.join(leaf, "cgroup.procs"), "w") as handle:
            handle.write("%d\n" % os.getpid())
        reply = daemon.launch_claim(
            {"cmd": "launch_claim", "scope": "app-x", "pid": os.getpid(), "app": "x"}
        )
        self.assertTrue(reply.get("ok"), reply)
        self.assertTrue(any(leaf == "app-x" for leaf, _p, _s in daemon.owners.values()))


class LaunchReleaseTest(unittest.TestCase):
    def test_release_drops_reservation_and_removes_empty_leaf(self):
        from taema.core import cgroup

        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        leaf = os.path.join(cgroup.base(), "app-x")
        reply = daemon.launch_release({"cmd": "launch_release", "scope": "app-x"})
        self.assertTrue(reply.get("ok"), reply)
        self.assertNotIn("app-x", daemon.launch_reservations)
        self.assertFalse(os.path.isdir(leaf))

    def test_release_keeps_a_live_leaf(self):
        from taema.core import cgroup

        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.launch_prepare(
            {"cmd": "launch_prepare", "app": "x", "pid": os.getpid(), "session": "s1"}
        )
        leaf = os.path.join(cgroup.base(), "app-x")
        with open(os.path.join(leaf, "cgroup.procs"), "w") as handle:
            handle.write("%d\n" % os.getpid())
        reply = daemon.launch_release({"cmd": "launch_release", "scope": "app-x"})
        self.assertTrue(reply.get("ok"), reply)
        self.assertTrue(os.path.isdir(leaf))


class LaunchSweepTest(unittest.TestCase):
    def test_expired_empty_reservation_is_reaped(self):
        from taema.core import cgroup

        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        with mock.patch("time.time", return_value=1000.0):
            daemon.launch_prepare(
                {
                    "cmd": "launch_prepare",
                    "app": "x",
                    "pid": os.getpid(),
                    "session": "s1",
                }
            )
        leaf = os.path.join(cgroup.base(), "app-x")
        daemon.launch_sweep(now=1006.0)
        self.assertNotIn("app-x", daemon.launch_reservations)
        self.assertFalse(os.path.isdir(leaf))

    def test_unexpired_reservation_survives(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        with mock.patch("time.time", return_value=1000.0):
            daemon.launch_prepare(
                {
                    "cmd": "launch_prepare",
                    "app": "x",
                    "pid": os.getpid(),
                    "session": "s1",
                }
            )
        daemon.launch_sweep(now=1004.0)
        self.assertIn("app-x", daemon.launch_reservations)

    def test_expired_live_scope_keeps_leaf_but_drops_reservation(self):
        from taema.core import cgroup

        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        with mock.patch("time.time", return_value=1000.0):
            daemon.launch_prepare(
                {
                    "cmd": "launch_prepare",
                    "app": "x",
                    "pid": os.getpid(),
                    "session": "s1",
                }
            )
        leaf = os.path.join(cgroup.base(), "app-x")
        with open(os.path.join(leaf, "cgroup.procs"), "w") as handle:
            handle.write("%d\n" % os.getpid())
        daemon.launch_sweep(now=1006.0)
        self.assertNotIn("app-x", daemon.launch_reservations)
        self.assertTrue(os.path.isdir(leaf))

    def test_sweep_prunes_launch_mapping_for_gone_scopes(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.store.data["launch_apps"] = {"app-gone": {"app": "gone"}}
        daemon.launch_sweep(now=1000.0)
        self.assertNotIn("app-gone", daemon.store.data.get("launch_apps", {}))

    def test_tick_schedules_the_sweep(self):
        daemon = make_launch_daemon()
        self.addCleanup(daemon._launch_cg.__exit__)
        daemon.last["launch"] = 0.0
        with (
            mock.patch.object(daemon, "launch_sweep") as sweeper,
            mock.patch("time.time", return_value=1000.0),
        ):
            daemon.tick()
        sweeper.assert_called_once_with(now=1000.0)


class LaunchAttachTest(unittest.TestCase):
    def test_attach_moves_app_scope_through_helper_move(self):
        from taema.governor import engine

        daemon = make_daemon()
        with mock.patch.object(engine, "helper_move", return_value=None) as mover:
            reply = daemon.attach(
                {"cmd": "attach", "scope": "app-x", "pids": [os.getpid()]}
            )
        self.assertTrue(reply.get("ok"), reply)
        mover.assert_called_once()
        args, _kwargs = mover.call_args
        self.assertEqual(args[1], "app-x")
        self.assertEqual(list(args[2]), [os.getpid()])


class LaunchCommandTest(unittest.TestCase):
    def _args(self, **over):
        import types

        params = {
            "app": "x",
            "unit": None,
            "bind": False,
            "dry_run": False,
            "cmd": ["true"],
        }
        params.update(over)
        return types.SimpleNamespace(**params)

    def _ask(self, seen, prepare):
        def ask(_cfg, msg):
            seen.append(msg)
            if msg["cmd"] == "launch_prepare":
                return prepare
            return {"ok": True, "scope": prepare["scope"]}

        return ask

    def _ask_replies(self, seen, replies):
        def ask(_cfg, msg):
            seen.append(msg)
            return replies[msg["cmd"]]

        return ask

    def test_registry_names_launch(self):
        import taema.cli.commands as cli
        from taema.cli import registry

        entries = [entry for entry in registry.COMMANDS if entry["name"] == "launch"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["handler"], "cmd_launch")
        self.assertTrue(callable(getattr(cli, "cmd_launch", None)))

    def test_helper_path_moves_claims_and_execs(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import tmp

        seen = []
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli,
                    "ask",
                    side_effect=self._ask(
                        seen,
                        {
                            "ok": True,
                            "scope": "app-x",
                            "via": "helper",
                            "expires": 1.0,
                        },
                    ),
                ),
                mock.patch.object(cli.engine, "helper_move") as mover,
                mock.patch.object(cli.os, "execvp") as ex,
            ):
                cli.cmd_launch(self._args())
        self.assertEqual(
            [msg["cmd"] for msg in seen], ["launch_prepare", "launch_claim"]
        )
        prepare = seen[0]
        self.assertEqual(prepare["app"], "x")
        self.assertEqual(prepare["pid"], os.getpid())
        self.assertIn("session", prepare)
        mover.assert_called_once()
        _cfg, scope, pids = mover.call_args.args
        self.assertEqual(scope, "app-x")
        self.assertEqual(list(pids), [os.getpid()])
        claim = seen[1]
        self.assertEqual(
            (claim["scope"], claim["pid"], claim["app"]),
            ("app-x", os.getpid(), "x"),
        )
        ex.assert_called_once_with("true", ["true"])

    def test_agent_path_uses_daemon_attach_without_helper(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import tmp

        seen = []
        replies = {
            "launch_prepare": {
                "ok": True,
                "scope": "app-x",
                "via": "agent",
                "expires": 1.0,
            },
            "attach": {"ok": True, "attached": [os.getpid()]},
            "launch_claim": {"ok": True, "scope": "app-x"},
        }
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli, "ask", side_effect=self._ask_replies(seen, replies)
                ),
                mock.patch.object(cli.engine, "helper_move") as mover,
                mock.patch.object(cli.os, "execvp") as ex,
            ):
                cli.cmd_launch(self._args())
        self.assertEqual(
            [msg["cmd"] for msg in seen],
            ["launch_prepare", "attach", "launch_claim"],
        )
        attach = seen[1]
        self.assertEqual(attach["scope"], "app-x")
        self.assertEqual(attach["pids"], [os.getpid()])
        mover.assert_not_called()
        ex.assert_called_once_with("true", ["true"])

    def test_bind_sends_owner(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import tmp

        seen = []
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli,
                    "ask",
                    side_effect=self._ask(
                        seen, {"ok": True, "scope": "app-x", "via": "helper"}
                    ),
                ),
                mock.patch.object(cli.engine, "helper_move"),
                mock.patch.object(cli.os, "execvp"),
            ):
                cli.cmd_launch(self._args(bind=True))
        self.assertEqual(seen[0].get("owner"), os.getpid())

    def test_app_defaults_to_command_basename(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import tmp

        seen = []
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli,
                    "ask",
                    side_effect=self._ask(
                        seen, {"ok": True, "scope": "app-true", "via": "helper"}
                    ),
                ),
                mock.patch.object(cli.engine, "helper_move"),
                mock.patch.object(cli.os, "execvp"),
            ):
                cli.cmd_launch(self._args(app=None, cmd=["/usr/bin/true"]))
        self.assertEqual(seen[0]["app"], "true")

    def test_bad_app_and_missing_command_die(self):
        import taema.cli.commands as cli
        from tests.test_phase0 import tmp

        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(cli.os, "execvp") as ex,
            ):
                self.assertEqual(cli.cmd_launch(self._args(app="../evil")), 2)
                self.assertEqual(cli.cmd_launch(self._args(cmd=[])), 2)
            ex.assert_not_called()

    def test_failed_attach_releases_and_dies(self):
        import taema.cli.commands as cli
        from taema.governor import engine
        from tests.test_phase0 import tmp

        seen = []
        with FakeCg():
            cfg = make_cfg(tmp())
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
                mock.patch.object(
                    cli,
                    "ask",
                    side_effect=self._ask(
                        seen, {"ok": True, "scope": "app-x", "via": "helper"}
                    ),
                ),
                mock.patch.object(
                    cli.engine,
                    "helper_move",
                    side_effect=engine.Refused("no sudo"),
                ),
                mock.patch.object(cli.os, "execvp") as ex,
            ):
                rc = cli.cmd_launch(self._args())
        self.assertNotEqual(rc, 0)
        ex.assert_not_called()
        self.assertEqual(
            [msg["cmd"] for msg in seen], ["launch_prepare", "launch_release"]
        )
        self.assertEqual(seen[1]["scope"], "app-x")


class LaunchWhyTest(unittest.TestCase):
    def _store(self):
        import tempfile

        from taema.store import knowledge
        from tests.test_phase0 import make_cfg

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return make_cfg(temp.name), knowledge.Store(temp.name, {})

    def _explain_scope(self, cfg, store):
        import taema.cli.commands as cli
        from taema.cli import targets, view

        scope = targets.Target("scope", "app-x", "scope:app-x", scope="app-x")
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[scope]),
            mock.patch.object(cli, "_target_scope_path", return_value="/cg/app-x"),
            mock.patch.object(cli.cgroup, "rel", return_value="app-x"),
            mock.patch.object(cli.engine, "unit_for_leaf", return_value=None),
            mock.patch.object(
                cli.engine,
                "plan_stop",
                return_value=[
                    {
                        "pid": os.getpid(),
                        "key": "comm:x",
                        "action": "keep",
                        "why": "test",
                    }
                ],
            ),
            mock.patch.object(view, "emit") as emit,
        ):
            rc = cli.cmd_explain(
                __import__("types").SimpleNamespace(target="scope:app-x", pick=False)
            )
        self.assertEqual(rc, 0)
        return emit.call_args.args[0]

    def test_why_shows_launch_provenance_and_desktop(self):
        from types import SimpleNamespace

        from taema.core import process as inspect

        cfg, store = self._store()
        store.data["launch_apps"] = {
            "app-x": {"app": "firefox", "launched_by": "launch"}
        }
        store.record_identity(
            SimpleNamespace(
                key="comm:x",
                display="x",
                exe="/usr/bin/x",
                kind="comm",
                desktop_id=None,
                unit=None,
                validated=True,
                device=None,
                inode=None,
            ),
            {
                "pid": os.getpid(),
                "start": inspect.starttime(os.getpid()),
                "scope": "app-x",
                "launched_by": "launch",
            },
        )
        model = self._explain_scope(cfg, store)
        explanation = model["explanation"]
        self.assertEqual(explanation["identity"]["desktop_id"], "firefox")
        self.assertEqual(explanation["provenance"].get("launched_by"), "launch")

    def test_why_rendering_shows_launched_by_and_desktop(self):
        from taema.cli import view

        text = view.render_explanation(
            "scope:app-x",
            {
                "identity": {
                    "key": "comm:x",
                    "display": "x",
                    "validated": True,
                    "desktop_id": "firefox",
                },
                "scope": {"name": "app-x", "live": True},
                "provenance": {"launched_by": "launch"},
                "current_decision": {"action": "keep", "reason": "test"},
            },
        )
        self.assertIn("launched_by=launch", text)
        self.assertIn("desktop=firefox", text)

    def test_launch_explanation_matches_schema(self):
        import json
        from pathlib import Path

        from tests.test_ipc_v2 import matches

        schema = json.loads(
            (
                Path(__file__).resolve().parents[1] / "schema/cli/read-v1.json"
            ).read_text()
        )
        cfg, store = self._store()
        store.data["launch_apps"] = {
            "app-x": {"app": "firefox", "launched_by": "launch"}
        }
        model = self._explain_scope(cfg, store)
        self.assertTrue(matches(model, schema, schema))


if __name__ == "__main__":
    unittest.main()
