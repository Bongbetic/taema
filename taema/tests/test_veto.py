"""Veto and undo behavior through the CLI and daemon command boundary."""

import io
import itertools
import json
import os
import random
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from taema.daemon import service as daemon
import taema.cli.commands as cli
from taema.cli import targets
from taema.core import signature as survivor_signature
from taema.governor import engine
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg, tmp


class VetoCommands(unittest.TestCase):
    @staticmethod
    def veto_args(selector=None, value=None, **options):
        args = SimpleNamespace(
            target=None,
            exe=None,
            all=False,
            **{
                name: None
                for name in (
                    "scope",
                    "pid",
                    "pair",
                    "signature",
                    "app",
                    "owner",
                    "unit",
                    "cgroup",
                    "path",
                )
            },
        )
        if selector:
            setattr(args, selector, value)
        for name, option in options.items():
            setattr(args, name, option)
        return args

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

    def test_matching_vetoes_reports_every_active_scope_and_member_match(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x")
        store.add_veto("app", "firefox")
        store.add_veto("pid", "42", start=100)

        matches = store.matching_vetoes(
            scope="scope-x/child",
            members=[{"pid": 42, "start": 100, "apps": ["firefox"]}],
        )

        self.assertEqual(
            [(item["kind"], item["value"]) for item in matches],
            [("pid", "42"), ("scope", "scope-x"), ("app", "firefox")],
        )
        self.assertEqual(
            store.match_veto(
                scope="scope-x/child",
                members=[{"pid": 42, "start": 100, "apps": ["firefox"]}],
            ),
            matches[0],
        )

    def test_all_target_kinds_match_in_declared_precedence(self):
        store = knowledge.Store(tmp(), {})
        # Add in reverse order: matching precedence must not depend on insertion order.
        store.add_veto("path", "/usr/bin/firefox")
        store.add_veto("cgroup", "/user/1000/scope-x")
        store.add_veto("unit", "browser")
        store.add_veto("owner", "browser")
        store.add_veto("app", "firefox")
        store.add_veto("signature", "sig-1")
        store.add_veto("pair", "firefox", owner="browser", leftover="firefox")
        store.add_veto("scope", "scope-x")
        store.add_veto("pid", "42", start=100)

        matches = store.matching_vetoes(
            scope="scope-x/child",
            members=[
                {
                    "pid": 42,
                    "start": 100,
                    "apps": ["firefox"],
                    "owners": ["browser"],
                    "owner": "browser",
                    "leftover": "firefox",
                    "unit": "browser",
                    "cgroup": "/user/1000/scope-x/child",
                    "path": "/usr/bin/firefox",
                }
            ],
            owner="browser",
            leftover="firefox",
            signature="sig-1",
            unit="browser",
            cgroup_path="/user/1000/scope-x/child",
        )

        self.assertEqual(
            [item["kind"] for item in matches],
            [
                "pid",
                "scope",
                "pair",
                "signature",
                "app",
                "owner",
                "unit",
                "cgroup",
                "path",
            ],
        )

    def test_precedence_property_holds_for_generated_orders_and_overlaps(self):
        store = knowledge.Store(tmp(), {})
        vetoes = [
            {"kind": "pid", "value": "42", "start": 100},
            {"kind": "scope", "value": "scope-x"},
            {
                "kind": "pair",
                "value": "firefox",
                "owner": "browser",
                "leftover": "firefox",
            },
            {"kind": "signature", "value": "sig-1"},
            {"kind": "app", "value": "firefox"},
            {"kind": "owner", "value": "browser"},
            {"kind": "unit", "value": "browser"},
            {"kind": "cgroup", "value": "/user/1000/scope-x"},
            {"kind": "path", "value": "/usr/bin/firefox"},
        ]
        context = {
            "scope": "scope-x/child",
            "members": [
                {
                    "pid": 42,
                    "start": 100,
                    "apps": ["firefox"],
                    "owners": ["browser"],
                    "owner": "browser",
                    "leftover": "firefox",
                    "unit": "browser",
                    "cgroup": "/user/1000/scope-x/child",
                    "path": "/usr/bin/firefox",
                }
            ],
            "owner": "browser",
            "leftover": "firefox",
            "signature": "sig-1",
            "unit": "browser",
            "cgroup_path": "/user/1000/scope-x/child",
        }
        precedence = knowledge._VETO_RANK
        rng = random.Random(36)

        for _ in range(128):
            ordered = list(vetoes)
            rng.shuffle(ordered)
            selected = ordered[: rng.randint(1, len(ordered))]
            store.data["vetoes"] = [
                {"id": str(index), "created": index, "expires": None, **item}
                for index, item in enumerate(selected)
            ]

            matches = store.matching_vetoes(**context)

            self.assertTrue(matches)
            self.assertEqual(
                [item["kind"] for item in matches],
                sorted((item["kind"] for item in selected), key=precedence.__getitem__),
            )
            self.assertEqual(store.match_veto(**context), matches[0])

    def test_expiry_property_matches_only_after_the_expiration_boundary(self):
        store = knowledge.Store(tmp(), {})
        context = {"members": [{"apps": ["firefox"]}]}

        for now, expires in itertools.product(range(95, 106), range(95, 106)):
            store.now = lambda current=now: current
            store.data["vetoes"] = [
                {
                    "id": "%s:%s" % (now, expires),
                    "kind": "app",
                    "value": "firefox",
                    "expires": expires,
                }
            ]

            self.assertEqual(
                store.match_veto(**context) is not None,
                expires > now,
                "veto expiry at now=%s expires=%s" % (now, expires),
            )

    def test_veto_rejects_expiry_integer_outside_finite_timestamp_range(self):
        store = knowledge.Store(tmp(), {})
        self.assertIsNone(store.add_veto("app", "firefox", expires=10**1000))

    def test_expiry_boundary_prunes_and_audits_veto(self):
        now = [100.0]
        store = knowledge.Store(tmp(), {}, now=lambda: now[0])
        store.add_veto(
            "app", "firefox", expires=101.0, reason="temporary test", source="cli"
        )

        now[0] = 100.999
        self.assertIsNotNone(store.match_veto(members=[{"apps": ["firefox"]}]))
        now[0] = 101.0
        self.assertIsNone(store.match_veto(members=[{"apps": ["firefox"]}]))
        expired = store.prune_vetoes(trigger="gc")

        self.assertEqual(len(expired), 1)
        self.assertEqual(store.data["vetoes"], [])
        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        self.assertTrue(
            any(
                event["event"] == "veto_expired"
                and event["trigger"] == "gc"
                and event["reason"] == "temporary test"
                and event["target"]["value"] == "firefox"
                for event in events
            )
        )

    def test_veto_creation_uses_spec_event_and_preserves_source(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("app", "firefox", source="cli")

        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        created = next(event for event in events if event["event"] == "veto")
        self.assertEqual(created["source"], "cli")
        self.assertEqual(created["target"]["value"], "firefox")

    def test_veto_resolver_supports_each_explicit_target_form(self):
        store = knowledge.Store(tmp(), {})
        store.data["pairs"][store.pkey("browser", "firefox")] = {}
        store.add_veto("signature", "sig-1")
        candidates = [
            targets.Target("scope", "scope-x", "scope:scope-x", scope="scope-x"),
            targets.Target("scope", "browser-1", "scope:browser-1", scope="browser-1"),
            targets.Target("pid", "42", "pid:42", scope="scope-x", pid=42, start=100),
            targets.Target("app", "firefox", "app:firefox", app_key="firefox"),
            targets.Target("app", "browser", "app:browser", app_key="browser"),
        ]
        units = [{"unit": {"name": "browser"}}]
        with (
            mock.patch.object(cli, "_target_candidates", return_value=candidates),
            mock.patch.object(targets, "process_target", return_value=candidates[2]),
            mock.patch.object(cli.inspect, "starttime", return_value=100),
            mock.patch.object(
                cli.cgroup, "proc_cgroup", return_value="/user/1000/scope-x"
            ),
            mock.patch.object(cli.inspect, "exe", return_value="/usr/bin/firefox"),
        ):
            cases = (
                ("scope", "scope-x", "scope"),
                ("app", "firefox", "app"),
                ("pair", ("browser", "firefox"), "pair"),
                ("signature", "sig-1", "signature"),
                ("pid", 42, "pid"),
                ("owner", "browser", "owner"),
                ("unit", "browser", "unit"),
                ("cgroup", "/user/1000", "cgroup"),
                ("path", "/usr/bin/firefox", "path"),
            )
            for selector, value, expected_kind in cases:
                with self.subTest(selector=selector):
                    resolved = cli.resolve_veto_targets(
                        self.veto_args(selector, value), store, units
                    )
                    self.assertEqual(resolved[0][0]["kind"], expected_kind)

    def test_veto_resolver_removes_an_existing_offline_target_without_live_lookup(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("app", "firefox")
        args = self.veto_args(target="app:firefox")
        with mock.patch.object(cli, "_target_candidates") as candidates:
            resolved = cli.resolve_veto_targets(args, store, [], removal=True)
        candidates.assert_not_called()
        self.assertEqual(resolved[0][0]["kind"], "app")
        self.assertIn("active app firefox", resolved[0][1])

    def test_plan_stop_skips_a_vetoed_member(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("app", "firefox")
        with (
            mock.patch.object(engine.cgroup, "tree_procs", return_value=[42]),
            mock.patch.object(engine.inspect, "starttime", return_value=100),
            mock.patch.object(engine.inspect, "exe", return_value="/usr/bin/firefox"),
            mock.patch.object(
                engine.cgroup, "proc_cgroup", return_value="/user/1000/scope-x"
            ),
            mock.patch.object(
                engine.inspect.ProcTable,
                "scan",
                return_value=engine.inspect.ProcTable.from_ppid({42: 1}),
            ),
            mock.patch.object(
                engine.inspect,
                "LazySnapshot",
                return_value=mock.Mock(get=mock.Mock(return_value=mock.Mock(ok=True))),
            ),
            mock.patch.object(engine.inspect, "edges", return_value={}),
            mock.patch.object(engine.inspect, "comm", return_value="firefox"),
            mock.patch.object(engine.policy, "app_key", return_value="firefox"),
            mock.patch.object(engine.policy, "protected_reason", return_value=None),
        ):
            plan = engine.plan_stop("scope-x", {}, store)

        self.assertEqual(plan[0]["action"], "skip")
        self.assertIn("vetoed app firefox", plan[0]["why"])

    def test_auto_stop_and_gc_held_verdict_honor_member_veto(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("app", "firefox", source="offline")
        member = {
            "pid": 42,
            "start": 100,
            "key": "firefox",
            "origin": "browser",
            "edges": [],
            "protected": None,
            "ptmx": False,
            "cpu": 0.0,
        }
        ok, reason = engine.auto_stop_ok(
            store,
            "browser",
            "firefox",
            member,
            decision=("stop", 1.0, "explicit stop"),
            scope="leftover/firefox",
        )
        self.assertFalse(ok)
        self.assertIn("vetoed app firefox", reason)

        with (
            mock.patch.object(engine.inspect, "edges", return_value={}),
            mock.patch.object(engine, "member_info", return_value=member),
        ):
            verdict = engine._leftover_verdict(
                {},
                store,
                None,
                [42],
                mock.Mock(get=mock.Mock(return_value=mock.Mock(ok=True))),
                set(),
                scope="leftover/firefox",
            )
        self.assertEqual(verdict[0], "held")
        self.assertIn("vetoed app firefox", verdict[1])

        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        block = next(event for event in events if event["event"] == "vetoed")
        self.assertEqual(block["source"], "offline")
        self.assertEqual(block["trigger"], "gc_stop")

    def test_do_not_kill_alias_queues_a_matching_app_veto(self):
        for argv in (
            ["dnk", "firefox"],
            ["never", "app:firefox"],
            ["--do-not-kill", "firefox"],
        ):
            with self.subTest(argv=argv):
                s = knowledge.Store(tmp(), {})
                s.data["standalone"]["firefox"] = {"n": 1}
                rc, out, _err = self.run_cli_offline(argv, s)
                self.assertEqual(rc, 0)
                self.assertIn("vetoed app firefox", out)
                self.assertEqual(self.queued(s)[0]["op"], "veto")
                self.assertEqual(self.queued(s)[0]["target"]["value"], "firefox")

    def test_pair_veto_expiry_reason_and_offline_enforcement(self):
        store = knowledge.Store(tmp(), {})
        store.data["pairs"][store.pkey("browser", "firefox")] = {}
        rc, out, err = self.run_cli_offline(
            [
                "do-not-kill",
                "--pair",
                "browser",
                "firefox",
                "--for",
                "7d",
                "--reason",
                "keep this helper",
            ],
            store,
        )

        self.assertEqual((rc, err), (0, ""))
        self.assertIn("matched: stored pair browser>firefox", out)
        op = self.queued(store)[0]
        self.assertEqual(op["target"]["kind"], "pair")
        self.assertEqual(op["target"]["owner"], "browser")
        self.assertEqual(op["target"]["leftover"], "firefox")
        self.assertEqual(op["reason"], "keep this helper")
        self.assertGreater(op["expires"], time.time() + 6 * 86400)
        self.assertEqual(
            store.match_veto(
                members=[
                    {
                        "pid": 7,
                        "apps": ["firefox"],
                        "owner": "browser",
                        "owners": ["browser"],
                    }
                ],
                owner="browser",
                leftover="firefox",
            )["kind"],
            "pair",
        )

    def test_ambiguous_veto_requires_all_and_unmatched_target_exits_two(self):
        store = knowledge.Store(tmp(), {})
        candidates = [
            targets.Target("app", "firefox", "app:firefox", app_key="firefox"),
            targets.Target(
                "scope", "scope-firefox", "scope:scope-firefox", scope="scope-firefox"
            ),
        ]
        with mock.patch.object(cli, "_target_candidates", return_value=candidates):
            rc, _out, err = self.run_cli_offline(["do-not-kill", "fire"], store)
        self.assertEqual(rc, 2)
        self.assertIn("ambiguous", err)
        self.assertFalse(os.path.exists(store.feedback_path))

        with mock.patch.object(cli, "_target_candidates", return_value=candidates):
            rc, out, err = self.run_cli_offline(
                ["do-not-kill", "--all", "--yes", "fire"], store
            )
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(len(self.queued(store)), 2)
        self.assertIn("matched:", out)

        unknown = knowledge.Store(tmp(), {})
        rc, _out, err = self.run_cli_offline(["do-not-kill", "no-such-app"], unknown)
        self.assertEqual(rc, 2)
        self.assertIn("no target matches", err)

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
        rc, out, _err = self.run_cli_offline(["forget", "--veto", "app:vite"], s)
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

    def test_unveto_pid_without_start_removes_all_instances_for_compatibility(self):
        from taema import protocol

        s = knowledge.Store(tmp(), {})
        s.add_veto("pid", "42", start=1234)
        s.add_veto("pid", "42", start=5678)
        operation = {
            "v": 1,
            "id": "unveto-pid-wildcard",
            "op": "unveto",
            "target": {"kind": "pid", "value": "42"},
        }

        protocol.validate_feedback(operation)
        result = s.apply_feedback_command(operation)

        self.assertEqual(len(result["removed"]), 2)
        self.assertEqual(s.data["vetoes"], [])

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

    def test_offline_manual_stop_refuses_a_matching_signature_veto(self):
        store = knowledge.Store(tmp(), {})
        with FakeCg() as cg:
            path = cg.leaf("scope-x", [42])
            cfg = make_cfg(store.dir, mode="enforce")
            signature = survivor_signature.signature(
                "browser", ["firefox"], "runtime-hash", "", False
            )
            store.ensure_signature("browser", signature)
            store.add_veto("signature", signature["id"])
            target = targets.Target(
                "scope", "scope-x", "scope:scope-x", scope="scope-x"
            )
            stat = cli.inspect.Proc(1, 42, 42, 0, 100, "S", 0)
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(cli, "_target_candidates", return_value=[target]),
                mock.patch.object(cli, "_target_scope_path", return_value=path),
                mock.patch.object(engine.cgroup, "tree_procs", return_value=[42]),
                mock.patch.object(engine.inspect, "starttime", return_value=100),
                mock.patch.object(engine.inspect, "_parse_stat", return_value=stat),
                mock.patch.object(engine.policy, "app_key", return_value="firefox"),
                mock.patch.object(
                    engine.inspect, "exe", return_value="/usr/bin/firefox"
                ),
                mock.patch.object(
                    engine.cgroup, "proc_cgroup", return_value="/user/1000/scope-x"
                ),
                mock.patch.object(
                    survivor_signature,
                    "runtime_dir_hash",
                    return_value="runtime-hash",
                ),
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                rc = cli.main(["kill", "scope-x"])

        self.assertEqual(rc, 4)
        self.assertIn("signature", err.getvalue())

    def test_force_veto_requires_confirmation_and_logs_audited_override(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x", reason="manual safety request")
        with FakeCg() as cg:
            scope_path = cg.leaf("scope-x")
            os.unlink(os.path.join(scope_path, "cgroup.procs"))
            cfg = make_cfg(store.dir, mode="enforce")
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch("sys.stdin.isatty", return_value=True),
                mock.patch("builtins.input", return_value="yes") as confirm,
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                rc = cli.main(["stop", "--force-veto", "scope-x"])

        self.assertEqual((rc, err.getvalue()), (0, ""))
        self.assertIn("plan: override veto affects 1 targets", out.getvalue())
        self.assertIn("manual safety request", out.getvalue())
        confirm.assert_called_once()
        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        self.assertTrue(
            any(
                event["event"] == "veto_override" and event["target"]["kind"] == "scope"
                for event in events
            )
        )

    def test_force_veto_does_not_bypass_unit_never_stop(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x", reason="user veto")
        unit = {"unit": {"name": "scope-x"}, "kill": {"never_stop": True}}
        with FakeCg() as cg:
            cg.leaf("scope-x")
            cfg = make_cfg(store.dir, mode="enforce")
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [unit])),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                rc = cli.main(["stop", "--force-veto", "--yes", "scope-x"])

        self.assertEqual(rc, 4)
        self.assertIn("unit veto: kill.never_stop", err.getvalue())
        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        self.assertTrue(any(event["event"] == "unit_vetoed" for event in events))
        self.assertFalse(any(event["event"] == "veto_override" for event in events))

    def test_force_veto_still_observes_self_guard(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x")
        with FakeCg() as cg:
            path = cg.leaf("scope-x")
            cfg = make_cfg(store.dir, mode="enforce")
            with mock.patch.object(
                engine, "self_guard", side_effect=engine.Refused("self guard")
            ):
                with self.assertRaisesRegex(engine.Refused, "self guard"):
                    engine.stop(path, cfg, store, veto_override=True)
        with open(store.log_path) as source:
            events = [json.loads(line) for line in source]
        self.assertFalse(any(event["event"] == "veto_override" for event in events))

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
        report = {
            "decisions": [{"key": "firefox", "action": "kill", "pid": 42}],
            "removed": True,
            "stopped": [42],
        }
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

    def test_veto_thaws_a_managed_freeze_for_online_and_replayed_vetoes(self):
        for replayed in (False, True):
            scope = "scope-frozen-%s" % replayed
            path = self.cg.leaf(scope)
            freeze_path = os.path.join(path, "cgroup.freeze")
            with open(freeze_path, "w") as target:
                target.write("1\n")
            operation = {
                "v": 2,
                "id": "freeze-veto-%s" % replayed,
                "op": "veto",
                "target": {"kind": "scope", "value": scope},
            }

            if replayed:
                with open(self.d.store.feedback_path, "w") as queue:
                    queue.write(json.dumps(operation) + "\n")
                self.d.store.apply_feedback()
                self.d.thaw_held_scopes()
            else:
                self.d.handle({"cmd": "feedback", **operation})

            with open(freeze_path) as source:
                self.assertEqual(source.read(), "0\n")

        thaw_events = [event for event in self.events() if event["event"] == "thaw"]
        self.assertEqual(len(thaw_events), 2)
        self.assertTrue(all(event.get("source") for event in thaw_events))

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
        report = {
            "decisions": [{"key": "firefox", "action": "kill", "pid": 42}],
            "removed": True,
            "stopped": [42],
        }
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
