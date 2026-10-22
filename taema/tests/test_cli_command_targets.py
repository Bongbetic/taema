"""Target-aware command behavior at the CLI boundary."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from taema.cli import targets, view
import taema.cli.commands as cli
from taema.core.identity import AppIdentity
from taema.store import knowledge
from tests.test_ipc_v2 import matches
from tests.test_phase0 import make_cfg

SCHEMA = json.loads(
    (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "schema/cli/read-v1.json"
    ).read_text()
)


class TargetCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = knowledge.Store(self.temp.name, {})
        self.cfg = make_cfg(self.temp.name)

    def test_explain_resolves_app_desktop_and_scope_targets(self):
        app = targets.Target("app", "browser", "app:browser", app_key="browser")
        desktop = targets.Target(
            "desktop",
            "org.example.Browser.desktop",
            "desktop:org.example.Browser.desktop",
            app_key="browser",
        )
        scope = targets.Target(
            "scope", "scope-browser", "scope:scope-browser", scope="scope-browser"
        )
        for query, candidate in (
            ("app:browser", app),
            ("desktop:org.example.Browser.desktop", desktop),
        ):
            with (
                self.subTest(query=query),
                mock.patch.object(
                    cli, "_load", return_value=(self.cfg, self.store, [])
                ),
                mock.patch.object(cli, "_target_candidates", return_value=[candidate]),
                mock.patch.object(view, "emit") as emit,
            ):
                self.assertEqual(
                    cli.cmd_explain(SimpleNamespace(target=query, pick=False)), 0
                )
                self.assertEqual(emit.call_args.args[0]["target"], query)

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[scope]),
            mock.patch.object(
                cli, "_target_scope_path", return_value="/cg/scope-browser"
            ),
            mock.patch.object(cli.engine, "unit_for_leaf", return_value=None),
            mock.patch.object(cli.engine, "plan_stop", return_value=[]),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="scope-browser", pick=False)), 0
            )
            explanation = emit.call_args.args[0]["explanation"]
            self.assertEqual(explanation["plan"], [])
            self.assertEqual(explanation["mode_outcomes"]["trigger"], "gc_stop")
            self.assertTrue(matches(emit.call_args.args[0], SCHEMA, SCHEMA))

    def test_explain_pid_checks_starttime_before_building_report(self):
        pid = targets.Target("pid", "42", "pid:42", scope="scope-x", pid=42, start=100)
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[pid]),
            mock.patch.object(cli.inspect, "starttime", return_value=100),
            mock.patch.object(cli.inspect, "comm", return_value="browser"),
            mock.patch.object(cli.cgroup, "proc_cgroup", return_value="scope-x"),
            mock.patch.object(cli, "_target_scope_path", return_value="/cg/scope-x"),
            mock.patch.object(cli.cgroup, "rel", return_value="scope-x"),
            mock.patch.object(
                cli.policy,
                "app_identity",
                return_value=AppIdentity(
                    "exe:browser:8:71", "browser", "exe", "browser", 8, 71
                ),
            ),
            mock.patch.object(cli.policy, "protected_reason", return_value=None),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="pid:42", pick=False)), 0
            )
            explanation = emit.call_args.args[0]["explanation"]
            self.assertEqual(explanation["provenance"]["pid"], 42)
            self.assertEqual(explanation["identity"]["key"], "exe:browser:8:71")

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[pid]),
            mock.patch.object(cli.inspect, "starttime", return_value=101),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="pid:42", pick=False)), 2
            )

    def test_why_renders_durable_parent_chain_and_evidence_confidence(self):
        parent = AppIdentity(
            "unit:niri", "niri", "unit", "/usr/bin/niri", unit="niri.service"
        )
        child = AppIdentity(
            "exe:firefox:8:71", "firefox", "exe", "/usr/bin/firefox", 8, 71
        )
        now = self.store.now()
        self.store.record_identities(
            [
                (
                    parent,
                    {
                        "pid": 40,
                        "start": 100,
                        "born": now,
                        "scope": "/user/1000/app-desktop",
                    },
                ),
                (
                    child,
                    {
                        "pid": 41,
                        "start": 101,
                        "born": now,
                        "parent_app": parent.key,
                        "scope": "/user/1000/app-desktop",
                        "parent_evidence": ["co_birth", "cgroup"],
                    },
                ),
            ]
        )

        explanation = cli._why_report(self.cfg, self.store, key=child.key)
        rendered = view.render_explanation("app:firefox", explanation)

        self.assertEqual(explanation["provenance"]["chain_text"], "firefox ← niri")
        self.assertIn("provenance: firefox ← niri", rendered)
        self.assertIn("cgroup=1, co_birth=1", rendered)
        self.assertIn("confidence=1.00", rendered)

    def test_why_pair_explains_learned_and_invalid_owner_authority(self):
        self.store.answer("npm", "vite", "stop")
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target=None, pair=["npm", "vite"])),
                0,
            )
        record = emit.call_args.args[0]
        explanation = record["explanation"]
        self.assertEqual(explanation["current_decision"]["action"], "stop")
        self.assertEqual(explanation["authority_source"], "explicit")
        self.assertEqual(
            explanation["learn_authority"],
            {"value": "learned", "source": "mode default for observe"},
        )
        self.assertIn("effective authority: learned", emit.call_args.args[2])
        self.assertIn("learned pair: npm -> vite", emit.call_args.args[2])
        auto = next(
            item
            for item in explanation["mode_outcomes"]["modes"]
            if item["mode"] == "auto"
        )
        self.assertEqual((auto["verdict"], auto["authority"]), ("act", "pair"))
        self.assertTrue(matches(record, SCHEMA, SCHEMA))

        self.store.record_decision(
            "gc_stop", scope="scope-x", authority="pair", mode="auto", why="pair stop"
        )
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target=None, pair=None)), 0
            )
        self.assertIn(
            "recorded context: kind=gc_stop; mode=auto; authority=pair",
            emit.call_args.args[2],
        )

        self.cfg["_profile_suppress_stops"] = True
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target=None, pair=["npm", "vite"])),
                0,
            )
        auto = next(
            item
            for item in emit.call_args.args[0]["explanation"]["mode_outcomes"]["modes"]
            if item["mode"] == "auto"
        )
        self.assertEqual((auto["verdict"], auto["slot"]), ("keep", "mode_capability"))
        self.cfg["_profile_suppress_stops"] = False

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(
                    SimpleNamespace(target=None, pair=["Thread-worker", "vite"])
                ),
                0,
            )
        explanation = emit.call_args.args[0]["explanation"]
        self.assertEqual(explanation["current_decision"]["action"], "invalid")
        self.assertFalse(explanation["identity"]["validated"])
        auto = next(
            item
            for item in explanation["mode_outcomes"]["modes"]
            if item["mode"] == "auto"
        )
        self.assertEqual((auto["verdict"], auto["slot"]), ("keep", "authority"))

    def test_why_without_a_target_explains_the_latest_decision_or_unknown(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target=None, pair=None)), 0
            )
        record = emit.call_args.args[0]
        explanation = record["explanation"]
        self.assertEqual(record["target"], "latest decision")
        self.assertEqual(explanation["current_decision"]["action"], "unknown")
        self.assertEqual(explanation["mode_outcomes"]["trigger"], "unknown")
        self.assertTrue(
            any(item["fact"] == "latest_decision" for item in explanation["unknown"])
        )
        self.assertTrue(matches(record, SCHEMA, SCHEMA))

    def test_why_json_emits_the_schema_valid_dashboard_object(self):
        self.store.answer("npm", "vite", "stop")
        output = io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            redirect_stdout(output),
        ):
            self.assertEqual(
                cli.cmd_explain(
                    SimpleNamespace(
                        target=None,
                        pair=["npm", "vite"],
                        json=True,
                        jsonl=False,
                    )
                ),
                0,
            )
        record = json.loads(output.getvalue())
        self.assertEqual(record["schema"], "taema.explain.v1")
        self.assertEqual(record["target"], "pair:npm -> vite")
        self.assertTrue(matches(record, SCHEMA, SCHEMA))

    def test_why_scope_reports_matching_veto_and_mode_reasons(self):
        self.store.add_veto("scope", "scope-x")
        scope = targets.Target("scope", "scope-x", "scope:scope-x", scope="scope-x")
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[scope]),
            mock.patch.object(cli, "_target_scope_path", return_value="/cg/scope-x"),
            mock.patch.object(cli.cgroup, "rel", return_value="scope-x"),
            mock.patch.object(cli.engine, "unit_for_leaf", return_value=None),
            mock.patch.object(cli.engine, "plan_stop", return_value=[]),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="scope:scope-x", pick=False)), 0
            )
        explanation = emit.call_args.args[0]["explanation"]
        self.assertEqual(explanation["vetoes"][0]["value"], "scope-x")
        self.assertEqual(
            {item["slot"] for item in explanation["mode_outcomes"]["modes"]},
            {"veto"},
        )

    def test_why_pid_reports_protection_through_the_hard_safety_slot(self):
        pid = targets.Target("pid", "42", "pid:42", scope="scope-x", pid=42, start=100)
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[pid]),
            mock.patch.object(cli.inspect, "starttime", return_value=100),
            mock.patch.object(
                cli.policy,
                "app_identity",
                return_value=AppIdentity(
                    "exe:browser:8:71", "browser", "exe", "browser", 8, 71
                ),
            ),
            mock.patch.object(cli.inspect, "comm", return_value="browser"),
            mock.patch.object(cli.cgroup, "proc_cgroup", return_value="scope-x"),
            mock.patch.object(cli, "_target_scope_path", return_value="/cg/scope-x"),
            mock.patch.object(cli.cgroup, "rel", return_value="scope-x"),
            mock.patch.object(
                cli.policy, "protected_reason", return_value="protected comm systemd"
            ),
            mock.patch.object(view, "emit") as emit,
        ):
            self.assertEqual(
                cli.cmd_explain(SimpleNamespace(target="pid:42", pick=False)), 0
            )
        explanation = emit.call_args.args[0]["explanation"]
        self.assertTrue(explanation["protected"]["blocked"])
        auto = next(
            item
            for item in explanation["mode_outcomes"]["modes"]
            if item["mode"] == "auto"
        )
        self.assertEqual((auto["verdict"], auto["slot"]), ("keep", "hard_safety"))

    def test_keep_resolves_live_app_and_dry_run_does_not_write(self):
        app = targets.Target("app", "browser", "app:browser", app_key="browser")
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[app]),
            mock.patch.object(cli, "feedback", return_value="queued") as feedback,
            mock.patch.object(self.store, "bump") as bump,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(
                    SimpleNamespace(exe="app:browser", dry_run=False, pick=False)
                ),
                0,
            )
        feedback.assert_called_once_with(self.cfg, self.store, "keep", "browser")
        bump.assert_called_once()

        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[app]),
            mock.patch.object(cli, "feedback") as feedback,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(SimpleNamespace(exe="browser", dry_run=True, pick=False)),
                0,
            )
        feedback.assert_not_called()

    def test_keep_pair_uses_relationship_teaching_feedback(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(
                cli,
                "feedback_action",
                return_value=("queued", {"ok": True, "queued": True}),
            ) as feedback,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["keep", "--pair", "browser", "helper"]), 0)
        feedback.assert_called_once_with(
            self.cfg,
            self.store,
            "teach",
            owner="browser",
            leftovers=["helper"],
            choice="keep",
        )

    def test_adopt_standalone_plans_only_live_standalone_members(self):
        self.cfg["mode"] = "enforce"
        self.store.data["standalone"] = {"helper": {"n": 1}}
        pt = SimpleNamespace(descendants=mock.Mock(return_value=[101]))
        entry = {
            "key": "helper",
            "pid": 101,
            "start": 303,
            "chain_ids": [(100, 200), (101, 303)],
        }
        lin = SimpleNamespace(entries={(101, 303): entry}, observe=mock.Mock())
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli.inspect.ProcTable, "scan", return_value=pt),
            mock.patch.object(cli.lineage, "Lineage", return_value=lin),
            mock.patch.object(cli.policy, "session_cgroups", return_value=["session"]),
            mock.patch.object(cli.cgroup, "procs", return_value=[101]),
            mock.patch.object(cli.policy, "protected_reason", return_value=None),
            mock.patch.object(
                cli.authorization,
                "authorize",
                return_value=SimpleNamespace(verdict="ACT"),
            ),
            mock.patch.object(
                cli.engine,
                "run_ops",
                side_effect=lambda _cfg, _store, ops, _execute: [
                    dict(op, done=True) for op in ops
                ],
            ) as run_ops,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["adopt", "--standalone"]), 0)
        ops = run_ops.call_args.args[2]
        self.assertEqual(len(ops), 1)
        self.assertEqual((ops[0]["owner"], ops[0]["pids"]), ("helper", [101]))

    def test_answer_command_normalizes_review_id_and_choice(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(
                cli,
                "feedback_action",
                return_value=("daemon", {"ok": True}),
            ) as feedback,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["answer", "r-2a", "4", "--owner", "browser"]), 0)
        feedback.assert_called_once_with(
            self.cfg,
            self.store,
            "review_answer",
            review_id=42,
            choice="never",
            owner="browser",
        )

    def test_teach_command_uses_the_shared_relationship_answer(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(
                cli,
                "feedback_action",
                return_value=("queued", {"ok": True}),
            ) as feedback,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["teach", "browser", "helper", "stop"]), 0)
        feedback.assert_called_once_with(
            self.cfg,
            self.store,
            "teach",
            owner="browser",
            leftovers=["helper"],
            choice="stop",
        )

    def test_unknown_desktop_id_is_rejected_for_mutating_target_commands(self):
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "_target_candidates", return_value=[]),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                cli.cmd_keep(
                    SimpleNamespace(
                        exe="desktop:missing.desktop", dry_run=False, pick=False
                    )
                ),
                2,
            )
            self.assertEqual(
                cli.cmd_do_not_kill(
                    SimpleNamespace(
                        target="desktop:missing.desktop", dry_run=False, pick=False
                    )
                ),
                2,
            )

    def test_bulk_confirmation_prints_a_plan_and_honors_yes(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertFalse(
                cli._confirm_bulk(
                    "adopt", ["scope-a", "scope-b"], SimpleNamespace(yes=False)
                )
            )
        self.assertIn("plan: adopt affects 2 targets", output.getvalue())
        self.assertIn("--yes", errors.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertTrue(
                cli._confirm_bulk("adopt", ["scope-a"], SimpleNamespace(yes=True))
            )

    def test_explicit_app_query_is_a_completion_candidate_even_when_not_live(self):
        with mock.patch.object(targets, "live_targets", return_value=[]):
            found = cli._target_candidates("app:learned", self.store)
        self.assertEqual(
            [(item.kind, item.value) for item in found], [("app", "learned")]
        )


if __name__ == "__main__":
    unittest.main()
