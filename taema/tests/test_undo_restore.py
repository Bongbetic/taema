"""Decision reversal and opt-in process restoration tests."""

import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from taema import protocol
from taema.cli import commands as cli
from taema.core import process
from taema.daemon import service
from taema.governor import engine
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg, tmp


class RestoreEnvironmentTests(unittest.TestCase):
    def test_restore_command_rejects_invalid_and_racy_process_data(self):
        self.assertIsNone(process.restore_command(True))

        with (
            mock.patch.object(process, "starttime", return_value=None),
            mock.patch.object(process, "read", return_value=b"/usr/bin/app\0"),
        ):
            self.assertIsNone(process.restore_command(123))

        with (
            mock.patch.object(process, "starttime", return_value=456),
            mock.patch.object(
                process,
                "read",
                return_value=b"x" * (process.MAX_RESTORE_ARGV_BYTES + 1),
            ),
        ):
            self.assertIsNone(process.restore_command(123))

        for raw in (b"", b"\0"):
            with (
                self.subTest(raw=raw),
                mock.patch.object(process, "starttime", return_value=456),
                mock.patch.object(process, "read", return_value=raw),
            ):
                self.assertIsNone(process.restore_command(123))

        with (
            mock.patch.object(process, "starttime", return_value=456),
            mock.patch.object(process, "read", return_value=b"/usr/bin/app\0"),
            mock.patch.object(process.os, "readlink", side_effect=OSError("gone")),
        ):
            self.assertIsNone(process.restore_command(123))

        for cwd, starts in (("relative", (456, 456)), ("/home/alice", (456, 457))):
            with (
                self.subTest(cwd=cwd, starts=starts),
                mock.patch.object(process, "starttime", side_effect=starts),
                mock.patch.object(process, "read", return_value=b"/usr/bin/app\0"),
                mock.patch.object(process.os, "readlink", return_value=cwd),
            ):
                self.assertIsNone(process.restore_command(123))

    def test_cmdline_keeps_its_existing_display_format(self):
        with mock.patch.object(process, "read", return_value=b"one\0two\0"):
            self.assertEqual(process.cmdline(123), "one two")

    def test_restore_environment_uses_only_the_documented_allowlist(self):
        env = {
            "PATH": "/usr/bin",
            "HOME": "/home/alice",
            "LANG": "en_US.UTF-8",
            "LC_TIME": "C",
            "XDG_RUNTIME_DIR": "/run/user/1000",
            "TAEMA_CONFIG": "/tmp/secret.toml",
            "API_TOKEN": "secret",
            "PWD": "/old/cwd",
            "WAYLAND_DISPLAY": "wayland-1",
        }

        self.assertEqual(
            process.restore_environment(env),
            {
                key: env[key]
                for key in ("PATH", "HOME", "LANG", "LC_TIME", "XDG_RUNTIME_DIR")
            },
        )

    def test_restore_snapshot_is_opt_in_and_preserves_root_argv_and_cwd(self):
        proc_table = SimpleNamespace(ancestors=lambda _pid: [])
        snapshot = {
            "pid": 123,
            "start": 456,
            "argv": ["/usr/bin/editor", "", "document.txt"],
            "cwd": "/home/alice",
        }
        with (
            mock.patch.object(
                engine.inspect.ProcTable, "scan", return_value=proc_table
            ),
            mock.patch.object(
                engine.inspect, "restore_command", return_value=snapshot
            ) as capture,
        ):
            self.assertIsNone(engine.restore_snapshot([123], {"learn": {}}))
            capture.assert_not_called()
            self.assertEqual(
                engine.restore_snapshot([123], {"learn": {"remember_argv": True}}),
                snapshot,
            )
            capture.assert_called_once_with(123)

    def test_restore_command_reads_a_stable_root_argv_and_cwd(self):
        with (
            mock.patch.object(process, "starttime", side_effect=(456, 456)),
            mock.patch.object(
                process,
                "read",
                return_value=b"/usr/bin/editor\0\0document.txt\0",
            ),
            mock.patch.object(process.os, "readlink", return_value="/home/alice"),
        ):
            self.assertEqual(
                process.restore_command(123),
                {
                    "pid": 123,
                    "start": 456,
                    "argv": ["/usr/bin/editor", "", "document.txt"],
                    "cwd": "/home/alice",
                },
            )

    def test_versioned_undo_accepts_only_a_boolean_restore_flag(self):
        operation = {
            "v": 2,
            "id": "undo-restore",
            "op": "undo",
            "action_id": "12",
            "restore": True,
        }
        protocol.validate_feedback(operation)
        schema_path = Path(__file__).parents[1] / "schema" / "ipc" / "v2-request.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertTrue(
            __import__("tests.test_ipc_v2", fromlist=["matches"]).matches(
                operation, schema["$defs"]["feedback_args"], schema
            )
        )
        for invalid in ("yes", 1, None):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(protocol.ProtocolError),
            ):
                protocol.validate_feedback({**operation, "restore": invalid})
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_feedback({**operation, "v": 1})


class UndoStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = knowledge.Store(
            self.temporary.name,
            {},
            now=lambda: 1000.0,
        )

    def test_every_reversible_action_is_selected_persisted_and_repeat_guarded(self):
        actions = (
            (
                "containment",
                {"operation": "adopt_standalone", "members": [{"key": "vite"}]},
            ),
            (
                "qos",
                {
                    "operation": "restore_priorities",
                    "resources": [{"file": "cpu.weight", "value": "100"}],
                },
            ),
            ("freeze", {"operation": "thaw"}),
        )
        callback = mock.Mock(return_value={"ok": True})
        decisions = []
        for kind, undo in actions:
            decision = self.store.record_decision(
                kind,
                scope="leftover/vite",
                authority="mode",
                undo=undo,
            )
            decisions.append(decision)
        self.store.save()

        for decision, (_kind, undo) in zip(decisions, actions):
            result = self.store.undo_decision(
                str(decision["id"]), external_apply=callback
            )
            self.assertIsNotNone(result)
            self.assertEqual(result["effect"], {"ok": True})
            self.assertEqual(self.store.decision(decision["id"])["undone"], 1000.0)
            self.assertIsNone(
                self.store.undo_decision(str(decision["id"]), external_apply=callback)
            )
        self.assertEqual(callback.call_count, len(actions))
        self.assertEqual(self.store.data["standalone"]["vite"]["n"], 1)
        self.store.save()
        reopened = knowledge.Store(self.temporary.name, now=lambda: 1001.0)
        self.assertEqual(reopened.latest_undoable_decision(), None)

    def test_stop_undo_adds_keep_veto_suspension_and_is_durable_once(self):
        action = self.store.record_auto_action(
            "leftover/vite", "pair stop", [("npm", "vite")], ["vite"]
        )
        pair = self.store._pair("npm", "vite")
        pair["last_auto_stop"] = 900.0
        pair["pending_stop"] = {"signature_id": "sig-vite"}
        decision_id = action["decision_id"]
        self.store.save()

        result = self.store.undo_decision(str(decision_id), feedback_id="undo-once")

        self.assertIsNotNone(result)
        self.assertEqual(pair["ex_keep"], 3.0)
        self.assertEqual(pair["last_auto_stop"], 0.0)
        self.assertNotIn("pending_stop", pair)
        self.assertEqual(pair["suspended_until"], 1000.0 + self.store.regret_suspend)
        self.assertTrue(
            any(
                veto["kind"] == "app" and veto["value"] == "vite"
                for veto in self.store.data["vetoes"]
            )
        )
        self.assertEqual(self.store.decision(decision_id)["undone"], 1000.0)
        self.assertIsNone(self.store.undo_decision(str(decision_id)))
        self.store.save()

        reopened = knowledge.Store(self.temporary.name, now=lambda: 1001.0)
        self.assertIsNone(reopened.undo_candidate(str(decision_id)))
        self.assertEqual(reopened.decision(decision_id)["undone"], 1000.0)
        events = [
            json.loads(line)
            for line in Path(reopened.log_path).read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(sum(event["event"] == "undo" for event in events), 1)

    def test_restore_command_is_stored_only_when_snapshot_was_supplied(self):
        without = self.store.record_auto_action("scope-a", "stop", apps=["a"])
        with_snapshot = self.store.record_auto_action(
            "scope-b",
            "stop",
            apps=["b"],
            restore={"argv": ["/usr/bin/b", ""], "cwd": "/tmp"},
        )
        self.store.save()
        reopened = knowledge.Store(self.temporary.name, now=lambda: 1001.0)
        self.assertIsNone(reopened.decision(without["decision_id"])["argv"])
        self.assertEqual(
            reopened.decision(with_snapshot["decision_id"])["argv"],
            ["/usr/bin/b", ""],
        )
        self.assertEqual(reopened.decision(with_snapshot["decision_id"])["cwd"], "/tmp")

    def test_restore_marker_is_one_shot_and_failed_reservation_can_be_cleared(self):
        saved = self.store.record_auto_action(
            "scope-saved",
            "stop",
            apps=["saved"],
            restore={"argv": ["/usr/bin/saved"], "cwd": "/tmp"},
        )
        self.store.save()
        identifier = saved["decision_id"]
        self.assertTrue(self.store.mark_decision_restored(identifier, at=2000.0))
        self.assertFalse(self.store.mark_decision_restored(identifier, at=2001.0))
        self.assertFalse(self.store.clear_decision_restored(identifier, 1999.0))
        self.assertTrue(self.store.clear_decision_restored(identifier, 2000.0))
        self.assertFalse(self.store.clear_decision_restored(identifier, 2000.0))

        pending = self.store.record_auto_action(
            "scope-pending",
            "stop",
            apps=["pending"],
            restore={"argv": ["/usr/bin/pending"], "cwd": "/tmp"},
        )
        self.assertTrue(
            self.store.mark_decision_restored(pending["decision_id"], at=3000.0)
        )
        self.assertTrue(
            self.store.clear_decision_restored(pending["decision_id"], 3000.0)
        )

    def test_generic_undo_refusal_repeat_and_stop_scope_fallback(self):
        decision = self.store.record_decision(
            "freeze", scope="leftover/frozen", undo={"operation": "thaw"}
        )
        self.store.save()
        callback = mock.Mock(return_value={"ok": False, "error": "scope is gone"})
        self.assertIsNone(
            self.store.undo_decision(str(decision["id"]), external_apply=callback)
        )
        self.assertIsNone(
            self.store.undo_decision(str(decision["id"]), external_apply=None)
        )
        callback.assert_called_once()

        action = self.store.record_auto_action("scope-only", "stop")
        result = self.store.undo_decision(action["id"])
        self.assertEqual(result["vetoes"][0]["kind"], "scope")
        repeated = self.store.undo_decision(
            str(action["decision_id"]), allow_already_undone=True
        )
        self.assertTrue(repeated["already_undone"])

    def test_restore_feedback_cannot_run_a_generic_undo_effect(self):
        decision = self.store.record_decision(
            "freeze", scope="leftover/frozen", undo={"operation": "thaw"}
        )
        callback = mock.Mock(return_value={"ok": True})
        result = self.store.apply_feedback_command(
            {
                "v": 2,
                "id": "restore-wrong-kind",
                "op": "undo",
                "action_id": str(decision["id"]),
                "restore": True,
            },
            undo_handler=callback,
        )
        self.assertIsNone(result)
        callback.assert_not_called()


class UndoDaemonTests(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        self.state = tmp()
        self.daemon = service.Daemon(make_cfg(self.state, mode="enforce"))

    def test_undo_thaws_freeze_and_restores_priorities(self):
        freeze_scope = "leftover/frozen"
        freeze_path = self.cg.leaf(freeze_scope)
        freeze_file = os.path.join(freeze_path, "cgroup.freeze")
        Path(freeze_file).write_text("1\n", encoding="ascii")
        result = self.daemon._undo_action_effect(
            {"id": 1, "scope": freeze_scope, "undo": {"operation": "thaw"}}
        )
        self.assertEqual(result["thawed"], True)
        self.assertEqual(Path(freeze_file).read_text(encoding="ascii"), "0\n")

        qos_scope = "leftover/qos"
        qos_path = self.cg.leaf(qos_scope)
        for name in ("cpu.weight", "io.weight"):
            Path(os.path.join(qos_path, name)).write_text("10\n", encoding="ascii")
        undo = {
            "operation": "restore_priorities",
            "resources": [
                {"file": "cpu.weight", "value": "100"},
                {"file": "io.weight", "value": "default 100"},
            ],
            "oom_score_adj": [{"pid": 42, "start": 99, "value": 0}],
        }
        with (
            mock.patch.object(service.inspect, "starttime", return_value=99),
            mock.patch.object(service.engine, "helper_oom_restore") as restore_oom,
        ):
            result = self.daemon._undo_action_effect(
                {"id": 2, "scope": qos_scope, "undo": undo}
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            Path(os.path.join(qos_path, "cpu.weight")).read_text(), "100\n"
        )
        self.assertEqual(
            Path(os.path.join(qos_path, "io.weight")).read_text(), "default 100\n"
        )
        restore_oom.assert_called_once_with(self.daemon.cfg, 42, 0)

    def test_undo_containment_adopts_live_members_as_standalone(self):
        decision = self.daemon.store.record_decision(
            "containment",
            scope="leftover/app",
            undo={
                "operation": "adopt_standalone",
                "scope": "leftover/app",
                "members": [{"pid": 42, "start": 99, "key": "app"}],
            },
        )
        self.daemon.store.save()
        with (
            mock.patch.object(
                self.daemon,
                "_live_standalone_members",
                return_value=[{"pid": 42, "start": 99, "key": "app"}],
            ),
            mock.patch.object(
                self.daemon, "adopt_standalone", return_value=True
            ) as adopt,
        ):
            result = self.daemon.store.undo_decision(
                str(decision["id"]), external_apply=self.daemon._undo_action_effect
            )
        self.assertIsNotNone(result)
        adopt.assert_called_once()
        self.assertEqual(self.daemon.store.data["standalone"]["app"]["n"], 1)

    def test_restore_launch_uses_fresh_scope_devnull_and_filtered_environment(self):
        cwd = tempfile.mkdtemp()
        action = self.daemon.store.record_auto_action(
            "scope-old",
            "automatic stop",
            apps=["editor"],
            restore={"argv": ["/usr/bin/editor", "", "file"], "cwd": cwd},
        )
        self.daemon.store.save()
        decision_id = action["decision_id"]
        with (
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "/usr/bin",
                    "HOME": "/home/alice",
                    "LANG": "C",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                    "TAEMA_CONFIG": "/tmp/secret.toml",
                    "API_TOKEN": "secret",
                },
                clear=True,
            ),
            mock.patch.object(
                service.subprocess,
                "Popen",
                return_value=SimpleNamespace(pid=9876),
            ) as popen,
        ):
            result = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "restore-once",
                    "op": "undo",
                    "action_id": str(decision_id),
                    "restore": True,
                }
            )
            self.assertTrue(result["restored"])
            second = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "restore-again",
                    "op": "undo",
                    "action_id": str(decision_id),
                    "restore": True,
                }
            )

        self.assertIn("already been restored", second["error"])
        popen.assert_called_once()
        command, options = popen.call_args
        self.assertEqual(command[0][-4:], ["--", "/usr/bin/editor", "", "file"])
        self.assertEqual(options["cwd"], cwd)
        self.assertIs(options["stdin"], service.subprocess.DEVNULL)
        self.assertIs(options["stdout"], service.subprocess.DEVNULL)
        self.assertIs(options["stderr"], service.subprocess.DEVNULL)
        self.assertTrue(options["start_new_session"])
        env = options["env"]
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HOME"], "/home/alice")
        self.assertEqual(env["LANG"], "C")
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1000")
        self.assertEqual(env["TAEMA_RESTORE_LAUNCH"], "1")
        self.assertNotIn("TAEMA_CONFIG", env)
        self.assertNotIn("API_TOKEN", env)

    def test_restore_runner_strips_internal_and_unallowed_environment_before_exec(self):
        cfg = make_cfg(self.state, mode="enforce")
        store = knowledge.Store(self.state, {})
        args = SimpleNamespace(
            name="restore-1",
            bind=True,
            owner=None,
            join=False,
            dry_run=False,
            cmd=["/usr/bin/example"],
        )
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(cli, "ask", return_value=None),
            mock.patch.object(cli.engine, "helper_attach"),
            mock.patch.object(cli.os, "execvpe", side_effect=SystemExit) as execvpe,
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "/usr/bin",
                    "HOME": "/home/alice",
                    "TAEMA_RESTORE_LAUNCH": "1",
                    "TAEMA_CONFIG": "/tmp/secret.toml",
                    "API_TOKEN": "secret",
                },
                clear=True,
            ),
        ):
            with self.assertRaises(SystemExit):
                cli.cmd_run(args)
        env = execvpe.call_args.args[2]
        self.assertEqual(env, {"PATH": "/usr/bin", "HOME": "/home/alice"})
        self.assertEqual(execvpe.call_args.args[0], "/usr/bin/example")

    def test_failed_restore_launch_releases_reservation_for_retry(self):
        action = self.daemon.store.record_auto_action(
            "scope-old",
            "automatic stop",
            apps=["editor"],
            restore={"argv": ["/usr/bin/editor"], "cwd": tempfile.gettempdir()},
        )
        self.daemon.store.save()
        with mock.patch.object(
            service.subprocess,
            "Popen",
            side_effect=[OSError("launcher unavailable"), SimpleNamespace(pid=21)],
        ) as popen:
            failed = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "restore-failed",
                    "op": "undo",
                    "action_id": str(action["decision_id"]),
                    "restore": True,
                }
            )
            self.assertIn("could not relaunch", failed["error"])
            decision = self.daemon.store.decision(action["decision_id"])
            self.assertIsNone(decision["undo"].get("restored_at"))
            retried = self.daemon.handle(
                {
                    "cmd": "feedback",
                    "v": 2,
                    "id": "restore-retry",
                    "op": "undo",
                    "action_id": str(action["decision_id"]),
                    "restore": True,
                }
            )
        self.assertTrue(retried["restored"])
        self.assertEqual(popen.call_count, 2)


class RestoreCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = knowledge.Store(self.temporary.name, {})
        self.cfg = make_cfg(self.temporary.name, mode="auto")

    def test_undo_restore_and_restore_id_send_the_requested_decision(self):
        action = self.store.record_auto_action(
            "scope-old",
            "automatic stop",
            apps=["editor"],
            restore={"argv": ["/usr/bin/editor"], "cwd": "/tmp"},
        )
        decision_id = action["decision_id"]
        response = {"ok": True, "restored": True, "scope": "scope-restore-1", "pid": 17}
        for argv in (
            ["undo", "--restore", str(decision_id)],
            ["restore", str(decision_id)],
        ):
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(
                    cli, "_load", return_value=(self.cfg, self.store, [])
                ),
                mock.patch.object(cli, "ask", return_value=response) as ask,
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                self.assertEqual(cli.main(argv), 0)
            request = ask.call_args.args[1]
            self.assertEqual(request["op"], "undo")
            self.assertEqual(request["action_id"], str(decision_id))
            self.assertIs(request["restore"], True)
            self.assertEqual(err.getvalue(), "")
            self.assertIn("restor", out.getvalue())

    def test_restore_without_opt_in_explains_unavailable_and_undoes_stop(self):
        action = self.store.record_auto_action(
            "scope-old", "automatic stop", apps=["editor"]
        )
        decision_id = action["decision_id"]
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            mock.patch.object(cli, "ask", return_value={"ok": True}),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            self.assertEqual(cli.main(["undo", "--restore", str(decision_id)]), 0)
        self.assertIn("remember_argv was false", out.getvalue())
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.store.decision(decision_id)["argv"], None)

        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(self.cfg, self.store, [])),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            self.assertEqual(cli.main(["restore", str(decision_id)]), 2)
        self.assertIn("remember_argv was false", err.getvalue())
