"""Decision reversal and opt-in process restoration tests."""

import json
import io
import os
from pathlib import Path
import tempfile
import threading
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
            "oom_score_adj": [{"pid": 42, "start": 99, "value": 0, "applied": 500}],
        }
        with (
            mock.patch.object(service.inspect, "starttime", return_value=99),
            mock.patch.object(service.inspect, "uid_of", return_value=os.getuid()),
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
        restore_oom.assert_called_once_with(self.daemon.cfg, 42, 99, 0, 500)

    def test_restore_filters_stale_oom_history_before_applying_record_limit(self):
        scope = "leftover/qos-history"
        self.cg.leaf(scope)
        stale = [
            {"pid": pid, "start": 1, "value": -100, "applied": 500}
            for pid in range(10000, 10000 + service.MAX_QOS_OOM_RECORDS + 1)
        ]
        oom_values = stale + [{"pid": 42, "start": 99, "value": 0, "applied": 500}]

        def starttime(pid):
            if pid == 42:
                return 99
            raise ProcessLookupError(pid)

        with (
            mock.patch.object(service.inspect, "starttime", side_effect=starttime),
            mock.patch.object(service.inspect, "uid_of", return_value=os.getuid()),
            mock.patch.object(service.engine, "helper_oom_restore") as restore_oom,
        ):
            result = self.daemon._undo_action_effect(
                {
                    "id": 3,
                    "scope": scope,
                    "undo": {
                        "operation": "restore_priorities",
                        "resources": [],
                        "oom_score_adj": oom_values,
                    },
                }
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["oom_score_adj"], 1)
        restore_oom.assert_called_once_with(self.daemon.cfg, 42, 99, 0, 500)

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

    def test_refused_standalone_adoption_does_not_consume_undo(self):
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
                service.engine,
                "run_ops",
                side_effect=service.engine.Refused("helper refused move"),
            ),
        ):
            result = self.daemon.store.undo_decision(
                str(decision["id"]), external_apply=self.daemon._undo_action_effect
            )
        self.assertIsNone(result)
        self.assertFalse(self.daemon.store.decision(decision["id"])["undone"])

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
                side_effect=lambda _command, **options: (
                    os.write(options["pass_fds"][0], b"R"),
                    SimpleNamespace(pid=9876),
                )[1],
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
        self.assertEqual(len(options["pass_fds"]), 1)
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
        read_fd, write_fd = os.pipe()
        try:
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
                mock.patch.object(cli.engine, "helper_attach"),
                mock.patch.object(
                    cli.os, "execvpe", side_effect=OSError("executable unavailable")
                ) as execvpe,
                mock.patch.dict(
                    os.environ,
                    {
                        "PATH": "/usr/bin",
                        "HOME": "/home/alice",
                        "TAEMA_RESTORE_LAUNCH": "1",
                        "TAEMA_RESTORE_ACK_FD": str(write_fd),
                        "TAEMA_CONFIG": "/tmp/secret.toml",
                        "API_TOKEN": "secret",
                    },
                    clear=True,
                ),
            ):
                self.assertNotEqual(cli.cmd_run(args), 0)
        finally:
            os.close(write_fd)
        ack = os.read(read_fd, 4096)
        os.close(read_fd)
        self.assertTrue(ack.startswith(b"RE"))
        self.assertIn(b"executable unavailable", ack)
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

        def start_runner(_command, **options):
            if popen.call_count == 1:
                raise OSError("launcher unavailable")
            os.write(options["pass_fds"][0], b"R")
            return SimpleNamespace(pid=21)

        with mock.patch.object(
            service.subprocess, "Popen", side_effect=start_runner
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

    def test_restore_startup_without_exec_ack_releases_reservation(self):
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
            return_value=SimpleNamespace(pid=23),
        ):
            result = self.daemon._launch_restored(action["decision_id"])
        self.assertIn("before confirming", result["error"])
        decision = self.daemon.store.decision(action["decision_id"])
        self.assertIsNone(decision["undo"].get("restored_at"))

    def test_restore_startup_services_child_rpc_through_live_daemon_socket(self):
        action = self.daemon.store.record_auto_action(
            "scope-old",
            "automatic stop",
            apps=["editor"],
            restore={"argv": ["/usr/bin/editor"], "cwd": tempfile.gettempdir()},
        )
        self.daemon.store.save()
        self.daemon.bind(self.daemon.cfg["paths"]["socket"])

        def close_daemon_sockets():
            for fd in tuple(self.daemon.owners):
                try:
                    self.daemon.sel.unregister(fd)
                except (KeyError, OSError, ValueError):
                    pass
                os.close(fd)
            self.daemon.owners.clear()
            if self.daemon.srv is not None:
                self.daemon.srv.close()
            self.daemon.sel.close()

        self.addCleanup(close_daemon_sockets)
        response = []
        runner_thread = []

        def start_runner(_command, **options):
            write_fd = os.dup(options["pass_fds"][0])

            def run_child_rpc():
                try:
                    result = cli.ask(
                        self.daemon.cfg,
                        {
                            "cmd": "register",
                            "scope": "scope-restore-%d" % action["decision_id"],
                            "owner": os.getpid(),
                        },
                    )
                    response.append(result)
                    os.write(
                        write_fd, b"R" if result and result.get("watching") else b"E"
                    )
                finally:
                    os.close(write_fd)

            thread = threading.Thread(target=run_child_rpc, daemon=True)
            thread.start()
            runner_thread.append(thread)
            return SimpleNamespace(pid=90001)

        with mock.patch.object(service.subprocess, "Popen", side_effect=start_runner):
            result = self.daemon._launch_restored(action["decision_id"])
        runner_thread[0].join(timeout=4)
        self.assertFalse(runner_thread[0].is_alive())
        self.assertEqual(response, [{"watching": True}])
        self.assertTrue(result["restored"])

    def test_restore_startup_timeout_is_bounded(self):
        read_fd, write_fd = os.pipe()
        try:
            with (
                mock.patch.object(service.time, "monotonic", return_value=0.0),
                mock.patch.object(service.select, "select", return_value=([], [], [])),
            ):
                started, error = self.daemon._await_restore_startup(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertFalse(started)
        self.assertIn("timed out", error)

    def test_restore_startup_ack_reports_runner_errors_and_rejects_bad_payloads(self):
        for payload, expected in (
            (b"Eexec failed", "exec failed"),
            (b"Rattach then failed", "attach then failed"),
            (b"unexpected", "before confirming"),
        ):
            with self.subTest(payload=payload):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, payload)
                os.close(write_fd)
                try:
                    started, error = self.daemon._await_restore_startup(read_fd)
                finally:
                    os.close(read_fd)
                self.assertFalse(started)
                self.assertIn(expected, error)

        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"x" * 5000)
        os.close(write_fd)
        try:
            started, error = self.daemon._await_restore_startup(read_fd)
        finally:
            os.close(read_fd)
        self.assertFalse(started)
        self.assertIn("too large", error)

    def test_restore_startup_ack_handles_read_errors_and_expired_deadline(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        try:
            with (
                mock.patch.object(
                    service.select, "select", return_value=([read_fd], [], [])
                ),
                mock.patch.object(
                    service.os, "read", side_effect=OSError("read failed")
                ),
            ):
                started, error = self.daemon._await_restore_startup(read_fd)
        finally:
            os.close(read_fd)
        self.assertFalse(started)
        self.assertIn("read failed", error)

        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(service.time, "monotonic", side_effect=[0.0, 16.0]):
                started, error = self.daemon._await_restore_startup(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertFalse(started)
        self.assertIn("timed out", error)

    def test_restore_launcher_is_killed_after_shutdown_timeout(self):
        child = SimpleNamespace(
            poll=mock.Mock(return_value=None),
            terminate=mock.Mock(),
            wait=mock.Mock(
                side_effect=[service.subprocess.TimeoutExpired("runner", 1), None]
            ),
            kill=mock.Mock(),
        )
        service.Daemon._stop_restore_launcher(child)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)


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
