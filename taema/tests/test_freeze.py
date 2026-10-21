"""Safety and lifecycle checks for reversible leftover freezing."""

import io
import os
import time
from pathlib import Path
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from unittest import mock

from taema.cli import commands
from taema.cli import view
from taema.core import cgroup
from taema.daemon import service
from taema.governor import engine, freezing
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg, tmp
from tests.test_phase1 import write


class EmptySnapshot:
    ok = True
    tcp = ()
    tcp_listen = ()
    unix = ()
    by_inode = {}


class FakeLineage:
    def entry(self, _pid):
        return {"start": 100, "key": "app:browser"}

    def observe(self, _table):
        return None

    def ptmx_host(self, _pid):
        return False


class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.cg = FakeCg().__enter__()
        self.addCleanup(self.cg.__exit__)
        runtime = mock.patch.dict(
            os.environ, {"XDG_RUNTIME_DIR": os.path.join(self.cg.root, "runtime")}
        )
        runtime.start()
        self.addCleanup(runtime.stop)
        self.scope = "leftover/browser"
        self.path = self.cg.leaf(self.scope, [4242], cpu=0)
        write(os.path.join(self.path, "cgroup.freeze"), "0\n")
        self.proc_root = os.path.join(self.cg.root, "proc")
        os.makedirs(os.path.join(self.proc_root, "4242", "fd"))
        write(os.path.join(self.proc_root, "4242", "environ"), "PATH=/bin\0")
        self.cfg = make_cfg(
            os.path.join(self.cg.root, "state"),
            mode="enforce",
            freeze={
                "enabled": True,
                "adopt": False,
                "after": 120,
                "wake_on_connect": True,
                "max_frozen": 32,
                "cpu_idle_max": 0.5,
            },
            experimental={"freeze": True},
            protected={"comm": [], "cgroup_prefix": [], "env_prefix": {}},
            mem={"enabled": False},
        )
        self.daemon = service.Daemon(self.cfg)
        self.daemon.lineage = FakeLineage()
        self.patches = [
            mock.patch.object(service.inspect, "PROC", self.proc_root),
            mock.patch.object(service.inspect.ProcTable, "scan", return_value=None),
            mock.patch.object(service.inspect, "Snapshot", return_value=EmptySnapshot()),
            mock.patch.object(service.inspect, "edges", return_value={}),
            mock.patch.object(service.policy, "protected_reason", return_value=None),
            mock.patch.object(
                service.cgroup,
                "proc_cgroup",
                return_value="/user/%d/%s" % (os.getuid(), self.scope),
            ),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_auto_freezes_only_after_a_full_cpu_idle_window_and_grace(self):
        self.cg.set_cpu(self.scope, 0)
        self.assertEqual(self.daemon.freeze_pass(now=0), [])
        self.assertEqual(self.daemon.freeze_pass(now=60), [])
        results = self.daemon.freeze_pass(now=120)
        self.assertTrue(results[0]["ok"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "1\n")
        self.assertEqual(
            self.daemon.store.data["frozen_scopes"][self.scope]["source"], "auto"
        )
        self.assertNotIn(self.scope, self.daemon.freeze_usage)
        self.assertNotIn(self.scope, self.daemon.freeze_idle_since)

    def test_unknown_socket_state_keeps_the_scope_running(self):
        bad_snapshot = SimpleNamespace(ok=False)
        with mock.patch.object(
            service.inspect, "Snapshot", return_value=bad_snapshot
        ):
            reason = self.daemon._freeze_safety_reason(self.scope, self.path)
        self.assertEqual(reason, "socket state unknown")
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")

    def test_unmatched_socket_fd_and_new_pty_host_fail_closed(self):
        fd_dir = os.path.join(self.proc_root, "4242", "fd")
        os.symlink("socket:[123456]", os.path.join(fd_dir, "5"))
        self.assertEqual(
            self.daemon._freeze_safety_reason(self.scope, self.path),
            "socket state unknown",
        )
        os.unlink(os.path.join(fd_dir, "5"))
        # The freeze check must inspect current descriptors, not a cached false result.
        os.symlink("/dev/ptmx", os.path.join(fd_dir, "6"))
        self.daemon.lineage.ptmx_host = lambda _pid: False
        self.assertEqual(
            self.daemon._freeze_safety_reason(self.scope, self.path), "pty host"
        )

    def test_listeners_and_compositor_clients_are_never_frozen(self):
        listener = EmptySnapshot()
        listener.unix = ({"state": "LISTEN", "pids": {4242}},)
        self.assertEqual(
            freezing.socket_safety_reason({4242}, listener), "listening socket"
        )
        compositor = EmptySnapshot()
        compositor.unix = (
            {"state": "ESTAB", "pids": {4242}, "peer_inode": 9, "path": ""},
        )
        compositor.by_inode = {
            9: {"path": "/run/user/1000/wayland-0", "peer_path": "", "pids": {9}}
        }
        self.assertEqual(
            freezing.socket_safety_reason({4242}, compositor),
            "connected to a window compositor",
        )

    def test_wake_on_connect_freeze_records_tcp_listener(self):
        listener = {
            "state": "LISTEN",
            "recv_q": 0,
            "send_q": 8,
            "local": "127.0.0.1:8000",
            "inode": 9101,
            "pids": {4242},
        }
        snapshot = SimpleNamespace(
            ok=True,
            tcp=(),
            tcp_listen=(listener,),
            unix=(),
            udp=(),
            by_inode={},
            socket_inodes={9101},
        )
        with mock.patch.object(service.inspect, "Snapshot", return_value=snapshot):
            reason = self.daemon._freeze_safety_reason(self.scope, self.path)
            frozen = self.daemon.freeze_scope(
                self.scope, manual=False, cpu_verified=True
            )

        self.assertEqual(reason, "")
        self.assertTrue(frozen["ok"])
        self.assertEqual(
            self.daemon.store.data["frozen_scopes"][self.scope]["listeners"],
            [{"transport": "tcp", "inode": 9101}],
        )

    def test_wake_on_connect_freeze_records_unix_listener(self):
        listener = {
            "state": "LISTEN",
            "recv_q": 0,
            "send_q": 8,
            "path": "/run/user/1000/test.sock",
            "peer_path": "",
            "inode": 9103,
            "peer_inode": 0,
            "pids": {4242},
        }
        snapshot = SimpleNamespace(
            ok=True,
            tcp=(),
            tcp_listen=(),
            unix=(listener,),
            udp=(),
            by_inode={9103: listener},
            socket_inodes={9103},
        )
        with mock.patch.object(service.inspect, "Snapshot", return_value=snapshot):
            reason = self.daemon._freeze_safety_reason(self.scope, self.path)
            frozen = self.daemon.freeze_scope(
                self.scope, manual=False, cpu_verified=True
            )

        self.assertEqual(reason, "")
        self.assertTrue(frozen["ok"])
        self.assertEqual(
            self.daemon.store.data["frozen_scopes"][self.scope]["listeners"],
            [{"transport": "unix", "inode": 9103}],
        )

    def test_listener_freeze_stays_disabled_without_wake_on_connect(self):
        self.daemon.cfg["freeze"]["wake_on_connect"] = False
        listener = {
            "state": "LISTEN",
            "recv_q": 0,
            "send_q": 8,
            "local": "127.0.0.1:8000",
            "inode": 9102,
            "pids": {4242},
        }
        snapshot = SimpleNamespace(
            ok=True,
            tcp=(),
            tcp_listen=(listener,),
            unix=(),
            udp=(),
            by_inode={},
            socket_inodes={9102},
        )
        self.assertEqual(
            self.daemon._freeze_safety_reason(self.scope, self.path, snapshot),
            "listening socket",
        )

    def _assert_listener_queue_wakes_scope(self, transport):
        inode = 9201 if transport == "tcp" else 9202
        descriptor = {"transport": transport, "inode": inode}
        self.daemon.store.set_frozen_scope(
            self.scope, 1.0, listeners=[descriptor], source="auto"
        )
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        fd_dir = os.path.join(self.proc_root, "4242", "fd")
        os.symlink("socket:[%d]" % inode, os.path.join(fd_dir, "5"))
        row = {
            "state": "LISTEN",
            "recv_q": 0,
            "send_q": 8,
            "inode": inode,
            "pids": {4242},
        }
        if transport == "tcp":
            row["local"] = "127.0.0.1:8000"
            snapshot = SimpleNamespace(
                ok=True,
                tcp=(),
                tcp_listen=(row,),
                unix=(),
                udp=(),
                by_inode={},
                socket_inodes={inode},
            )
        else:
            row.update({"path": "/run/test.sock", "peer_path": "", "peer_inode": 0})
            snapshot = SimpleNamespace(
                ok=True,
                tcp=(),
                tcp_listen=(),
                unix=(row,),
                udp=(),
                by_inode={inode: row},
                socket_inodes={inode},
            )

        with (
            mock.patch.object(service.inspect, "Snapshot", return_value=snapshot) as take,
            mock.patch.object(self.daemon.store, "log", wraps=self.daemon.store.log) as log,
        ):
            self.assertEqual(self.daemon.listener_wake_pass(now=1000.0), [])
            self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "1\n")
            self.assertEqual(self.daemon.listener_wake_pass(now=1001.9), [])
            self.assertEqual(take.call_count, 1)
            row["recv_q"] = 1
            result = self.daemon.listener_wake_pass(now=1002.0)

        self.assertTrue(result[0]["thawed"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, self.daemon.store.data["frozen_scopes"])
        self.assertTrue(
            any(
                call.kwargs.get("event") == "thaw"
                and call.kwargs.get("reason") == "connect"
                for call in log.call_args_list
            )
        )

    def test_pending_tcp_connection_thaws_listener_scope(self):
        self._assert_listener_queue_wakes_scope("tcp")

    def test_pending_unix_connection_thaws_listener_scope(self):
        self._assert_listener_queue_wakes_scope("unix")

    def test_connection_accepted_during_freeze_race_thaws_listener_scope(self):
        inode = 9203
        self.daemon.store.set_frozen_scope(
            self.scope,
            1.0,
            listeners=[{"transport": "tcp", "inode": inode}],
            source="auto",
        )
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        fd_dir = os.path.join(self.proc_root, "4242", "fd")
        os.symlink("socket:[%d]" % inode, os.path.join(fd_dir, "5"))
        established = {
            "state": "ESTAB",
            "recv_q": 0,
            "send_q": 0,
            "local": "127.0.0.1:8000",
            "peer": "127.0.0.1:42123",
            "inode": 9204,
            "pids": {4242},
        }
        os.symlink("socket:[9204]", os.path.join(fd_dir, "6"))
        listener = {
            "state": "LISTEN",
            "recv_q": 0,
            "send_q": 8,
            "local": "127.0.0.1:8000",
            "peer": "0.0.0.0:*",
            "inode": inode,
            "pids": {4242},
        }
        snapshot = SimpleNamespace(
            ok=True,
            tcp=(established,),
            tcp_listen=(listener,),
            unix=(),
            udp=(),
            by_inode={},
            socket_inodes={inode, 9204},
        )
        with (
            mock.patch.object(service.inspect, "Snapshot", return_value=snapshot),
            mock.patch.object(self.daemon.store, "log", wraps=self.daemon.store.log) as log,
        ):
            result = self.daemon.listener_wake_pass(now=1000.0)

        self.assertTrue(result[0]["thawed"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertTrue(
            any(
                call.kwargs.get("event") == "thaw"
                and call.kwargs.get("reason") == "connect"
                for call in log.call_args_list
            )
        )

    def test_accept_queue_poll_is_scheduled_only_for_frozen_listeners(self):
        self.daemon.last.update(
            {"adopt": 1000.0, "gc": 1000.0, "freeze": 1000.0}
        )
        self.daemon.last_listener_check = 1000.0
        without_listener = self.daemon.next_timeout(now=1000.0)
        self.daemon.store.set_frozen_scope(
            self.scope,
            1000.0,
            listeners=[{"transport": "tcp", "inode": 9301}],
        )
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        with_listener = self.daemon.next_timeout(now=1000.0)
        self.assertGreater(without_listener, 2.0)
        self.assertEqual(with_listener, 2.0)

    def test_no_accept_queue_snapshot_without_frozen_listener(self):
        with mock.patch.object(
            service.inspect, "Snapshot", side_effect=AssertionError("unexpected poll")
        ):
            self.assertEqual(self.daemon.listener_wake_pass(now=1000.0), [])

    def test_listener_wake_still_thaws_when_store_writer_is_busy(self):
        inode = 9302
        self.daemon.store.set_frozen_scope(
            self.scope,
            1.0,
            listeners=[{"transport": "tcp", "inode": inode}],
        )
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        os.symlink(
            "socket:[%d]" % inode,
            os.path.join(self.proc_root, "4242", "fd", "5"),
        )
        listener = {
            "state": "LISTEN",
            "recv_q": 1,
            "send_q": 8,
            "local": "127.0.0.1:8000",
            "peer": "0.0.0.0:*",
            "inode": inode,
            "pids": {4242},
        }
        snapshot = SimpleNamespace(
            ok=True,
            tcp=(),
            tcp_listen=(listener,),
            unix=(),
            udp=(),
            by_inode={},
            socket_inodes={inode},
        )

        with (
            mock.patch.object(service.inspect, "Snapshot", return_value=snapshot),
            mock.patch.object(self.daemon.store.db, "write_available", return_value=False),
        ):
            self.daemon.tick()

        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertTrue(
            any(
                event["event"] == "thaw"
                and event["data"].get("reason") == "connect"
                for event in self.daemon.store.events_since(0)["events"]
            )
        )

    def test_manual_freeze_and_thaw_work_in_observe_mode(self):
        self.daemon.cfg["mode"] = "observe"
        self.daemon.manual_freeze_usage[self.scope] = (
            0,
            time.time() - 61.0,
            (4242,),
        )
        frozen = self.daemon.handle({"cmd": "freeze", "scope": self.scope})
        self.assertTrue(frozen["frozen"])
        self.assertEqual(
            self.daemon.store.data["frozen_scopes"][self.scope]["source"], "manual"
        )
        thawed = self.daemon.handle({"cmd": "thaw", "scope": self.scope})
        self.assertTrue(thawed["thawed"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, self.daemon.store.data["frozen_scopes"])

    def test_manual_freeze_requires_a_full_idle_cpu_sample(self):
        self.daemon.cfg["mode"] = "observe"
        result = self.daemon.freeze_scope(self.scope, manual=True)
        self.assertFalse(result["ok"])
        self.assertIn("60-second", result["error"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")

    def test_observe_pass_preserves_manual_cpu_sample(self):
        self.daemon.cfg["mode"] = "observe"
        now = {"value": 1000.0}
        with mock.patch.object(service.time, "time", side_effect=lambda: now["value"]):
            first = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertFalse(first["ok"])
            self.assertIn("60-second", first["error"])

            self.daemon.freeze_pass(now=1060.0)
            now["value"] = 1061.0
            retry = self.daemon.freeze_scope(self.scope, manual=True)

        self.assertTrue(retry["ok"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "1\n")

    def test_thaw_requires_a_new_running_cpu_sample_before_manual_refreeze(self):
        self.daemon.cfg["mode"] = "observe"
        now = {"value": 1000.0}
        with mock.patch.object(service.time, "time", side_effect=lambda: now["value"]):
            first = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertFalse(first["ok"])

            now["value"] = 1061.0
            frozen = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertTrue(frozen["ok"])

            now["value"] = 1121.0
            thawed = self.daemon.handle({"cmd": "thaw", "scope": self.scope})
            self.assertTrue(thawed["thawed"])
            self.cg.set_cpu(self.scope, 100_000)

            now["value"] = 1122.0
            retry = self.daemon.freeze_scope(self.scope, manual=True)

        self.assertFalse(retry["ok"])
        self.assertIn("60-second", retry["error"])
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")

    def test_hold_refuses_freeze_and_managed_veto_thaws(self):
        self.daemon.store.apply_feedback_command(
            {"v": 2, "id": "hold-freeze", "op": "hold", "held": True}
        )
        held = self.daemon.freeze_scope(self.scope, manual=True)
        self.assertFalse(held["ok"])
        self.assertIn("held", held["error"])
        self.daemon.store.data["held"] = False
        self.daemon.store.add_veto("scope", self.scope)
        self.daemon.store.set_frozen_scope(self.scope, 1.0, source="manual")
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        self.daemon.thaw_held_scopes()
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, self.daemon.store.data["frozen_scopes"])

    def test_startup_recovers_prior_managed_freeze(self):
        self.daemon.store.set_frozen_scope(self.scope, 1.0, source="auto")
        self.daemon.store.save()
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        recovered = service.Daemon(self.cfg)
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, recovered.store.data["frozen_scopes"])

    def test_every_stop_thaws_a_managed_scope_first(self):
        self.daemon.cfg["mode"] = "observe"
        now = {"value": 1000.0}
        with mock.patch.object(service.time, "time", side_effect=lambda: now["value"]):
            self.daemon.manual_freeze_usage[self.scope] = (0, 939.0, (4242,))
            self.daemon.freeze_usage[self.scope] = (0, 939.0, (4242,))
            self.daemon.freeze_idle_since[self.scope] = 880.0
            result = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertTrue(result["ok"])

            now["value"] = 1061.0
            repeated = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertTrue(repeated["ok"])
            self.assertTrue(repeated["already"])
            self.assertNotIn(self.scope, self.daemon.manual_freeze_usage)

            now["value"] = 1121.0
            repeated = self.daemon.freeze_scope(self.scope, manual=True)
            self.assertTrue(repeated["already"])
            self.assertNotIn(self.scope, self.daemon.manual_freeze_usage)

            now["value"] = 1181.0
            with mock.patch.object(
                engine, "_stop_impl", return_value={"stopped": True}
            ):
                engine.stop(self.path, self.cfg, self.daemon.store)
            self.assertNotIn(self.scope, self.daemon.manual_freeze_usage)
            self.assertNotIn(self.scope, self.daemon.freeze_usage)
            self.assertNotIn(self.scope, self.daemon.freeze_idle_since)
            self.cg.set_cpu(self.scope, 100_000)
            now["value"] = 1182.0
            retry = self.daemon.freeze_scope(self.scope, manual=True)

        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, self.daemon.store.data["frozen_scopes"])
        self.assertNotIn(self.scope, self.daemon.freeze_usage)
        self.assertFalse(retry["ok"])
        self.assertIn("60-second", retry["error"])

    def test_auto_freeze_thaws_before_scope_loses_leaf_status(self):
        self.daemon.store.set_frozen_scope(self.scope, 1.0, source="auto")
        write(os.path.join(self.path, "cgroup.freeze"), "1\n")
        child = os.path.join(self.path, "child")
        os.makedirs(child)
        write(os.path.join(child, "cgroup.procs"), "")
        self.daemon.freeze_pass(now=180)
        self.assertEqual(Path(self.path, "cgroup.freeze").read_text(), "0\n")
        self.assertNotIn(self.scope, self.daemon.store.data["frozen_scopes"])

    def test_recovery_intent_is_saved_before_kernel_freeze(self):
        self.daemon.cfg["mode"] = "observe"
        self.daemon.manual_freeze_usage[self.scope] = (
            0,
            time.time() - 61.0,
            (4242,),
        )
        save = self.daemon.store.save
        observations = []

        def inspect_save():
            observations.append(
                (
                    Path(self.path, "cgroup.freeze").read_text(),
                    self.scope in self.daemon.store.data["frozen_scopes"],
                )
            )
            return save()

        with mock.patch.object(self.daemon.store, "save", side_effect=inspect_save):
            result = self.daemon.freeze_scope(self.scope, manual=True)
        self.assertTrue(result["ok"])
        self.assertEqual(observations[0], ("0\n", True))

    def test_ls_and_why_mark_a_frozen_scope(self):
        self.daemon.store.set_frozen_scope(self.scope, 1.0, source="manual")
        output = io.StringIO()
        args = SimpleNamespace(wide=True, _width=120, _color=False)
        with (
            mock.patch.object(commands, "_load", return_value=(self.cfg, self.daemon.store, [])),
            mock.patch.object(commands, "_memory_snapshot", return_value={"scopes": []}),
            mock.patch.object(commands.inspect, "comm", return_value="browser"),
            redirect_stdout(output),
        ):
            self.assertEqual(commands.cmd_ls(args), 0)
        self.assertIn("browser ❄", output.getvalue())
        explanation = commands._why_report(
            self.cfg, self.daemon.store, target_scope=self.scope, scope_live=True
        )
        self.assertTrue(explanation["scope"]["frozen"])
        self.assertIn("❄", view.render_explanation(self.scope, explanation))


if __name__ == "__main__":
    unittest.main()
