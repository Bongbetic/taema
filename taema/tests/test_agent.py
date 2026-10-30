"""Session agent lifecycle: daemon ops, protection, status/doctor, client."""

import json
import os
import socket
import threading
import unittest
from unittest import mock

from taema import agent as agent_mod
from taema.core import cgroup
from taema.daemon import service
from taema.governor import engine
from taema import doctor
from taema import protocol
from tests.test_phase0 import FakeCg, make_cfg, tmp


def make_daemon(cfg=None):
    cfg = cfg or make_cfg(tmp(), mode="auto")
    daemon = service.Daemon(cfg)
    return daemon


def register(daemon, session="s1", pid=None, capabilities=("heartbeat",)):
    return daemon.handle(
        {
            "cmd": "register_agent",
            "session": session,
            "pid": os.getpid() if pid is None else pid,
            "capabilities": list(capabilities),
            "compositor": "/run/user/1000/wayland-0",
        }
    )


class RegisterAgentTests(unittest.TestCase):
    def test_register_ok(self):
        daemon = make_daemon()
        reply = register(daemon)
        self.assertEqual(reply, {"ok": True})
        self.assertEqual(daemon.agents["s1"]["state"], "up")

    def test_register_logs_agent_up(self):
        daemon = make_daemon()
        register(daemon)
        events = daemon.store.events_since(0, limit=100)["events"]
        self.assertTrue(any(e.get("event") == "agent_up" for e in events))

    def test_register_rejects_foreign_uid(self):
        daemon = make_daemon()
        with mock.patch.object(service.inspect, "uid_of", return_value=4321):
            reply = register(daemon)
        self.assertIn("error", reply)
        self.assertNotIn("s1", daemon.agents)

    def test_register_rejects_bad_session(self):
        daemon = make_daemon()
        reply = daemon.handle({"cmd": "register_agent", "session": "", "pid": 1})
        self.assertIn("error", reply)

    def test_second_registration_replaces(self):
        daemon = make_daemon()
        register(daemon, capabilities=("heartbeat",))
        reply = register(daemon, capabilities=("heartbeat", "wayland"))
        self.assertEqual(reply, {"ok": True})
        self.assertEqual(daemon.agents["s1"]["capabilities"], ["heartbeat", "wayland"])


class HeartbeatTests(unittest.TestCase):
    def test_beat_ok(self):
        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle(
            {"cmd": "agent_beat", "session": "s1", "pid": os.getpid()}
        )
        self.assertEqual(reply, {"ok": True})

    def test_beat_unknown_session_errors(self):
        daemon = make_daemon()
        reply = daemon.handle(
            {"cmd": "agent_beat", "session": "nope", "pid": os.getpid()}
        )
        self.assertIn("error", reply)

    def test_beat_rejects_foreign_uid(self):
        daemon = make_daemon()
        register(daemon)
        with mock.patch.object(service.inspect, "uid_of", return_value=4321):
            reply = daemon.handle(
                {"cmd": "agent_beat", "session": "s1", "pid": os.getpid()}
            )
        self.assertIn("error", reply)

    def test_beat_carries_facts(self):
        daemon = make_daemon()
        register(daemon)
        daemon.handle(
            {
                "cmd": "agent_beat",
                "session": "s1",
                "pid": os.getpid(),
                "facts": {"windows": ["a", "b"]},
            }
        )
        self.assertEqual(daemon.agent_facts("s1"), {"windows": ["a", "b"]})


class ExpiryTests(unittest.TestCase):
    def test_three_missed_beats_marks_down(self):
        daemon = make_daemon()
        register(daemon)
        daemon.agents["s1"]["last_beat"] -= 91.0
        daemon.agent_watch_pass()
        self.assertEqual(daemon.agents["s1"]["state"], "down")
        events = daemon.store.events_since(0, limit=100)["events"]
        self.assertTrue(any(e.get("event") == "agent_down" for e in events))

    def test_two_missed_beats_stays_up(self):
        daemon = make_daemon()
        register(daemon)
        daemon.agents["s1"]["last_beat"] -= 61.0
        daemon.agent_watch_pass()
        self.assertEqual(daemon.agents["s1"]["state"], "up")

    def test_down_agent_facts_refused(self):
        daemon = make_daemon()
        register(daemon)
        daemon.handle(
            {
                "cmd": "agent_beat",
                "session": "s1",
                "pid": os.getpid(),
                "facts": {"windows": ["a"]},
            }
        )
        self.assertEqual(daemon.agent_facts("s1"), {"windows": ["a"]})
        daemon.agents["s1"]["last_beat"] -= 91.0
        daemon.agent_watch_pass()
        self.assertEqual(daemon.agent_facts("s1"), {})
        self.assertFalse(daemon.agent_live("s1"))

    def test_beat_revives_down_agent(self):
        daemon = make_daemon()
        register(daemon)
        daemon.agents["s1"]["last_beat"] -= 91.0
        daemon.agent_watch_pass()
        self.assertEqual(daemon.agents["s1"]["state"], "down")
        reply = daemon.handle(
            {"cmd": "agent_beat", "session": "s1", "pid": os.getpid()}
        )
        self.assertEqual(reply, {"ok": True})
        self.assertEqual(daemon.agents["s1"]["state"], "up")

    def test_status_reports_agents(self):
        daemon = make_daemon()
        register(daemon)
        reply = daemon.handle({"cmd": "status"})
        self.assertEqual(reply["agents"]["s1"]["state"], "up")
        self.assertEqual(reply["agents"]["s1"]["pid"], os.getpid())


class AgentLeafProtectionTests(unittest.TestCase):
    def test_stop_refuses_agent_leaf(self):
        cfg = make_cfg(tmp(), mode="auto")
        with FakeCg():
            path = cgroup.base() + "/agent"
            os.makedirs(path, exist_ok=True)
            with self.assertRaises(engine.Refused):
                engine.stop(path, cfg, mock.Mock(), dry_run=True)

    def test_gc_never_lists_agent_leaf(self):
        cfg = make_cfg(tmp(), mode="auto")
        with FakeCg():
            os.makedirs(cgroup.base() + "/agent", exist_ok=True)
            cands = engine.gc_candidates(cfg, [], mock.Mock(), {})
        self.assertFalse([p for p, _ in cands if p.endswith("/agent")])

    def test_remove_empty_keeps_agent_leaf(self):
        with FakeCg():
            path = cgroup.base() + "/agent"
            os.makedirs(path, exist_ok=True)
            self.assertFalse(engine.remove_empty(path))

    def test_freeze_refuses_agent_leaf(self):
        daemon = make_daemon()
        reply = daemon.handle({"cmd": "freeze", "scope": "agent"})
        self.assertIn("error", reply)

    def test_reclaim_refuses_agent_leaf(self):
        daemon = make_daemon()
        self.assertIsNone(daemon._reclaim_class("agent", "/x/agent"))
        self.assertTrue(daemon._reclaim_safety_reason("agent", "/x/agent", []))

    def test_agent_pid_is_protected(self):
        from taema.config import policy

        cfg = make_cfg(tmp(), mode="auto")
        cfg["protected"] = {"comm": [], "cgroup_prefix": [], "env_prefix": {}}
        with mock.patch.object(
            cgroup, "proc_cgroup", return_value="/user/%d/agent" % os.getuid()
        ):
            reason = policy.protected_reason(os.getpid(), cfg)
        self.assertTrue(reason)


class DoctorTests(unittest.TestCase):
    def test_doctor_shows_agent_up(self):
        report = doctor.diagnose(
            make_cfg(tmp()), agents={"s1": {"state": "up", "pid": 9}}
        )
        checks = {c["name"]: c for c in report["checks"]}
        self.assertEqual(checks["session agent"]["status"], "ok")

    def test_doctor_warns_agent_down(self):
        report = doctor.diagnose(
            make_cfg(tmp()), agents={"s1": {"state": "down", "pid": 9}}
        )
        checks = {c["name"]: c for c in report["checks"]}
        self.assertEqual(checks["session agent"]["status"], "warn")

    def test_daemon_doctor_includes_agent(self):
        daemon = make_daemon()
        register(daemon)
        report = daemon.handle({"cmd": "doctor"})
        names = [c["name"] for c in report["checks"]]
        self.assertIn("session agent", names)


class ProtocolTests(unittest.TestCase):
    def test_v2_register_agent(self):
        command = protocol.decode_v2(
            {
                "v": 2,
                "id": 1,
                "cmd": "register_agent",
                "args": {"session": "s1", "pid": 99},
            }
        )
        self.assertEqual(command["cmd"], "register_agent")

    def test_v2_agent_beat(self):
        command = protocol.decode_v2(
            {"v": 2, "id": 2, "cmd": "agent_beat", "args": {"session": "s1", "pid": 99}}
        )
        self.assertEqual(command["cmd"], "agent_beat")


class FakeDaemon(threading.Thread):
    """Minimal socket answering legacy ok replies to v2 envelopes."""

    daemon = True

    def __init__(self, path):
        super().__init__()
        self.path = path
        self.seen = []
        self._stop_event = threading.Event()
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(8)
        self._srv.settimeout(0.2)

    def run(self):
        srv = self._srv
        while not self._stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(2.0)
                data = b""
                while b"\n" not in data:
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                try:
                    self.seen.append(json.loads(data.decode()))
                except ValueError:
                    continue
                try:
                    conn.sendall(b'{"ok": true}\n')
                except OSError:
                    pass
        srv.close()

    def stop(self):
        self._stop_event.set()
        self.join(timeout=5)


class AgentClientTests(unittest.TestCase):
    def test_lock_is_exclusive(self):
        path = os.path.join(tmp(), "agent-s1.lock")
        first = agent_mod.hold_lock(path)
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(agent_mod.hold_lock(path))
        finally:
            agent_mod.release_lock(first)

    def test_backoff_caps_at_30(self):
        self.assertEqual(
            [agent_mod.backoff(n) for n in range(7)], [1, 2, 4, 8, 16, 30, 30]
        )

    def test_compositor_gone_exits(self):
        missing = os.path.join(tmp(), "wayland-9")
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": missing}, clear=False):
            self.assertEqual(agent_mod.compositor_socket(), missing)
            self.assertFalse(agent_mod.compositor_live(missing))

    def test_capabilities(self):
        sock = os.path.join(tmp(), "wayland-0")
        open(sock, "w").close()
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": sock}, clear=False):
            caps = agent_mod.detect_capabilities()
        self.assertIn("heartbeat", caps)
        self.assertIn("wayland", caps)

    def test_register_and_beat_against_fake_daemon(self):
        state = tmp()
        sock = os.path.join(state, "a.sock")
        server = FakeDaemon(sock)
        server.start()
        self.addCleanup(server.stop)
        cfg = make_cfg(state)
        live = os.path.join(state, "wayland-0")
        open(live, "w").close()
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": live}, clear=False):
            agent = agent_mod.Agent(cfg, "s1")
            self.assertTrue(agent.connect())
            self.assertTrue(agent.beat())
        self.assertEqual(
            [msg["cmd"] for msg in server.seen], ["register_agent", "agent_beat"]
        )

    def test_run_loop_beats_then_exits_when_compositor_goes_away(self):
        state = tmp()
        sock = os.path.join(state, "a.sock")
        server = FakeDaemon(sock)
        server.start()
        self.addCleanup(server.stop)
        cfg = make_cfg(state)
        live = os.path.join(state, "wayland-0")
        open(live, "w").close()
        sleeps = []
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": live}, clear=False):
            agent = agent_mod.Agent(cfg, "s1")
            self.assertTrue(agent.connect())
            os.unlink(live)
            result = agent.run(sleep=sleeps.append)
        self.assertEqual(result, "compositor-gone")
        self.assertEqual(sleeps, [])

    def test_run_loop_backoff_on_loss(self):
        state = tmp()
        cfg = make_cfg(state)
        live = os.path.join(state, "wayland-0")
        open(live, "w").close()
        sleeps = []
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": live}, clear=False):
            agent = agent_mod.Agent(cfg, "s1")
            result = agent.run(sleep=sleeps.append, max_beats=3)
        self.assertEqual(result, "stopped")
        self.assertEqual(sleeps, [1, 2, 4])

    def test_ensure_leaf_moves_self(self):
        with FakeCg():
            self.assertTrue(agent_mod.ensure_leaf(os.getpid(), ask=lambda m: None))

    def test_ensure_leaf_asks_daemon_when_move_fails(self):
        calls = []
        with FakeCg():
            with mock.patch.object(cgroup, "move", side_effect=OSError("denied")):
                ok = agent_mod.ensure_leaf(
                    os.getpid(), ask=lambda m: calls.append(m) or {"ok": True}
                )
        self.assertTrue(ok)
        self.assertEqual(calls[0]["cmd"], "attach")
        self.assertEqual(calls[0]["scope"], "agent")

    def test_beat_loss_then_reconnect(self):
        state = tmp()
        sock = os.path.join(state, "a.sock")
        cfg = make_cfg(state)
        live = os.path.join(state, "wayland-0")
        open(live, "w").close()
        with mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": live}, clear=False):
            agent = agent_mod.Agent(cfg, "s1")
            self.assertFalse(agent.beat())
            server = FakeDaemon(sock)
            server.start()
            self.addCleanup(server.stop)
            self.assertTrue(agent.connect())
            self.assertTrue(agent.beat())
        self.assertEqual(
            [msg["cmd"] for msg in server.seen], ["register_agent", "agent_beat"]
        )


class StatusAgentTests(unittest.TestCase):
    def test_status_shows_agent(self):
        from taema.cli import view
        from types import SimpleNamespace

        model = view.snapshot("status", {"daemon": "running"})
        model["status"]["details"] = {
            "agents": {"s1": {"state": "up", "pid": 9, "capabilities": ["heartbeat"]}}
        }
        text = view.render_status(model, SimpleNamespace(_width=80, _color=False))
        self.assertIn("agent: up", text)
        self.assertIn("s1", text)

    def test_status_without_agents_omits_line(self):
        from taema.cli import view
        from types import SimpleNamespace

        model = view.snapshot("status", {"daemon": "unavailable"})
        text = view.render_status(model, SimpleNamespace(_width=80, _color=False))
        self.assertNotIn("agent:", text)


class AutostartTests(unittest.TestCase):
    def test_entries_ship(self):
        import taema

        root = os.path.dirname(os.path.dirname(os.path.dirname(taema.__file__)))
        base = os.path.join(root, "examples", "autostart")
        self.assertTrue(os.path.isfile(os.path.join(base, "taema-agent.desktop")))
        self.assertTrue(os.path.isfile(os.path.join(base, "niri-taema-agent.kdl")))


if __name__ == "__main__":
    unittest.main()
