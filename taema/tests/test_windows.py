"""Tests for the niri window backend (issue #60).

Recorded niri event streams replay through a real (socketpair) fake
socket: snapshot parsing, open/change/close/focus normalization, full
state replacement, unknown-event tolerance, and title dropping.
"""

import json
import os
import socket
import unittest
from unittest import mock

from taema import windows


def window(id, app_id="firefox", pid=4242, focused=False, title="t"):
    return {
        "id": id,
        "title": title,
        "app_id": app_id,
        "pid": pid,
        "workspace_id": 1,
        "is_focused": focused,
        "is_floating": False,
        "is_urgent": False,
        "layout": {},
        "focus_timestamp": None,
    }


RECORDED_STREAM = [
    # Up-front state: two windows, one focused.
    {
        "WindowsChanged": {
            "windows": [window(1, focused=True), window(2, app_id="foot")]
        }
    },
    # A new window opens.
    {"WindowOpenedOrChanged": {"window": window(3, app_id="mpv", pid=5000)}},
    # Focus moves.
    {"WindowFocusChanged": {"id": 3}},
    # A title change on a known window.
    {"WindowOpenedOrChanged": {"window": window(1, title="new title")}},
    # A window without pid or app id (older niri / odd client).
    {"WindowOpenedOrChanged": {"window": window(4, app_id=None, pid=None)}},
    # Unknown future events are ignored, not fatal.
    {"WorkspacesChanged": {"workspaces": []}},
    {"SomeFutureEvent": {"x": 1}},
    "not json at all",
    # A close.
    {"WindowClosed": {"id": 2}},
    # Focus leaves windows entirely.
    {"WindowFocusChanged": {"id": None}},
]


def replay(lines):
    """Feed JSON lines through a socketpair; yield what the backend reads."""
    client, server = socket.socketpair()
    with client, server:
        for line in lines:
            text = line if isinstance(line, str) else json.dumps(line)
            server.sendall((text + "\n").encode())
        server.shutdown(socket.SHUT_WR)
        reader = client.makefile("r", encoding="utf-8")
        for arrived in reader:
            yield arrived


class NormalizeTest(unittest.TestCase):
    def test_normalizes_a_window(self):
        self.assertEqual(
            windows.normalize_window(window(7, focused=True), store_titles=False),
            {"id": 7, "app_id": "firefox", "pid": 4242, "focused": True},
        )

    def test_titles_kept_only_on_request(self):
        plain = windows.normalize_window(window(7), store_titles=False)
        self.assertNotIn("title", plain)
        kept = windows.normalize_window(window(7), store_titles=True)
        self.assertEqual(kept["title"], "t")

    def test_missing_ids_and_pids(self):
        self.assertIsNone(windows.normalize_window({"app_id": "x"}))
        self.assertIsNone(windows.normalize_window({"id": "nan", "pid": 1}))
        parsed = windows.normalize_window(window(7, app_id=None, pid=None))
        self.assertEqual(
            parsed, {"id": 7, "app_id": None, "pid": None, "focused": False}
        )
        negative = windows.normalize_window(window(7, pid=-1))
        self.assertIsNone(negative["pid"])


class IngestTest(unittest.TestCase):
    def test_recorded_stream(self):
        backend = windows.NiriBackend(socket_path="/nonexistent")
        events = []
        for line in replay(RECORDED_STREAM):
            events.extend(backend.ingest_line(line))
        kinds = [(event["kind"], event.get("window_id")) for event in events]
        self.assertEqual(
            kinds,
            [
                ("opened", 1),
                ("opened", 2),
                ("opened", 3),
                ("focus", 3),
                ("changed", 1),
                ("opened", 4),
                ("closed", 2),
                ("focus", None),
            ],
        )
        by_id = {
            event["window_id"]: event for event in events if event.get("window_id")
        }
        self.assertEqual(by_id[3]["app_id"], "mpv")
        self.assertEqual(by_id[3]["pid"], 5000)
        self.assertTrue(by_id[3]["focus"])
        self.assertIsNone(by_id[4]["pid"])

    def test_backend_state_tracks_focus(self):
        backend = windows.NiriBackend(socket_path="/nonexistent")
        for line in replay(RECORDED_STREAM):
            backend.ingest_line(line)
        self.assertEqual(
            {id: w["focused"] for id, w in backend.windows.items()},
            {1: False, 3: False, 4: False},
        )
        self.assertIsNone(backend.focused_id())

    def test_replacement_drops_missing_windows(self):
        backend = windows.NiriBackend(socket_path="/nonexistent")
        backend.ingest_line(json.dumps({"WindowsChanged": {"windows": [window(1)]}}))
        events = backend.ingest_line(
            json.dumps({"WindowsChanged": {"windows": [window(2)]}})
        )
        self.assertEqual(
            sorted((event["kind"], event["window_id"]) for event in events),
            [("closed", 1), ("opened", 2)],
        )

    def test_titles_follow_store_titles(self):
        backend = windows.NiriBackend(socket_path="/nonexistent", store_titles=True)
        events = backend.ingest_line(
            json.dumps({"WindowOpenedOrChanged": {"window": window(9)}})
        )
        self.assertEqual(events[0]["title"], "t")
        self.assertEqual(backend.windows[9]["title"], "t")
        backend.store_titles = False
        events = backend.ingest_line(
            json.dumps({"WindowOpenedOrChanged": {"window": window(10)}})
        )
        self.assertNotIn("title", events[0])


class SnapshotTest(unittest.TestCase):
    def test_snapshot_parses_ok_reply(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall(
                (
                    json.dumps({"Ok": {"Windows": [window(1), window(2)]}}) + "\n"
                ).encode()
            )
            server.shutdown(socket.SHUT_WR)
            backend = windows.NiriBackend(socket_path="/nonexistent")
            found = backend.snapshot(connect=lambda: client)
        self.assertEqual([w["id"] for w in found], [1, 2])
        self.assertEqual(sorted(backend.windows), [1, 2])

    def test_snapshot_accepts_bare_arrays(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall((json.dumps([window(1)]) + "\n").encode())
            server.shutdown(socket.SHUT_WR)
            backend = windows.NiriBackend(socket_path="/nonexistent")
            found = backend.snapshot(connect=lambda: client)
        self.assertEqual([w["id"] for w in found], [1])

    def test_snapshot_error_replies_raise(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall((json.dumps({"Err": "nope"}) + "\n").encode())
            server.shutdown(socket.SHUT_WR)
            backend = windows.NiriBackend(socket_path="/nonexistent")
            with self.assertRaises(windows.WindowError):
                backend.snapshot(connect=lambda: client)

    def test_missing_socket_path_raises(self):
        backend = windows.NiriBackend(socket_path=None)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIRI_SOCKET", None)
            with self.assertRaises(windows.WindowError):
                backend.snapshot()


def make_daemon(**overrides):
    from taema.daemon import service
    from tests.test_phase0 import make_cfg, tmp

    cfg = make_cfg(tmp(), mode="auto")
    cfg.update(overrides)
    return service.Daemon(cfg)


def register(daemon, session="s1"):
    return daemon.handle(
        {
            "cmd": "register_agent",
            "session": session,
            "pid": os.getpid(),
            "capabilities": ["heartbeat", "windows"],
            "compositor": "/run/user/1000/wayland-0",
        }
    )


class WindowEventTest(unittest.TestCase):
    def _event(self, daemon, kind, window_id=1, **fields):
        message = {
            "cmd": "window_event",
            "session": "s1",
            "pid": os.getpid(),
            "kind": kind,
            "window_id": window_id,
        }
        message.update(fields)
        return daemon.handle(message)

    def test_unknown_session_refused(self):
        daemon = make_daemon()
        reply = daemon.handle(
            {
                "cmd": "window_event",
                "session": "nope",
                "pid": 424242,
                "kind": "focus",
                "window_id": 1,
            }
        )
        self.assertIn("error", reply)

    def test_bad_kinds_and_types_refused(self):
        daemon = make_daemon()
        register(daemon)
        self.assertIn("error", self._event(daemon, "bogus"))
        self.assertIn("error", self._event(daemon, "opened", window_id="x"))
        self.assertIn("error", self._event(daemon, "opened", window_pid=-5))

    def test_opened_closed_focus_roundtrip(self):
        daemon = make_daemon()
        register(daemon)
        reply = self._event(
            daemon, "opened", app_id="firefox", window_pid=os.getpid(), focus=True
        )
        self.assertTrue(reply.get("ok"))
        state = daemon.window_state["s1"]
        self.assertEqual(state["windows"][1]["app_id"], "firefox")
        self.assertEqual(state["windows"][1]["pid"], os.getpid())
        self.assertEqual(state["focused"], 1)
        self._event(daemon, "closed")
        self.assertNotIn(1, daemon.window_state["s1"]["windows"])

    def test_snapshot_replaces(self):
        daemon = make_daemon()
        register(daemon)
        self._event(daemon, "opened", window_id=1, app_id="old")
        reply = daemon.handle(
            {
                "cmd": "window_event",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "snapshot",
                "windows": [{"window_id": 9, "app_id": "new", "focus": True}],
            }
        )
        self.assertTrue(reply.get("ok"))
        state = daemon.window_state["s1"]
        self.assertEqual(sorted(state["windows"]), [9])
        self.assertEqual(state["focused"], 9)

    def test_rate_limit_drops_excess(self):
        daemon = make_daemon()
        register(daemon)
        replies = [
            self._event(daemon, "opened", window_id=id, app_id="a%d" % id)
            for id in range(1, 52)
        ]
        self.assertTrue(all(reply.get("ok") for reply in replies))
        self.assertTrue(replies[-1].get("dropped"))
        self.assertEqual(len(daemon.window_state["s1"]["windows"]), 50)

    def test_forged_pid_is_unmapped(self):
        from taema.core import process as inspect_mod

        daemon = make_daemon()
        register(daemon)

        def uid_of(pid):
            return os.getuid() if pid == os.getpid() else 424242

        with mock.patch.object(inspect_mod, "uid_of", side_effect=uid_of):
            reply = self._event(daemon, "opened", window_pid=999999)
        self.assertTrue(reply.get("ok"))
        self.assertIsNone(daemon.window_state["s1"]["windows"][1]["pid"])

    def test_titles_dropped_unless_configured(self):
        daemon = make_daemon()
        register(daemon)
        self._event(daemon, "opened", app_id="x", title="secret")
        self.assertNotIn("title", daemon.window_state["s1"]["windows"][1])

        daemon2 = make_daemon(agent={"store_titles": True})
        register(daemon2)
        daemon2.handle(
            {
                "cmd": "window_event",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "opened",
                "window_id": 1,
                "app_id": "x",
                "title": "kept",
            }
        )
        self.assertEqual(daemon2.window_state["s1"]["windows"][1]["title"], "kept")

    def test_status_reports_window_summary(self):
        daemon = make_daemon()
        register(daemon)
        self._event(
            daemon, "opened", app_id="firefox", window_pid=os.getpid(), focus=True
        )
        summary = daemon.handle({"cmd": "status"})["windows"]
        self.assertTrue(summary["connected"])
        self.assertIn("pids", summary)
        self.assertIn(str(os.getpid()), summary["pids"])


class WindowMappingTest(unittest.TestCase):
    def _daemon_with_proc(self, pid, cgroup_line):
        from tests.test_phase0 import FakeCg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        proc_root = os.path.join(cg.root, "proc")
        pid_dir = os.path.join(proc_root, str(pid))
        os.makedirs(pid_dir)
        with open(os.path.join(pid_dir, "cgroup"), "w") as handle:
            handle.write("0::%s\n" % cgroup_line)
        daemon = make_daemon()
        return cg, daemon, proc_root

    def test_pid_maps_to_scope_under_base(self):
        from taema.core import cgroup

        cg, daemon, proc_root = self._daemon_with_proc(
            4242, "%s/app-x" % cgroup.base()[len(cgroup.CG) :]
        )
        with mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}):
            self.assertEqual(daemon._window_scope(4242), "app-x")

    def test_pid_outside_base_is_unmapped(self):
        cg, daemon, proc_root = self._daemon_with_proc(4242, "/init.scope")
        with mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}):
            self.assertIsNone(daemon._window_scope(4242))

    def test_dead_pid_is_unmapped(self):
        cg, daemon, proc_root = self._daemon_with_proc(4242, "/user/0/app-x")
        with mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}):
            self.assertIsNone(daemon._window_scope(999999))


class WindowInstanceTest(unittest.TestCase):
    def _seed_app(self, daemon, key="firefox"):
        from types import SimpleNamespace

        daemon.store.db.record_app_identity(
            SimpleNamespace(
                key=key,
                display=key,
                exe="/usr/bin/" + key,
                kind="comm",
                desktop_id=None,
                unit=None,
                validated=False,
                device=None,
                inode=None,
            ),
            {"pid": os.getpid(), "start": 1, "born": 1.0},
            now=1000.0,
        )

    def test_app_id_becomes_desktop_id_and_display(self):
        from taema.config import policy

        daemon = make_daemon()
        register(daemon)
        self._seed_app(daemon, policy.app_key(os.getpid()))
        daemon.handle(
            {
                "cmd": "window_event",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "opened",
                "window_id": 1,
                "app_id": "org.mozilla.firefox",
                "window_pid": os.getpid(),
            }
        )
        key = policy.app_key(os.getpid())
        row = daemon.store.db.app_identity(key)
        self.assertIsNotNone(row)
        self.assertEqual(row["desktop_id"], "org.mozilla.firefox")
        self.assertEqual(row["display"], "org.mozilla.firefox")

    def test_unchanged_values_skip_the_write(self):
        daemon = make_daemon()
        register(daemon)
        from taema.config import policy

        key = policy.app_key(os.getpid())
        self._seed_app(daemon, key)
        daemon.store.db.set_app_desktop(
            key, "org.mozilla.firefox", "org.mozilla.firefox", now=1000.0
        )
        before = daemon.store.db.app_identity(key)["last_seen"]
        daemon.handle(
            {
                "cmd": "window_event",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "opened",
                "window_id": 1,
                "app_id": "org.mozilla.firefox",
                "window_pid": os.getpid(),
            }
        )
        self.assertEqual(daemon.store.db.app_identity(key)["last_seen"], before)

    def test_missing_app_id_changes_nothing(self):
        daemon = make_daemon()
        register(daemon)
        from taema.config import policy

        key = policy.app_key(os.getpid())
        self._seed_app(daemon, key)
        daemon.handle(
            {
                "cmd": "window_event",
                "session": "s1",
                "pid": os.getpid(),
                "kind": "opened",
                "window_id": 1,
                "window_pid": os.getpid(),
            }
        )
        self.assertIsNone(daemon.store.db.app_identity(key)["desktop_id"])


class WindowClassTest(unittest.TestCase):
    def _windowed_daemon(self):
        from taema.core import cgroup
        from taema.core import process as inspect_mod
        from tests.test_phase0 import FakeCg, make_cfg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        leaf = cg.leaf("app-x", [4242], cpu=0)
        with open(os.path.join(leaf, "cgroup.freeze"), "w") as handle:
            handle.write("0\n")
        proc_root = os.path.join(cg.root, "proc")
        os.makedirs(os.path.join(proc_root, "4242"))
        with open(os.path.join(proc_root, "4242", "cgroup"), "w") as handle:
            handle.write("0::%s/app-x\n" % cgroup.base()[len(cgroup.CG) :])
        cfg = make_cfg(
            os.path.join(cg.root, "state"),
            mode="enforce",
            freeze={
                "enabled": True,
                "adopt": False,
                "after": 120,
                "wake_on_connect": False,
                "max_frozen": 32,
                "cpu_idle_max": 100.0,
            },
            experimental={"freeze": True},
        )
        from taema.daemon import service

        daemon = service.Daemon(cfg)
        register(daemon)
        return daemon, proc_root, inspect_mod

    def _open_window(self, daemon, proc_root, inspect_mod, focus=False):
        with (
            mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}),
            mock.patch.object(inspect_mod, "uid_of", return_value=os.getuid()),
            mock.patch.object(inspect_mod, "starttime", return_value=777),
        ):
            daemon.handle(
                {
                    "cmd": "window_event",
                    "session": "s1",
                    "pid": os.getpid(),
                    "kind": "opened",
                    "window_id": 1,
                    "app_id": "firefox",
                    "window_pid": 4242,
                    "focus": focus,
                }
            )

    def test_freeze_refused_with_open_window(self):
        from taema.core import process as inspect_mod

        daemon, proc_root, _inspect = self._windowed_daemon()
        self._open_window(daemon, proc_root, inspect_mod)
        with (
            mock.patch.object(daemon, "_wait_for_cgroup_frozen", return_value=True),
            mock.patch.object(daemon, "_freeze_safety_facts", return_value=(None, [])),
            mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}),
            mock.patch.object(inspect_mod, "starttime", return_value=777),
        ):
            result = daemon.freeze_scope("app-x")
        self.assertFalse(result.get("ok"))
        self.assertIn("window", result.get("error", ""))

    def test_window_qos_classes(self):
        from taema.core import process as inspect_mod

        daemon, proc_root, _inspect = self._windowed_daemon()
        with (
            mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}),
            mock.patch.object(inspect_mod, "starttime", return_value=777),
        ):
            self.assertIsNone(daemon._window_qos_class("app-x"))
            self._open_window(daemon, proc_root, inspect_mod)
            self.assertEqual(daemon._window_qos_class("app-x"), "interactive")
            daemon.handle(
                {
                    "cmd": "window_event",
                    "session": "s1",
                    "pid": os.getpid(),
                    "kind": "focus",
                    "window_id": 1,
                    "focus": True,
                }
            )
            self.assertEqual(daemon._window_qos_class("app-x"), "foreground")

    def test_focus_boost_only_in_focus_profile(self):
        daemon = make_daemon()
        self.assertFalse(daemon._focus_boost_on())
        daemon.cfg["_profile_name"] = "focus"
        daemon.cfg["qos"] = {"focus_boost": True, "focus_cpu_weight": 300}
        self.assertTrue(daemon._focus_boost_on())
        daemon.cfg["qos"] = {"focus_boost": False, "focus_cpu_weight": 300}
        self.assertFalse(daemon._focus_boost_on())

    def test_foreground_plan_boosts_cpu(self):
        from taema.core import qos
        from tests.test_phase0 import FakeCg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        leaf = cg.leaf("app-x", [], cpu=0)
        with open(os.path.join(leaf, "cpu.weight"), "w") as handle:
            handle.write("100\n")
        plan = qos.plan(leaf, "foreground", focus_weight=300)
        writes = {item.name: item.value for item in plan.writes}
        self.assertEqual(writes.get("cpu.weight"), "300")

    def test_anonymous_reclaim_skips_focused_scopes(self):
        from taema.core import process as inspect_mod

        daemon, proc_root, _inspect = self._windowed_daemon()
        self._open_window(daemon, proc_root, inspect_mod, focus=False)
        # Frozen after opening: focus events thaw at once (see FocusThawTest),
        # so mark focus directly to test the reclaim skip in isolation.
        daemon.store.data["frozen_scopes"] = {"app-x": {"decision_id": 1}}
        daemon.window_state["s1"]["focused"] = 1
        daemon.window_state["s1"]["windows"][1]["focus"] = True
        from taema.core import memory

        with (
            mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}),
            mock.patch.object(inspect_mod, "starttime", return_value=777),
            mock.patch.object(inspect_mod, "uid_of", return_value=os.getuid()),
            mock.patch.object(
                daemon, "_memory_paths", return_value={"app-x": "/fake/app-x"}
            ),
            mock.patch.object(daemon, "_freeze_value", return_value="1"),
            mock.patch.object(
                memory,
                "scope_counters",
                return_value={
                    "current_bytes": 100,
                    "file_bytes": 10,
                    "anon_bytes": 90,
                    "reclaimable_bytes": 10,
                },
            ),
        ):
            skipped = daemon._guard_reclaim_step("anonymous")
            self.assertEqual(skipped["results"], [])
            self.assertEqual(skipped["scopes"], [])
            daemon.window_state["s1"]["focused"] = None
            for known in daemon.window_state["s1"]["windows"].values():
                known["focus"] = False
            reclaimed = []
            with (
                mock.patch.object(daemon, "_guard_pressure_high", return_value=True),
                mock.patch.object(
                    daemon,
                    "_reclaim_one",
                    side_effect=lambda *a, **k: (
                        reclaimed.append(a[0]) or {"anonymous_reclaimed_bytes": 5}
                    ),
                ),
            ):
                results = daemon._guard_reclaim_step("anonymous")
            self.assertEqual(reclaimed, ["app-x"])
            self.assertEqual(len(results["results"]), 1)


class FakeWindowBackend(windows.NiriBackend):
    """Real parsing, scripted transport."""

    def __init__(self, lines=(), snapshot_windows=(), store_titles=False):
        super().__init__(socket_path="/fake/niri.sock", store_titles=store_titles)
        self._lines = list(lines)
        self._snapshot_windows = list(snapshot_windows)
        self.snapshots = 0

    def snapshot(self, connect=None):
        self.snapshots += 1
        self.windows = {}
        found = []
        for raw in self._snapshot_windows:
            parsed = windows.normalize_window(raw, self.store_titles)
            if parsed is not None:
                self.windows[parsed["id"]] = parsed
                found.append(parsed)
        return found

    def open_stream(self, connect=None):
        import io
        import socket as socket_mod

        lines = [self._lines.pop(0) for _ in range(len(self._lines))]

        class TimeoutReader(io.StringIO):
            def readline(self, *args):
                line = super().readline(*args)
                if line == "":
                    raise socket_mod.timeout("timed out")
                return line

        return TimeoutReader("".join(lines))


def niri_line(message):
    import json

    return json.dumps(message) + "\n"


class AgentWindowTest(unittest.TestCase):
    def _agent(self, window_backend):
        from taema import agent as agent_mod
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp(), mode="auto")
        return agent_mod.Agent(cfg, "s1", backend=None, window_backend=window_backend)

    def test_backend_selected_from_socket(self):
        from taema import agent as agent_mod
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp(), mode="auto")
        with mock.patch.dict(os.environ, {"NIRI_SOCKET": "/fake/niri.sock"}):
            agent = agent_mod.Agent(cfg, "s1")
        self.assertIsInstance(agent.window_backend, windows.NiriBackend)
        self.assertIn("windows", agent.capabilities)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIRI_SOCKET", None)
            agent = agent_mod.Agent(cfg, "s1")
        self.assertIsNone(agent.window_backend)
        self.assertNotIn("windows", agent.capabilities)

    def test_drain_forwards_events_with_time(self):
        lines = [
            niri_line(
                {
                    "WindowOpenedOrChanged": {
                        "window": {
                            "id": 1,
                            "title": "t",
                            "app_id": "firefox",
                            "pid": 4242,
                            "workspace_id": 1,
                            "is_focused": True,
                            "is_floating": False,
                            "is_urgent": False,
                            "layout": {},
                            "focus_timestamp": None,
                        }
                    }
                }
            ),
            niri_line({"WindowClosed": {"id": 1}}),
        ]
        agent = self._agent(FakeWindowBackend(lines=lines))
        seen = []
        with mock.patch.object(agent, "_ask", side_effect=lambda m: seen.append(m)):
            agent.drain_windows()
        kinds = [m["cmd"] for m in seen]
        self.assertIn("window_event", kinds)
        events = [m for m in seen if m["cmd"] == "window_event"]
        self.assertEqual([e["kind"] for e in events], ["snapshot", "opened", "closed"])
        self.assertTrue(all(isinstance(e["time"], int) for e in events))
        self.assertNotIn("title", events[1])

    def test_forwarding_is_capped_at_50_per_drain(self):
        lines = [niri_line({"WindowClosed": {"id": id}}) for id in range(1, 61)]
        agent = self._agent(FakeWindowBackend(lines=lines))
        seen = []
        with mock.patch.object(agent, "_ask", side_effect=lambda m: seen.append(m)):
            agent.drain_windows()
            first = [m for m in seen if m["cmd"] == "window_event"]
            agent.drain_windows()
            second = [m for m in seen if m["cmd"] == "window_event"][len(first) :]
        # Snapshot plus 50 events, then the remaining 10.
        self.assertEqual(len(first), 51)
        self.assertEqual(len(second), 10)

    def test_titles_forwarded_when_configured(self):
        from taema import agent as agent_mod
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp(), mode="auto", agent={"store_titles": True})
        lines = [
            niri_line(
                {
                    "WindowOpenedOrChanged": {
                        "window": {
                            "id": 1,
                            "title": "kept",
                            "app_id": "x",
                            "pid": None,
                            "workspace_id": 1,
                            "is_focused": False,
                            "is_floating": False,
                            "is_urgent": False,
                            "layout": {},
                            "focus_timestamp": None,
                        }
                    }
                }
            ),
        ]
        backend = FakeWindowBackend(lines=lines, store_titles=True)
        agent = agent_mod.Agent(cfg, "s1", backend=None, window_backend=backend)
        seen = []
        with mock.patch.object(agent, "_ask", side_effect=lambda m: seen.append(m)):
            agent.drain_windows()
        opened = [m for m in seen if m.get("kind") == "opened"][0]
        self.assertEqual(opened["title"], "kept")

    def test_stream_errors_reconnect_next_tick(self):
        class Failing(FakeWindowBackend):
            def open_stream(self, connect=None):
                raise windows.WindowError("gone")

        agent = self._agent(Failing())
        seen = []
        with mock.patch.object(agent, "_ask", side_effect=lambda m: seen.append(m)):
            agent.drain_windows()
        self.assertEqual(seen, [])

    def test_connected_ticks_drain_windows(self):
        from tests.test_phase0 import tmp

        agent = self._agent(FakeWindowBackend())
        live = os.path.join(tmp(), "wayland-9")
        open(live, "w").close()
        agent.compositor = live
        ticks = []
        clock = iter([0.0, 0.0, 31.0, 31.0])
        with (
            mock.patch.object(
                agent, "poll_once", side_effect=lambda: ticks.append("poll")
            ),
            mock.patch.object(
                agent, "drain_windows", side_effect=lambda: ticks.append("drain")
            ),
        ):
            agent._sleep_connected(ticks.append, clock=lambda: next(clock))
        self.assertIn("drain", ticks)
        self.assertIn("poll", ticks)


class WindowColumnsTest(unittest.TestCase):
    def _args(self, width=100):
        args = mock.Mock()
        args._width = width
        args._color = False
        args.wide = False
        return args

    def test_ls_shows_windows_column(self):
        from taema.cli import view

        scopes = [
            {
                "depth": 0,
                "name": "app-a",
                "processes": 2,
                "memory_bytes": 8,
                "psi_avg10": 0.0,
                "memory": None,
                "commands": ["a"],
                "deprioritized": False,
                "frozen": False,
                "windows": {"count": 2, "focused": False},
            },
            {
                "depth": 0,
                "name": "app-b",
                "processes": 1,
                "memory_bytes": 8,
                "psi_avg10": 0.0,
                "memory": None,
                "commands": ["b"],
                "deprioritized": False,
                "frozen": False,
                "windows": {"count": 1, "focused": True},
            },
            {
                "depth": 0,
                "name": "app-c",
                "processes": 1,
                "memory_bytes": 8,
                "psi_avg10": 0.0,
                "memory": None,
                "commands": ["c"],
                "deprioritized": False,
                "frozen": False,
                "windows": None,
            },
        ]
        text = view.render_scopes(scopes, self._args())
        header, row_a, row_b, row_c = text.splitlines()
        self.assertIn(" W ", " " + header + " ")
        # W column sits after name(28) procs(4) MEM(8) PSI(6) plus gaps.
        w_at = 28 + 1 + 4 + 2 + 8 + 1 + 6 + 1
        self.assertEqual(row_a[w_at : w_at + 2].strip(), "2")
        self.assertEqual(row_b[w_at : w_at + 2].strip(), "F")
        self.assertEqual(row_c[w_at : w_at + 2], "  ")

    def test_top_shows_window_marker(self):
        from taema.cli import view

        model = [
            {
                "pid": 7,
                "scope": "app-a",
                "user": "u",
                "cpu": 1.0,
                "mem_pct": 0.5,
                "mem": 8,
                "threads": 1,
                "state": "S",
                "cmd": "a",
                "window": "F",
            },
            {
                "pid": 8,
                "scope": "app-b",
                "user": "u",
                "cpu": 0.0,
                "mem_pct": 0.1,
                "mem": 8,
                "threads": 1,
                "state": "S",
                "cmd": "b",
                "window": "",
            },
        ]
        text = view.render_top(model, self._args())
        header, first, second = text.splitlines()
        self.assertIn(" W ", " " + header + " ")
        self.assertIn(" F ", " " + first + " ")
        self.assertNotIn(" F ", " " + second + " ")

    def test_tree_marks_windowed_nodes(self):
        from taema.cli import view

        model = [
            (
                "app-a",
                [
                    {"pid": 7, "depth": 0, "state": "S", "zombies": 0, "window": "F"},
                    {"pid": 8, "depth": 1, "state": "S", "zombies": 0, "window": "w"},
                    {"pid": 9, "depth": 1, "state": "S", "zombies": 0, "window": ""},
                ],
            ),
        ]
        text = view.render_tree(model, self._args())
        self.assertIn("\u25c9", text)
        self.assertIn("\u25cf", text)
        marked = [
            line for line in text.splitlines() if "\u25c9" in line or "\u25cf" in line
        ]
        self.assertEqual(len(marked), 2)

    def test_dash_row_shows_windows(self):
        from taema.cli import dash
        from tests.test_dash import FakeScreen

        screen = FakeScreen([])
        state = {
            "model": {
                "scopes": [
                    {
                        "name": "app-a",
                        "processes": 1,
                        "memory_bytes": 8,
                        "frozen": False,
                        "windows": {"count": 2, "focused": True},
                    },
                    {
                        "name": "app-b",
                        "processes": 1,
                        "memory_bytes": 8,
                        "frozen": False,
                        "windows": None,
                    },
                ],
                "daemon": "up",
            },
            "selected": 0,
            "filter": "",
            "search": "",
            "message": "",
        }
        args = mock.Mock()
        dash._draw(screen, args, state, [])
        self.assertIn("win=F", screen.lines[1])
        self.assertNotIn("win=", screen.lines[2])

    def test_top_details_annotates_window_pids(self):
        from taema.cli import commands

        details = commands._top_details(
            [os.getpid()], windows={str(os.getpid()): {"focused": True}}
        )
        self.assertEqual(details[os.getpid()]["window"], "F")
        details = commands._top_details(
            [os.getpid()], windows={str(os.getpid()): {"focused": False}}
        )
        self.assertEqual(details[os.getpid()]["window"], "w")
        details = commands._top_details([os.getpid()], windows={})
        self.assertEqual(details[os.getpid()]["window"], "")

    def test_ls_rows_annotate_from_daemon(self):
        from taema.cli import commands
        from taema.store.knowledge import Store
        from tests.test_phase0 import FakeCg, make_cfg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        cg.leaf("app-a", [], cpu=0)
        cfg = make_cfg(os.path.join(cg.root, "state"), mode="auto")
        store = Store(os.path.join(cg.root, "state"), {}, lambda: 0.0)
        with mock.patch.object(
            commands,
            "ask",
            return_value={
                "windows": {"scopes": {"app-a": {"count": 3, "focused": True}}}
            },
        ):
            rows, _memory = commands._ls_rows(cfg, store)
        row = next(row for row in rows if row["name"] == "app-a")
        self.assertEqual(row["windows"], {"count": 3, "focused": True})

    def test_ls_rows_without_daemon_have_no_markers(self):
        from taema.cli import commands
        from taema.store.knowledge import Store
        from tests.test_phase0 import FakeCg, make_cfg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        cg.leaf("app-a", [], cpu=0)
        cfg = make_cfg(os.path.join(cg.root, "state"), mode="auto")
        store = Store(os.path.join(cg.root, "state"), {}, lambda: 0.0)
        with mock.patch.object(commands, "ask", return_value=None):
            rows, _memory = commands._ls_rows(cfg, store)
        row = next(row for row in rows if row["name"] == "app-a")
        self.assertIsNone(row["windows"])


class FocusThawTest(unittest.TestCase):
    def test_focus_thaws_a_frozen_scope(self):
        from taema.core import cgroup
        from tests.test_phase0 import FakeCg

        cg = FakeCg().__enter__()
        self.addCleanup(cg.__exit__)
        leaf = cg.leaf("app-x", [4242], cpu=0)
        with open(os.path.join(leaf, "cgroup.freeze"), "w") as handle:
            handle.write("1\n")
        proc_root = os.path.join(cg.root, "proc")
        os.makedirs(os.path.join(proc_root, "4242"))
        with open(os.path.join(proc_root, "4242", "cgroup"), "w") as handle:
            handle.write("0::%s/app-x\n" % cgroup.base()[len(cgroup.CG) :])
        daemon = make_daemon()
        daemon.store.data["frozen_scopes"] = {"app-x": {"decision_id": 1}}
        register(daemon)
        from taema.core import process as inspect_mod

        with (
            mock.patch.dict(os.environ, {"TAEMA_PROCROOT": proc_root}),
            mock.patch.object(inspect_mod, "uid_of", return_value=os.getuid()),
            mock.patch.object(inspect_mod, "starttime", return_value=777),
        ):
            reply = daemon.handle(
                {
                    "cmd": "window_event",
                    "session": "s1",
                    "pid": os.getpid(),
                    "kind": "focus",
                    "window_id": 5,
                    "app_id": "firefox",
                    "window_pid": 4242,
                    "focus": True,
                }
            )
        self.assertTrue(reply.get("ok"))
        with open(os.path.join(leaf, "cgroup.freeze")) as handle:
            self.assertEqual(handle.read().strip(), "0")
        self.assertNotIn("app-x", daemon.store.data.get("frozen_scopes", {}))


if __name__ == "__main__":
    unittest.main()
