"""Dashboard snapshot, rendering, fallback, keys, and action parity."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

import taema.cli.commands as cli
from taema.cli import dash, view
from taema.store import knowledge
from tests.test_phase0 import FakeCg, make_cfg, tmp


def dash_args(**options):
    args = SimpleNamespace(
        once=False,
        json=False,
        jsonl=False,
        plain=False,
        wide=False,
        quiet=False,
        yes=False,
        socket=None,
        config=None,
        _width=80,
    )
    for name, value in options.items():
        setattr(args, name, value)
    return args


def hand_model():
    return view.snapshot(
        "dash",
        scopes=[
            {"name": "scope-a", "procs": 2, "memory_bytes": 1024, "frozen": False},
        ],
        memory={"enabled": True, "host": {"total_bytes": 8192}},
    ) | {
        "learned": {
            "apps": [{"key": "firefox", "decision": "keep"}],
            "pairs": [{"owner": "cc1", "leftover": "sh", "decision": "stop"}],
            "signatures": [{"id": "sig1", "decision": "ask"}],
        },
        "budget": {"enabled": False},
        "events": [{"seq": 7, "event": "vetoed", "scope": "scope-a"}],
        "reviews": [{"id": 3, "owner": "cc1"}],
        "daemon": "ok",
    }


class DashSnapshotTests(unittest.TestCase):
    def test_sections(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-a")
        with FakeCg() as cg:
            cg.leaf("scope-a")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
            ):
                model = cli.dash_snapshot(dash_args())
        self.assertEqual(model["kind"], "dash")
        self.assertTrue(
            any(row.get("name", "").endswith("scope-a") for row in model["scopes"])
        )
        self.assertIn("pairs", model["learned"])
        self.assertIn("signatures", model["learned"])
        self.assertIn("apps", model["learned"])
        self.assertIn("memory", model)
        self.assertIn("events", model)
        self.assertIn("reviews", model)

    def test_offline_budget_is_none(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        with FakeCg():
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
            ):
                model = cli.dash_snapshot(dash_args())
        self.assertIsNone(model["budget"])
        self.assertEqual(model["daemon"], "unavailable")


class DashRenderTests(unittest.TestCase):
    def test_golden(self):
        self.assertEqual(
            view.render_dash(hand_model(), dash_args()),
            "scopes (1)\n"
            "  scope-a procs=2 mem=1.0K\n"
            "learned apps=1 pairs=1 signatures=1\n"
            "  pair cc1 -> sh stop\n"
            "  signature sig1 ask\n"
            "memory\n"
            "  host total 8.0K  budget disabled\n"
            "reviews (1)\n"
            "  #3 owner=cc1\n"
            "events\n"
            "  #7 vetoed scope-a\n",
        )

    def test_once_is_deterministic(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        store.log(event="vetoed", scope="scope-a")
        outs = []
        with FakeCg() as cg:
            cg.leaf("scope-a")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
            ):
                for _ in range(2):
                    out = io.StringIO()
                    with redirect_stdout(out):
                        self.assertEqual(cli.cmd_dash(dash_args(once=True)), 0)
                    outs.append(out.getvalue())
        self.assertEqual(outs[0], outs[1])
        self.assertIn("scopes", outs[0])


class DashJsonTests(unittest.TestCase):
    def test_json_snapshot(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        with FakeCg() as cg:
            cg.leaf("scope-a")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
            ):
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(cli.cmd_dash(dash_args(json=True)), 0)
        model = json.loads(out.getvalue())
        self.assertEqual(model["schema"], "taema.view.v1")
        self.assertEqual(model["kind"], "dash")
        for key in ("scopes", "learned", "memory", "events", "reviews"):
            self.assertIn(key, model)


class DashFallbackTests(unittest.TestCase):
    def test_no_curses_falls_back_to_watch_plain(self):
        seen = {}

        def fake_watch(args):
            seen["plain"] = args.plain
            return 0

        with mock.patch.object(cli, "cmd_watch", side_effect=fake_watch):
            self.assertEqual(dash.main(dash_args(), curses_module=None), 0)
        self.assertTrue(seen["plain"])


class DashKeysTests(unittest.TestCase):
    def test_core_keys(self):
        keys = dash.key_help()
        for key in ("j", "k", "enter", "s", "n", "u", "a", "f", "/", "?", "q"):
            self.assertIn(key, keys)

    def test_governor_keys_follow_registry(self):
        keys = dash.key_help()
        for key in ("R", "Z", "T", "P", "G"):
            self.assertIn(key, keys)
        names = {"R": "reclaim", "Z": "freeze", "T": "thaw", "P": "profile"}
        for key, command in names.items():
            self.assertIn(command, keys[key].lower())
        self.assertIn("gc", keys["G"].lower())


class DashActionTests(unittest.TestCase):
    def run_both(self, argv, store):
        cfg = make_cfg(store.dir, mode="auto")
        results = []
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(cli, "ask", return_value=None),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            results.append((cli.main(argv), out.getvalue(), err.getvalue()))
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
            mock.patch.object(cli, "ask", return_value=None),
        ):
            code, text = dash.run_action(argv, dash_args())
            results.append((code, text, ""))
        return results

    def test_kill_veto_refusal_matches_cli(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x")
        with FakeCg() as cg:
            cg.leaf("scope-x")
            via_cli, via_dash = self.run_both(["kill", "scope-x"], store)
        self.assertEqual(via_cli[0], 4)
        self.assertIn("veto", via_cli[2].lower())
        self.assertEqual(via_dash[0], via_cli[0])
        self.assertEqual(via_dash[1], via_cli[1] + via_cli[2])

    def test_stop_preview_shows_veto_edge_memory_facts(self):
        store = knowledge.Store(tmp(), {})
        store.add_veto("scope", "scope-x")
        cfg = make_cfg(store.dir, mode="auto")
        with FakeCg() as cg:
            cg.leaf("scope-x")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
            ):
                text = dash.stop_preview("scope-x", dash_args())
        lowered = text.lower()
        self.assertIn("veto", lowered)
        self.assertIn("edge", lowered)
        self.assertIn("memory", lowered)


class DashCursesTests(unittest.TestCase):
    def test_quit_smoke(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        screen = FakeScreen([ord("q")])
        with FakeCg() as cg:
            cg.leaf("scope-a")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
                mock.patch.object(dash, "EventPump", NullPump),
            ):
                dash.run_screen(screen, dash_args())
        rendered = "\n".join(screen.lines)
        self.assertIn("scope-a", rendered)

    def test_move_and_help(self):
        cfg = make_cfg(tmp(), mode="auto")
        store = knowledge.Store(tmp(), {})
        screen = FakeScreen([ord("j"), ord("k"), ord("?"), ord(" "), ord("q")])
        with FakeCg() as cg:
            cg.leaf("scope-a")
            with (
                mock.patch.object(cli, "_load", return_value=(cfg, store, [])),
                mock.patch.object(cli, "ask", return_value=None),
                mock.patch.object(dash, "EventPump", NullPump),
            ):
                dash.run_screen(screen, dash_args())
        self.assertIn("q: quit", screen.seen)
        self.assertIn("s: stop selection", "\n".join(screen.seen))


class FakeScreen:
    def __init__(self, keys):
        self.keys = list(keys)
        self.lines = []
        self.seen = []
        self.height = 24
        self.width = 80

    def getmaxyx(self):
        return (self.height, self.width)

    def timeout(self, _ms):
        return None

    def getch(self):
        return self.keys.pop(0) if self.keys else ord("q")

    def erase(self):
        self.lines = []

    def addstr(self, row, _col, text, *_attrs):
        while len(self.lines) <= row:
            self.lines.append("")
        self.lines[row] = text[: self.width]
        self.seen.append(text[: self.width])

    def refresh(self):
        return None


class NullPump:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None

    def drain(self):
        return []

    def stop(self):
        return None


if __name__ == "__main__":
    unittest.main()
