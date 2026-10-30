"""Status bar feed tests (issue #64).

`taema bar` renders one line per state change from subscriptions in
waybar, i3bar, json, or plain formats; the quickshell widget consumes
the json stream.
"""

import json
import os
import unittest
from unittest import mock


def sample_status(**over):
    status = {
        "mode": "auto",
        "profile": "default",
        "reviews": 2,
        "hold": "",
        "hold_state": {"global": False},
        "frozen_scopes": [{"scope": "app-x"}],
        "deprioritized": 3,
        "freed_today_bytes": 9979123456,
        "guard": {"active": False},
        "agents": {"sessions": []},
    }
    status.update(over)
    return status


class BarStatusTest(unittest.TestCase):
    def test_status_reports_deprioritized_and_freed_today(self):
        from tests.test_windows import make_daemon

        daemon = make_daemon()
        daemon.store.data["qos_scopes"] = {
            "scope-a": {"deprioritized": True},
            "scope-b": {"deprioritized": False},
        }
        daemon.store.log(event="freed", scope="scope-a", freed_bytes=1024)
        reply = daemon.handle({"cmd": "status"})
        self.assertEqual(reply["deprioritized"], 1)
        self.assertGreaterEqual(reply["freed_today_bytes"], 1024)


class BarModelTest(unittest.TestCase):
    def test_model_derives_counts_and_class(self):
        from taema import bar

        model = bar.model_from_status(sample_status())
        self.assertEqual(
            (model["reviews"], model["frozen"], model["deprioritized"]),
            (2, 1, 3),
        )
        self.assertEqual(model["class"], "review")
        self.assertEqual(model["mode"], "auto")
        self.assertFalse(model["hold"])
        self.assertFalse(model["pressure"])

    def test_class_priority(self):
        from taema import bar

        self.assertEqual(bar.model_from_status(sample_status())["class"], "review")
        self.assertEqual(bar.model_from_status(sample_status(reviews=0))["class"], "ok")
        self.assertEqual(
            bar.model_from_status(sample_status(guard={"active": True}))["class"],
            "pressure",
        )
        self.assertEqual(
            bar.model_from_status(sample_status(hold="user"))["class"], "hold"
        )
        self.assertEqual(
            bar.model_from_status(sample_status(hold="user", reviews=0))["class"],
            "hold",
        )
        self.assertEqual(bar.error_model()["class"], "error")

    def test_text_format(self):
        from taema import bar

        self.assertEqual(
            bar.render_text(bar.model_from_status(sample_status())),
            "tæma ⟲2 ❄1 ↓3 9.3G",
        )
        quiet = bar.model_from_status(
            sample_status(reviews=0, frozen_scopes=[], deprioritized=0)
        )
        self.assertEqual(bar.render_text(quiet), "tæma 9.3G")

    def test_tooltip_carries_mode_profile_and_state(self):
        from taema import bar

        tooltip = bar.render_tooltip(bar.model_from_status(sample_status()))
        for needle in ("auto", "default", "2", "frozen", "9.3"):
            self.assertIn(needle, tooltip)


class BarFormatTest(unittest.TestCase):
    def test_waybar_format(self):
        from taema import bar

        line = bar.render("waybar", bar.model_from_status(sample_status()))
        payload = json.loads(line)
        self.assertEqual(payload["text"], "tæma ⟲2 ❄1 ↓3 9.3G")
        self.assertEqual(payload["class"], "review")
        self.assertIn("auto", payload["tooltip"])

    def test_i3bar_format(self):
        from taema import bar

        line = bar.render("i3bar", bar.model_from_status(sample_status()))
        payload = json.loads(line)
        self.assertEqual(payload["full_text"], "tæma ⟲2 ❄1 ↓3 9.3G")
        self.assertEqual(payload["short_text"], "tæma ⟲2")
        self.assertIn("color", payload)

    def test_json_format_carries_widget_fields(self):
        from taema import bar

        line = bar.render("json", bar.model_from_status(sample_status()))
        payload = json.loads(line)
        for field in (
            "mode",
            "profile",
            "reviews",
            "frozen",
            "freed_today_bytes",
            "pressure",
            "hold",
            "class",
            "text",
            "tooltip",
        ):
            self.assertIn(field, payload)

    def test_plain_format(self):
        from taema import bar

        line = bar.render("plain", bar.model_from_status(sample_status()))
        self.assertEqual(line, "tæma ⟲2 ❄1 ↓3 9.3G")

    def test_unknown_format_raises(self):
        from taema import bar

        with self.assertRaises(ValueError):
            bar.render("wayb ar", bar.model_from_status(sample_status()))


class BarCommandTest(unittest.TestCase):
    def _args(self, **over):
        import types

        params = {"format": "plain", "follow": False}
        params.update(over)
        return types.SimpleNamespace(**params)

    def test_registry_names_bar(self):
        import taema.cli.commands as cli
        from taema.cli import registry

        entries = [entry for entry in registry.COMMANDS if entry["name"] == "bar"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["handler"], "cmd_bar")
        self.assertTrue(callable(getattr(cli, "cmd_bar", None)))

    def test_one_shot_prints_one_line(self):
        import io
        from contextlib import redirect_stdout

        import taema.cli.commands as cli
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp())
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
            mock.patch.object(cli, "ask", return_value=sample_status()),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_bar(self._args())
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "tæma ⟲2 ❄1 ↓3 9.3G\n")

    def test_daemon_down_prints_error(self):
        import io
        from contextlib import redirect_stdout

        import taema.cli.commands as cli
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp())
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
            mock.patch.object(cli, "ask", return_value=None),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_bar(self._args(format="waybar"))
        self.assertEqual(rc, 1)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["class"], "error")

    def test_follow_prints_only_changes(self):
        import io
        from contextlib import redirect_stdout

        import taema.cli.commands as cli
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp())
        first = sample_status()
        second = sample_status(reviews=3)
        replies = [first, second, second]
        stream = [
            {"subscribed": True},
            {"event": {"event": "review_created"}},
            {"event": {"event": "review_created"}},
        ]
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
            mock.patch.object(cli, "ask", side_effect=lambda _c, _m: replies.pop(0)),
            mock.patch.object(cli, "subscribe", return_value=iter(stream)),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_bar(self._args(follow=True))
        self.assertEqual(rc, 1)  # stream ended: daemon went away
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn("⟲2", lines[0])
        self.assertIn("⟲3", lines[1])
        self.assertIn("error", lines[2])

    def test_follow_stream_error_prints_error(self):
        import io
        from contextlib import redirect_stdout

        import taema.cli.commands as cli
        from tests.test_phase0 import make_cfg, tmp

        cfg = make_cfg(tmp())
        stream = [{"subscribed": True}, {"error": "boom", "code": "x"}]
        with (
            mock.patch.object(cli, "_load", return_value=(cfg, None, [])),
            mock.patch.object(cli, "ask", return_value=sample_status()),
            mock.patch.object(cli, "subscribe", return_value=iter(stream)),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.cmd_bar(self._args(follow=True))
        self.assertEqual(rc, 1)
        self.assertIn("error", out.getvalue().splitlines()[-1])


WIDGET_FIELDS = (
    "mode",
    "profile",
    "reviews",
    "frozen",
    "deprioritized",
    "freed_today_bytes",
    "hold",
    "pressure",
    "agent_running",
    "class",
    "text",
    "tooltip",
)


def widget_dir():
    from pathlib import Path

    return Path(__file__).resolve().parents[1] / "widgets" / "taema-bar"


class WidgetFeedContractTest(unittest.TestCase):
    def test_recorded_feed_matches_widget_contract(self):
        feed = widget_dir() / "feed.json"
        self.assertTrue(feed.is_file())
        lines = [line for line in feed.read_text().splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 2)
        for line in lines:
            payload = json.loads(line)
            for field in WIDGET_FIELDS:
                self.assertIn(field, payload)


class WidgetLoadTest(unittest.TestCase):
    @unittest.skipUnless(
        __import__("shutil").which("quickshell")
        and (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")),
        "quickshell and a display are needed",
    )
    def test_widget_loads_against_recorded_feed(self):
        import re
        import subprocess

        env = dict(os.environ)
        env["TAEMA_BAR_FEED"] = str(widget_dir() / "feed.json")
        env["QT_LOGGING_RULES"] = "qml.debug=true"
        proc = subprocess.run(
            ["quickshell", "-p", str(widget_dir())],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, output[-2000:])
        self.assertIn("TAEMA_WIDGET_OK", output)
        errors = [
            line
            for line in output.splitlines()
            if re.search(
                r"TypeError|ReferenceError|SyntaxError|is not a type|"
                r"Unable to assign|qml:.*[Ee]rror",
                line,
            )
        ]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
