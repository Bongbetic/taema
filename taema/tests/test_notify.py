"""Tests for the notification backends (issue #59).

notify-send, gdbus, and jeepney D-Bus backends behind one Notifier
contract, with `auto` selection and doctor reporting. D-Bus tests use a
fake connection, including forged signals.
"""

import io
import subprocess
import unittest

from taema import notify


class FakeCompleted:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class NotifySendBackendTest(unittest.TestCase):
    def test_builds_action_argv(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return FakeCompleted("7\n")

        backend = notify.NotifySendBackend(runner=runner)
        receipt = backend.send(
            "Review needed",
            "firefox leftovers",
            actions=[("stop", "Stop when it closes"), ("keep", "Keep")],
            app="taema",
            urgency="critical",
            expire_ms=30000,
        )
        self.assertEqual(receipt["id"], 7)
        self.assertEqual(
            seen[0],
            [
                "notify-send",
                "--app-name=taema",
                "--urgency=critical",
                "--expire-time=30000",
                "--action=stop=Stop when it closes",
                "--action=keep=Keep",
                "--print-id",
                "Review needed",
                "firefox leftovers",
            ],
        )

    def test_send_failure_raises(self):
        def runner(argv, **kwargs):
            return FakeCompleted("", returncode=1, stderr="no server")

        backend = notify.NotifySendBackend(runner=runner)
        with self.assertRaises(notify.NotifyError):
            backend.send("s", "b")

    def test_wait_reads_action_key(self):
        class FakeProc:
            def __init__(self, line):
                self.stdout = io.StringIO(line)
                self.argv = None

            def wait(self, timeout=None):
                return 0

        def popen(argv, **kwargs):
            proc = FakeProc("keep\n")
            proc.argv = argv
            return proc

        backend = notify.NotifySendBackend(popen=popen)
        receipt = backend.send("s", "b", actions=[("keep", "Keep")], wait=True)
        self.assertIn("--wait", receipt["argv"])
        self.assertEqual(
            backend.wait_for_action(receipt, timeout=5), ("action", "keep")
        )

    def test_wait_empty_output_means_closed(self):
        class FakeProc:
            def __init__(self):
                self.stdout = io.StringIO("")

            def wait(self, timeout=None):
                return 0

        backend = notify.NotifySendBackend(popen=lambda a, **k: FakeProc())
        receipt = backend.send("s", "b", actions=[("keep", "Keep")], wait=True)
        kind, _reason = backend.wait_for_action(receipt, timeout=5)
        self.assertEqual(kind, "closed")

    def test_wait_timeout(self):
        class FakeProc:
            def __init__(self):
                self.stdout = io.StringIO("")

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("notify-send", timeout)

        backend = notify.NotifySendBackend(popen=lambda a, **k: FakeProc())
        receipt = backend.send("s", "b", wait=True)
        self.assertEqual(backend.wait_for_action(receipt, timeout=1), ("timeout", None))

    def test_close_is_unsupported(self):
        backend = notify.NotifySendBackend(runner=lambda a, **k: FakeCompleted("1\n"))
        with self.assertRaises(notify.NotifyError):
            backend.close(1)
        self.assertEqual(backend.capabilities(), {"send", "actions"})

    def test_body_is_plain_by_default(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return FakeCompleted("1\n")

        backend = notify.NotifySendBackend(runner=runner)
        backend.send("a <b>", "x & y")
        self.assertIn("a &lt;b&gt;", seen[0])
        self.assertIn("x &amp; y", seen[0])

    def test_markup_passes_through_when_allowed(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return FakeCompleted("1\n")

        backend = notify.NotifySendBackend(runner=runner)
        backend.send("a <b>bold</b>", "plain", markup=True)
        self.assertIn("a <b>bold</b>", seen[0])


class GDBusBackendTest(unittest.TestCase):
    def test_builds_notify_call(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return FakeCompleted("(uint32 42,)")

        backend = notify.GDBusBackend(runner=runner)
        receipt = backend.send("Hi", "there <b>you</b>", app="taema", expire_ms=5000)
        self.assertEqual(receipt["id"], 42)
        self.assertEqual(
            seen[0][:7],
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
            ],
        )
        self.assertIn("org.freedesktop.Notifications.Notify", seen[0])
        # The negative default timeout must not parse as a flag.
        self.assertIn("--", seen[0])
        self.assertLess(seen[0].index("--"), seen[0].index("5000"))
        # GVariant double-quoted strings; markup escaped by default.
        self.assertIn('"Hi"', seen[0])
        self.assertIn('"there &lt;b&gt;you&lt;/b&gt;"', seen[0])

    def test_unparseable_reply_raises(self):
        backend = notify.GDBusBackend(
            runner=lambda a, **k: FakeCompleted("Error: nope\n")
        )
        with self.assertRaises(notify.NotifyError):
            backend.send("s", "b")

    def test_wait_is_unsupported(self):
        backend = notify.GDBusBackend(
            runner=lambda a, **k: FakeCompleted("(uint32 1,)")
        )
        with self.assertRaises(notify.NotifyError):
            backend.send("s", "b", wait=True)
        self.assertEqual(backend.capabilities(), {"send"})

    def test_query_capabilities_parses_gvariant(self):
        def runner(argv, **kwargs):
            return FakeCompleted("(['actions', 'body', 'body-markup'],)")

        self.assertEqual(
            notify.query_server_capabilities(runner=runner),
            ["actions", "body", "body-markup"],
        )

    def test_query_capabilities_failure_means_unknown(self):
        def runner(argv, **kwargs):
            raise OSError("no gdbus")

        self.assertEqual(notify.query_server_capabilities(runner=runner), [])


class FakeConnection:
    """Scripted stand-in for the jeepney D-Bus connection."""

    def __init__(self, owner=":1.5", script=(), capabilities=("actions", "body")):
        self._owner = owner
        self._script = list(script)
        self._capabilities = list(capabilities)
        self.sent = []
        self.closed = []
        self.close_calls = 0

    def call_notify(self, app, replaces, icon, summary, body, actions, hints, expire):
        self.sent.append((summary, body, list(actions)))
        return 99

    def call_close(self, nid):
        self.closed.append(nid)
        self.close_calls += 1

    def call_get_capabilities(self):
        return list(self._capabilities)

    def call_get_owner(self):
        return self._owner

    def wait_signal(self, members, timeout):
        if not self._script:
            return None
        return self._script.pop(0)

    def close(self):
        pass


class DBusNotifierTest(unittest.TestCase):
    def test_send_and_close(self):
        conn = FakeConnection()
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(receipt["id"], 99)
        backend.close(99)
        self.assertEqual(conn.closed, [99])

    def test_action_signal(self):
        conn = FakeConnection(script=[("ActionInvoked", ":1.5", (99, "stop"))])
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(
            backend.wait_for_action(receipt, timeout=5), ("action", "stop")
        )

    def test_forged_signal_is_ignored(self):
        conn = FakeConnection(
            script=[
                ("ActionInvoked", ":1.99", (99, "stop")),
                ("ActionInvoked", ":1.5", (99, "keep")),
            ]
        )
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(
            backend.wait_for_action(receipt, timeout=5), ("action", "keep")
        )

    def test_signal_for_other_notification_is_ignored(self):
        conn = FakeConnection(
            script=[
                ("ActionInvoked", ":1.5", (7, "stop")),
                ("NotificationClosed", ":1.5", (99, 2)),
            ]
        )
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(backend.wait_for_action(receipt, timeout=5), ("closed", 2))

    def test_close_signal(self):
        conn = FakeConnection(script=[("NotificationClosed", ":1.5", (99, 1))])
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(backend.wait_for_action(receipt, timeout=5), ("closed", 1))

    def test_timeout(self):
        conn = FakeConnection(script=[])
        backend = notify.DBusNotifier(connect=lambda: conn)
        receipt = backend.send("s", "b")
        self.assertEqual(backend.wait_for_action(receipt, timeout=1), ("timeout", None))

    def test_capabilities_come_from_the_bus(self):
        conn = FakeConnection(capabilities=("actions", "body-markup"))
        backend = notify.DBusNotifier(connect=lambda: conn)
        self.assertEqual(backend.capabilities(), {"send", "actions", "close"})
        self.assertEqual(backend.server_capabilities(), ["actions", "body-markup"])

    def test_missing_jeepney_refuses_cleanly(self):
        try:
            import jeepney  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("jeepney is installed here")
        backend = notify.DBusNotifier()
        with self.assertRaises(notify.NotifyError):
            backend.send("s", "b")


class SelectBackendTest(unittest.TestCase):
    def test_explicit_names(self):
        self.assertIsInstance(
            notify.select_backend("notify-send", which=lambda name: "/bin/" + name),
            notify.NotifySendBackend,
        )
        self.assertIsInstance(
            notify.select_backend("gdbus", which=lambda name: "/bin/" + name),
            notify.GDBusBackend,
        )
        self.assertIsInstance(notify.select_backend("dbus"), notify.DBusNotifier)
        self.assertIsInstance(notify.select_backend("jeepney"), notify.DBusNotifier)

    def test_unknown_name_refuses(self):
        with self.assertRaises(notify.NotifyError):
            notify.select_backend("carrier-pigeon", which=lambda name: None)

    def test_auto_prefers_notify_send(self):
        backend = notify.select_backend(
            "auto", which=lambda name: "/bin/" + name if name != "missing" else None
        )
        self.assertIsInstance(backend, notify.NotifySendBackend)

    def test_auto_falls_back_to_gdbus_without_libnotify(self):
        backend = notify.select_backend(
            "auto", which=lambda name: "/bin/gdbus" if name == "gdbus" else None
        )
        self.assertIsInstance(backend, notify.GDBusBackend)

    def test_auto_without_tools_is_null(self):
        backend = notify.select_backend("auto", which=lambda name: None)
        self.assertIsInstance(backend, notify.NullNotifier)
        receipt = backend.send("s", "b")
        self.assertIsNone(receipt["id"])
        self.assertEqual(
            backend.wait_for_action(receipt, timeout=1), ("closed", "no-backend")
        )


class MarkupTest(unittest.TestCase):
    def test_supports_markup(self):
        self.assertTrue(notify.supports_markup(["actions", "body-markup"]))
        self.assertFalse(notify.supports_markup(["actions", "body"]))
        self.assertFalse(notify.supports_markup([]))

    def test_escape(self):
        self.assertEqual(notify.escape_markup('a<b>&"c"'), 'a&lt;b&gt;&amp;"c"')


class DoctorNotifyTest(unittest.TestCase):
    def _config(self, backend="auto"):
        return {
            "mode": "observe",
            "paths": {},
            "timers": {},
            "protected": {},
            "seeds": {},
            "learner": {},
            "notify": {"backend": backend, "enabled": True},
            "_sources": [],
        }

    def _check(self, report):
        for item in report["checks"]:
            if item["name"] == "notifications":
                return item
        self.fail("no notifications check in doctor report")

    def test_reports_active_backend_and_capabilities(self):
        from taema import doctor

        report = doctor.diagnose(
            self._config("notify-send"),
            notify={"backend": "notify-send", "capabilities": ["actions", "body"]},
        )
        item = self._check(report)
        self.assertEqual(item["status"], "ok")
        self.assertIn("notify-send", item["message"])
        self.assertIn("actions", item["message"])

    def test_no_backend_is_a_warning(self):
        from taema import doctor

        report = doctor.diagnose(
            self._config("auto"), notify={"backend": "null", "capabilities": []}
        )
        item = self._check(report)
        self.assertEqual(item["status"], "warn")
        self.assertIn("no notification backend", item["message"])

    def test_live_probe_never_crashes(self):
        from taema import doctor

        report = doctor.diagnose(self._config("auto"))
        item = self._check(report)
        self.assertIn(item["status"], ("ok", "warn"))


if __name__ == "__main__":
    unittest.main()
