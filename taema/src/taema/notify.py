"""Desktop notification backends behind one Notifier contract.

notify-send is the default; an opt-in jeepney D-Bus backend adds closing
and signal listening; gdbus is the one-way fallback when libnotify is
missing. No backend is a mandatory dependency: jeepney is imported lazily
and the tools are only required when their backend is selected.
"""

import re
import shutil
import subprocess
import time

SERVICE = "org.freedesktop.Notifications"
OBJECT_PATH = "/org/freedesktop/Notifications"

_WAIT_TIMEOUT = 10


class NotifyError(Exception):
    """A notification could not be sent, waited on, or closed."""


def escape_markup(text):
    """Escape the three characters notification markup treats specially."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def supports_markup(capabilities):
    """Whether the server advertises markup-capable bodies."""
    return "body-markup" in (capabilities or ())


def _quote_variant(text):
    """Double-quote a string for GVariant text format."""
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


class NotifySendBackend:
    """Default backend: libnotify's notify-send, with --wait for actions."""

    name = "notify-send"

    def __init__(self, runner=None, popen=None):
        self._run = runner or _default_runner
        self._popen = popen or subprocess.Popen

    def capabilities(self):
        return {"send", "actions"}

    def server_capabilities(self):
        return []

    def send(
        self,
        summary,
        body,
        actions=(),
        app="taema",
        icon="",
        urgency="normal",
        expire_ms=-1,
        markup=False,
        wait=False,
    ):
        if not markup:
            summary = escape_markup(summary)
            body = escape_markup(body)
        argv = [
            "notify-send",
            "--app-name=" + app,
            "--urgency=" + urgency,
            "--expire-time=%d" % expire_ms,
        ]
        if icon:
            argv.append("--icon=" + icon)
        for key, label in actions:
            argv.append("--action=%s=%s" % (key, label))
        argv.append("--print-id")
        if wait:
            argv.append("--wait")
            try:
                proc = self._popen(
                    argv + [summary, body],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            except OSError as e:
                raise NotifyError("notify-send failed to start: %s" % e)
            keys = [key for key, _label in actions]
            return {
                "id": None,
                "backend": self.name,
                "proc": proc,
                "keys": keys,
                "argv": argv,
            }
        try:
            completed = self._run(
                argv + [summary, body],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=_WAIT_TIMEOUT,
            )
        except OSError as e:
            raise NotifyError("notify-send failed to start: %s" % e)
        if completed.returncode != 0:
            raise NotifyError(
                "notify-send exited %d: %s"
                % (completed.returncode, (completed.stderr or "").strip()[:200])
            )
        try:
            nid = int((completed.stdout or "").strip().splitlines()[0])
        except (IndexError, ValueError):
            raise NotifyError(
                "notify-send printed no id: %r" % (completed.stdout or "")
            )
        return {"id": nid, "backend": self.name, "argv": argv}

    def wait_for_action(self, receipt, timeout):
        """Read the --wait outcome: an action key, a close, or a timeout."""
        proc = receipt.get("proc")
        if proc is None:
            raise NotifyError("notify-send receipt was not sent with wait=True")
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return ("timeout", None)
        line = (proc.stdout.readline() or "").strip()
        if line and line in receipt.get("keys", ()):
            return ("action", line)
        return ("closed", line or "dismissed")

    def close(self, nid):
        raise NotifyError("notify-send cannot close notification %r" % (nid,))

    def cancel_wait(self, receipt):
        """Abandon a --wait process; the notification itself stays up."""
        proc = receipt.get("proc")
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def _default_runner(argv, **kwargs):
    return subprocess.run(argv, **kwargs)  # noqa: S603 - argv only, never a shell line


def _parse_gdbus_uint32(text):
    match = re.search(r"\(uint32 (\d+),\)", text or "")
    if not match:
        raise NotifyError("gdbus printed no notification id: %r" % (text or ""))
    return int(match.group(1))


class GDBusBackend:
    """One-way fallback backend: gdbus method calls, no listening."""

    name = "gdbus"

    def __init__(self, runner=None):
        self._run = runner or _default_runner

    def capabilities(self):
        return {"send"}

    def server_capabilities(self):
        return query_server_capabilities(runner=self._run)

    def _call(self, method, args):
        argv = [
            "gdbus",
            "call",
            "--session",
            "--dest",
            SERVICE,
            "--object-path",
            OBJECT_PATH,
            "--method",
            SERVICE + "." + method,
            # A negative expire timeout would parse as a flag without this.
            "--",
        ] + args
        try:
            completed = self._run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=_WAIT_TIMEOUT,
            )
        except OSError as e:
            raise NotifyError("gdbus failed to start: %s" % e)
        if completed.returncode != 0:
            raise NotifyError(
                "gdbus %s failed: %s" % (method, (completed.stderr or "").strip()[:200])
            )
        return completed.stdout or ""

    def send(
        self,
        summary,
        body,
        actions=(),
        app="taema",
        icon="",
        urgency="normal",
        expire_ms=-1,
        markup=False,
        wait=False,
    ):
        if wait:
            raise NotifyError("the gdbus backend is one-way; it cannot wait")
        if not markup:
            summary = escape_markup(summary)
            body = escape_markup(body)
        flat = []
        for key, label in actions:
            flat.append(_quote_variant(key))
            flat.append(_quote_variant(label))
        out = self._call(
            "Notify",
            [
                _quote_variant(app),
                "0",
                _quote_variant(icon),
                _quote_variant(summary),
                _quote_variant(body),
                "[%s]" % ", ".join(flat),
                "{}",
                "%d" % expire_ms,
            ],
        )
        return {"id": _parse_gdbus_uint32(out), "backend": self.name}

    def wait_for_action(self, receipt, timeout):
        raise NotifyError("the gdbus backend is one-way; it cannot wait")

    def cancel_wait(self, receipt):
        pass

    def close(self, nid):
        self._call("CloseNotification", ["%d" % nid])


def query_server_capabilities(runner=None):
    """Ask the notification server for its capabilities via gdbus.

    Returns [] when gdbus is missing, the server is away, or the reply
    does not parse: unknown capabilities, never an exception.
    """
    run = runner or _default_runner
    try:
        completed = run(
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                SERVICE,
                "--object-path",
                OBJECT_PATH,
                "--method",
                SERVICE + ".GetCapabilities",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_WAIT_TIMEOUT,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    match = re.search(r"\(\[(.*)\],\)", completed.stdout or "", re.DOTALL)
    if not match:
        return []
    return re.findall(r"'((?:[^'\\]|\\.)*)'", match.group(1))


class _JeepneyConnection:
    """The small jeepney surface the D-Bus backend needs.

    Blocking I/O only: method calls plus one filtered signal wait. Every
    jeepney import happens here, so the module loads without jeepney.
    """

    def __init__(self):
        try:
            from jeepney import (  # type: ignore[import-not-found]
                DBusAddress,
                HeaderFields,
                MatchRule,
                new_method_call,
            )
            from jeepney.bus_messages import message_bus  # type: ignore[import-not-found]
            from jeepney.io.blocking import (  # type: ignore[import-not-found]
                open_dbus_connection,
            )
        except ImportError:
            raise NotifyError(
                "the dbus backend needs jeepney: pip install jeepney "
                "or pick another notify backend"
            )
        self._DBusAddress = DBusAddress
        self._HeaderFields = HeaderFields
        self._MatchRule = MatchRule
        self._new_method_call = new_method_call
        self._message_bus = message_bus
        try:
            self._conn = open_dbus_connection(bus="SESSION")
        except Exception as e:
            raise NotifyError("could not open the session bus: %s" % e)
        self._address = DBusAddress(OBJECT_PATH, bus_name=SERVICE, interface=SERVICE)

    def _call(self, method, signature, args, timeout=_WAIT_TIMEOUT):
        msg = self._new_method_call(self._address, method, signature, args)
        try:
            reply = self._conn.send_and_get_reply(msg, timeout=timeout)
        except Exception as e:
            raise NotifyError("D-Bus %s failed: %s" % (method, e))
        return reply.body

    def call_notify(self, app, replaces, icon, summary, body, actions, hints, expire):
        flat = []
        for key, label in actions:
            flat.extend((key, label))
        body = self._call(
            "Notify",
            "susssasa{sv}i",
            (app, replaces, icon, summary, body, flat, dict(hints), expire),
        )
        return body[0]

    def call_close(self, nid):
        self._call("CloseNotification", "u", (nid,))

    def call_get_capabilities(self):
        return list(self._call("GetCapabilities", "", ()))

    def call_get_owner(self):
        msg = self._new_method_call(self._message_bus, "GetNameOwner", "s", (SERVICE,))
        try:
            reply = self._conn.send_and_get_reply(msg, timeout=_WAIT_TIMEOUT)
        except Exception as e:
            raise NotifyError("D-Bus GetNameOwner failed: %s" % e)
        return reply.body[0]

    def _field(self, msg, name, fallback):
        fields = msg.header.fields
        key = getattr(self._HeaderFields, name, fallback)
        try:
            value = fields.get(key)
        except (AttributeError, TypeError):
            value = None
        if value is None and key != fallback:
            try:
                value = fields.get(fallback)
            except (AttributeError, TypeError):
                value = None
        return value

    def wait_signal(self, members, timeout):
        """Wait for the next ActionInvoked/NotificationClosed signal.

        Returns (member, sender, body) or None on timeout. The match rule
        carries no sender: forged signals still arrive so the caller can
        ignore them explicitly against the current service owner.
        """
        for member in members:
            rule = "type='signal',interface='%s',member='%s',path='%s'" % (
                SERVICE,
                member,
                OBJECT_PATH,
            )
            msg = self._new_method_call(self._message_bus, "AddMatch", "s", (rule,))
            try:
                self._conn.send_and_get_reply(msg, timeout=_WAIT_TIMEOUT)
            except Exception as e:
                raise NotifyError("D-Bus AddMatch failed: %s" % e)
        local = self._MatchRule(type="signal", interface=SERVICE, path=OBJECT_PATH)
        try:
            with self._conn.filter(local) as matches:
                msg = self._conn.recv_until_filtered(matches, timeout=timeout)
        except TimeoutError:
            return None
        except Exception as e:
            raise NotifyError("D-Bus signal wait failed: %s" % e)
        member = self._field(msg, "member", 3)
        return (member, self._field(msg, "sender", 7), tuple(msg.body))

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


class DBusNotifier:
    """Richer backend over jeepney: send, close, and signal listening.

    Signals are accepted only from the unique name that currently owns
    the notification service; anything else is a forgery and is ignored.
    """

    name = "dbus"

    def __init__(self, connect=None):
        self._connect = connect or _JeepneyConnection
        self._conn = None

    def _connection(self):
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def capabilities(self):
        return {"send", "actions", "close"}

    def server_capabilities(self):
        try:
            return self._connection().call_get_capabilities()
        except NotifyError:
            return []

    def send(
        self,
        summary,
        body,
        actions=(),
        app="taema",
        icon="",
        urgency="normal",
        expire_ms=-1,
        markup=False,
        wait=False,
    ):
        if not markup:
            summary = escape_markup(summary)
            body = escape_markup(body)
        hints = {}
        if urgency != "normal":
            hints["urgency"] = {"low": 0, "critical": 2}.get(urgency, 1)
        conn = self._connection()
        nid = conn.call_notify(
            app, 0, icon, summary, body, list(actions), hints, expire_ms
        )
        return {"id": nid, "backend": self.name}

    def wait_for_action(self, receipt, timeout):
        """Wait for an action or close on this notification only.

        Forged signals (wrong sender) and signals for other notifications
        are skipped; the wait continues until timeout.
        """
        conn = self._connection()
        owner = conn.call_get_owner()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout", None)
            signal = conn.wait_signal(
                ("ActionInvoked", "NotificationClosed"), remaining
            )
            if signal is None:
                return ("timeout", None)
            member, sender, args = signal
            if sender != owner or not args or args[0] != receipt["id"]:
                continue
            if member == "ActionInvoked":
                return ("action", args[1] if len(args) > 1 else "")
            if member == "NotificationClosed":
                return ("closed", args[1] if len(args) > 1 else 0)
            continue

    def close(self, nid):
        self._connection().call_close(nid)

    def cancel_wait(self, receipt):
        pass


class NullNotifier:
    """No tool backend: sends vanish, waits report no-backend."""

    name = "null"

    def capabilities(self):
        return set()

    def server_capabilities(self):
        return []

    def send(self, summary, body, **kwargs):
        return {"id": None, "backend": self.name}

    def wait_for_action(self, receipt, timeout):
        return ("closed", "no-backend")

    def cancel_wait(self, receipt):
        pass

    def close(self, nid):
        pass


def jeepney_available():
    try:
        import jeepney  # noqa: F401
    except ImportError:
        return False
    return True


def select_backend(name, which=None):
    """Resolve a configured backend name to a backend instance.

    `auto` prefers the default notify-send, falls back to one-way gdbus
    when libnotify is missing, and degrades to null without tools. The
    richer jeepney backend is opt-in: `dbus` or `jeepney`.
    """
    find = which or shutil.which
    if name in ("dbus", "jeepney"):
        return DBusNotifier()
    if name == "notify-send":
        return NotifySendBackend()
    if name == "gdbus":
        return GDBusBackend()
    if name == "null":
        return NullNotifier()
    if name != "auto":
        raise NotifyError("unknown notify backend %r" % (name,))
    if find("notify-send"):
        return NotifySendBackend()
    if find("gdbus"):
        return GDBusBackend()
    return NullNotifier()
