"""Window backends: snapshots and event streams behind one contract.

Niri is the first backend, spoken to over its Unix socket with single-line
JSON: a "Windows" request snapshots, an "EventStream" request streams.
Unknown events and missing fields are tolerated; only transport failures
raise.
"""

import json
import os
import socket


class WindowError(Exception):
    """The window backend is unreachable or answered unparseably."""


def normalize_window(raw, store_titles=False):
    """Normalize one niri window object; None when it has no valid id."""
    if not isinstance(raw, dict):
        return None
    id = raw.get("id")
    if not isinstance(id, int) or isinstance(id, bool) or id < 0:
        return None
    pid = raw.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        pid = None
    app_id = raw.get("app_id")
    if not isinstance(app_id, str) or not app_id:
        app_id = None
    normalized = {
        "id": id,
        "app_id": app_id,
        "pid": pid,
        "focused": bool(raw.get("is_focused")),
    }
    if store_titles and isinstance(raw.get("title"), str) and raw["title"]:
        normalized["title"] = raw["title"]
    return normalized


class WindowBackend:
    """Snapshot plus event-stream contract every compositor backend keeps."""

    name = "none"

    def snapshot(self, connect=None):
        """Current windows, seeding backend state; raises WindowError."""
        raise NotImplementedError

    def ingest_line(self, line):
        """Turn one stream line into normalized events (possibly none)."""
        raise NotImplementedError


class NiriBackend(WindowBackend):
    """Niri over $NIRI_SOCKET: "Windows" snapshots, "EventStream" streams."""

    name = "niri"

    def __init__(self, socket_path=None, store_titles=False):
        self.socket_path = socket_path
        self.store_titles = store_titles
        self.windows = {}

    def _path(self):
        path = self.socket_path or os.environ.get("NIRI_SOCKET")
        if not path:
            raise WindowError("NIRI_SOCKET is not set and no socket path was given")
        return path

    def _connect(self, connect):
        if connect is not None:
            return connect()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._path())
        except OSError as e:
            sock.close()
            raise WindowError("cannot reach niri at %s: %s" % (self._path(), e))
        return sock

    def _request(self, payload, connect=None):
        sock = self._connect(connect)
        release = connect is None
        try:
            try:
                sock.sendall((json.dumps(payload) + "\n").encode())
                reader = sock.makefile("r", encoding="utf-8")
                line = reader.readline()
            except OSError as e:
                raise WindowError("niri request failed: %s" % e)
            if not line:
                raise WindowError("niri closed the connection without a reply")
            try:
                return json.loads(line)
            except ValueError:
                raise WindowError("niri answered unparseably: %r" % line[:200])
        finally:
            if release:
                try:
                    sock.close()
                except OSError:
                    pass

    def snapshot(self, connect=None):
        """Fetch every window; tolerates bare arrays and wrapped replies."""
        reply = self._request("Windows", connect=connect)
        if isinstance(reply, dict) and "Err" in reply:
            raise WindowError("niri refused the snapshot: %r" % (reply["Err"],))
        if isinstance(reply, dict) and "Ok" in reply:
            reply = reply["Ok"]
        if isinstance(reply, dict):
            for key in ("Windows", "windows"):
                if isinstance(reply.get(key), list):
                    reply = reply[key]
                    break
        if not isinstance(reply, list):
            raise WindowError("niri snapshot has no window list: %r" % (reply,))
        found = []
        self.windows = {}
        for raw in reply:
            parsed = normalize_window(raw, self.store_titles)
            if parsed is not None:
                self.windows[parsed["id"]] = parsed
                found.append(parsed)
        return found

    def open_stream(self, connect=None):
        """Connect and request the event stream; returns a line reader.

        Reads time out quickly so the agent's poll tick never blocks on
        an idle compositor.
        """
        sock = self._connect(connect)
        try:
            sock.sendall(b'"EventStream"\n')
        except OSError as e:
            if connect is None:
                sock.close()
            raise WindowError("niri event stream request failed: %s" % e)
        try:
            sock.settimeout(0.5)
        except OSError:
            pass
        return sock.makefile("r", encoding="utf-8")

    def focused_id(self):
        """The focused window id, or None when nothing is focused."""
        for id, known in self.windows.items():
            if known.get("focused"):
                return id
        return None

    def _event(self, kind, window_id, app_id=None, pid=None, focus=False, title=None):
        event = {
            "kind": kind,
            "window_id": window_id,
            "app_id": app_id,
            "pid": pid,
            "focus": focus,
        }
        if title is not None:
            event["title"] = title
        return event

    def ingest_line(self, line):
        """Parse one stream line; unknown events and garbage yield nothing."""
        try:
            message = json.loads(line)
        except ValueError:
            return []
        if not isinstance(message, dict) or len(message) != 1:
            return []
        variant, body = next(iter(message.items()))
        if not isinstance(body, dict):
            return []
        if variant == "WindowsChanged":
            return self._ingest_replacement(body.get("windows"))
        if variant == "WindowOpenedOrChanged":
            parsed = normalize_window(body.get("window"), self.store_titles)
            if parsed is None:
                return []
            known = self.windows.get(parsed["id"])
            kind = "changed" if known is not None else "opened"
            if parsed["focused"]:
                for other in self.windows.values():
                    other["focused"] = False
            self.windows[parsed["id"]] = parsed
            return [
                self._event(
                    kind,
                    parsed["id"],
                    parsed["app_id"],
                    parsed["pid"],
                    parsed["focused"],
                    parsed.get("title"),
                )
            ]
        if variant == "WindowClosed":
            id = body.get("id")
            if not isinstance(id, int) or isinstance(id, bool):
                return []
            self.windows.pop(id, None)
            return [self._event("closed", id)]
        if variant == "WindowFocusChanged":
            id = body.get("id")
            if id is not None and (not isinstance(id, int) or isinstance(id, bool)):
                return []
            for known_id, known in self.windows.items():
                known["focused"] = known_id == id
            known = self.windows.get(id) if id is not None else None
            return [
                self._event(
                    "focus",
                    id,
                    (known or {}).get("app_id"),
                    (known or {}).get("pid"),
                    id is not None,
                )
            ]
        return []

    def _ingest_replacement(self, raw_windows):
        """A full configuration replaces state; diff it into open/close."""
        if not isinstance(raw_windows, list):
            return []
        fresh = {}
        for raw in raw_windows:
            parsed = normalize_window(raw, self.store_titles)
            if parsed is not None:
                fresh[parsed["id"]] = parsed
        events = []
        for id in self.windows:
            if id not in fresh:
                events.append(self._event("closed", id))
        for id, parsed in fresh.items():
            if id not in self.windows:
                events.append(
                    self._event(
                        "opened",
                        id,
                        parsed["app_id"],
                        parsed["pid"],
                        parsed["focused"],
                        parsed.get("title"),
                    )
                )
        self.windows = fresh
        return events
