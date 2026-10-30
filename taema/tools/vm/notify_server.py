#!/usr/bin/env python3
# Scripted org.freedesktop.Notifications server for the graphical VM
# scenario.  Records every Notify call as one JSON object per line and obeys
# a control file: each appended line is "invoke <id> <action-key>" or
# "close <id>", which emits ActionInvoked / NotificationClosed on cue.
# Stdlib-only record/control helpers; dbus is imported only in main().

import json
import os
import sys

CAPABILITIES = ["actions", "body", "persistence"]


def record(log_path, entry):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
        fh.flush()


def read_records(log_path):
    if not os.path.isfile(log_path):
        return []
    with open(log_path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def parse_control_line(line):
    parts = line.split()
    if len(parts) >= 3 and parts[0] == "invoke":
        try:
            return ("invoke", int(parts[1]), parts[2])
        except ValueError:
            return None
    if len(parts) >= 2 and parts[0] == "close":
        try:
            return ("close", int(parts[1]), "")
        except ValueError:
            return None
    return None


def pending_commands(control_path, offset):
    """(commands, new_offset): control lines appended since offset."""
    try:
        size = os.path.getsize(control_path)
    except OSError:
        return [], offset
    if size < offset:
        offset = 0
    if size == offset:
        return [], offset
    commands = []
    with open(control_path, encoding="utf-8") as fh:
        fh.seek(offset)
        for line in fh:
            command = parse_control_line(line)
            if command is not None:
                commands.append(command)
        offset = fh.tell()
    return commands, offset


def main(argv):
    if len(argv) != 3:
        print("usage: notify_server.py <log> <control>", file=sys.stderr)
        return 2
    log_path, control_path = argv[1], argv[2]

    import dbus
    import dbus.mainloop.glib
    import dbus.service
    from gi.repository import GLib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.freedesktop.Notifications", bus)

    class Notifications(dbus.service.Object):
        def __init__(self):
            super().__init__(name, "/org/freedesktop/Notifications")
            self.next_id = 0
            self.offset = 0
            open(control_path, "a", encoding="utf-8").close()
            record(log_path, {"event": "ready"})

        @dbus.service.method(
            "org.freedesktop.Notifications",
            in_signature="susssasa{sv}i",
            out_signature="u",
        )
        def Notify(
            self,
            app_name,
            replaces_id,
            app_icon,
            summary,
            body,
            actions,
            hints,
            expire_timeout,
        ):
            self.next_id += 1
            nid = self.next_id
            record(
                log_path,
                {
                    "event": "notify",
                    "id": nid,
                    "app": str(app_name),
                    "summary": str(summary),
                    "body": str(body),
                    "actions": [str(action) for action in actions],
                },
            )
            return dbus.UInt32(nid)

        @dbus.service.method(
            "org.freedesktop.Notifications", in_signature="", out_signature="as"
        )
        def GetCapabilities(self):
            return CAPABILITIES

        @dbus.service.method(
            "org.freedesktop.Notifications", in_signature="", out_signature="ssss"
        )
        def GetServerInformation(self):
            return ("taema-scripted", "taema", "1.0", "1.2")

        @dbus.service.method(
            "org.freedesktop.Notifications", in_signature="u", out_signature=""
        )
        def CloseNotification(self, nid):
            record(log_path, {"event": "closed", "id": int(nid), "reason": 3})
            self.NotificationClosed(dbus.UInt32(nid), dbus.UInt32(3))

        @dbus.service.signal("org.freedesktop.Notifications", signature="us")
        def ActionInvoked(self, nid, action_key):
            pass

        @dbus.service.signal("org.freedesktop.Notifications", signature="uu")
        def NotificationClosed(self, nid, reason):
            pass

        def poll_control(self):
            commands, self.offset = pending_commands(control_path, self.offset)
            for verb, nid, action in commands:
                if verb == "invoke":
                    record(
                        log_path,
                        {"event": "action", "id": nid, "action": action},
                    )
                    self.ActionInvoked(dbus.UInt32(nid), action)
                else:
                    record(log_path, {"event": "closed", "id": nid, "reason": 3})
                    self.NotificationClosed(dbus.UInt32(nid), dbus.UInt32(3))
            return True

    service = Notifications()
    GLib.timeout_add(100, service.poll_control)
    GLib.MainLoop().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
