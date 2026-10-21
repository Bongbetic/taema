"""Conservative socket checks for reversible idle-scope freezing."""

from __future__ import annotations

import os
import re


_X_SOCKET = re.compile(r"(?:^|/)\.x11-unix/x\d+$", re.IGNORECASE)
_MEDIA_SOCKET_PARTS = (
    "pipewire",
    "pulse/native",
    "pulseaudio",
    "jack/",
    "libcamera",
    "camera",
    "video4linux",
)
_SOCKET_FD = re.compile(r"^socket:\[(\d+)\]$")
_MAX_FD_SCAN = 1024


def _socket_kind(path: str) -> str:
    normalized = path.lower().removeprefix("@").replace("%00", "")
    name = normalized.rsplit("/", 1)[-1]
    if "wayland-" in name or _X_SOCKET.search(normalized):
        return "window"
    if any(part in normalized for part in _MEDIA_SOCKET_PARTS):
        return "media"
    return ""


def member_fd_facts(members, snapshot, proc_root):
    """Return current socket inodes and fail closed on unknown descriptor state."""
    known_inodes = getattr(snapshot, "socket_inodes", None)
    if known_inodes is None:
        known_inodes = {
            row.get("inode")
            for row in (
                *getattr(snapshot, "unix", ()),
                *getattr(snapshot, "tcp", ()),
                *getattr(snapshot, "tcp_listen", ()),
                *getattr(snapshot, "udp", ()),
            )
            if isinstance(row.get("inode"), int)
        }
    sockets = set()
    for pid in members:
        directory = os.path.join(proc_root, str(pid), "fd")
        try:
            descriptors = os.listdir(directory)
        except OSError:
            return "process descriptor state unknown", set(), False
        if len(descriptors) > _MAX_FD_SCAN:
            return "process descriptor state unknown", set(), False
        for descriptor in descriptors:
            try:
                target = os.readlink(os.path.join(directory, descriptor))
            except OSError:
                return "process descriptor state unknown", set(), False
            if target == "/dev/ptmx" or target.endswith("/pts/ptmx"):
                return "", sockets, True
            match = _SOCKET_FD.fullmatch(target)
            if not match:
                continue
            inode = int(match.group(1))
            if inode not in known_inodes:
                return "socket state unknown", set(), False
            sockets.add(inode)
    return "", sockets, False


def socket_safety_reason(members, snapshot, member_socket_inodes=()):
    """Return why socket state is unsafe or unknown, otherwise ``None``.

    Any member listener is withheld until wake-on-connect is implemented. All established TCP
    connections are live dependencies. Unix peer facts must resolve; named compositor and
    media-service connections are treated as live clients even without a window/session agent.
    """
    members = set(members)
    member_socket_inodes = set(member_socket_inodes)
    if not getattr(snapshot, "ok", False):
        return "socket state unknown"

    for row in snapshot.tcp_listen:
        if row["pids"] & members or row.get("inode") in member_socket_inodes:
            return "listening socket"
    for row in snapshot.tcp:
        if row["state"] == "ESTAB" and (
            row["pids"] & members or row.get("inode") in member_socket_inodes
        ):
            return "established TCP connection"
    for row in getattr(snapshot, "udp", ()):
        if row["pids"] & members or row.get("inode") in member_socket_inodes:
            return "UDP socket"

    for row in snapshot.unix:
        owned = row["pids"] & members or row.get("inode") in member_socket_inodes
        if not owned:
            continue
        if row["state"] == "LISTEN":
            return "listening socket"
        peer_inode = row["peer_inode"]
        peer = snapshot.by_inode.get(peer_inode) if peer_inode else None
        if peer is None:
            return "Unix socket peer unknown"
        for path in (
            row["path"],
            row.get("peer_path", ""),
            peer["path"],
            peer.get("peer_path", ""),
        ):
            kind = _socket_kind(path)
            if kind == "window":
                return "connected to a window compositor"
            if kind == "media":
                return "connected to an audio or video client socket"
        peer_pids = peer.get("pids", set())
        if not peer_pids:
            return "Unix socket peer owner unknown"
        if peer_pids - members:
            return "outside Unix socket peer"
    return None
