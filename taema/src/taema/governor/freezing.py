"""Conservative socket checks for reversible idle-scope freezing."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


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


@dataclass(frozen=True, slots=True)
class ListenerDescriptor:
    transport: str
    inode: int

    @classmethod
    def from_record(cls, record):
        if not isinstance(record, dict):
            return None
        transport = record.get("transport")
        inode = record.get("inode")
        if (
            transport not in ("tcp", "unix")
            or not isinstance(inode, int)
            or isinstance(inode, bool)
            or inode <= 0
        ):
            return None
        return cls(transport, inode)

    def to_record(self):
        return {"transport": self.transport, "inode": self.inode}


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


def socket_safety_reason(
    members, snapshot, member_socket_inodes=(), *, wake_on_connect=False
):
    """Return why socket state is unsafe or unknown, otherwise ``None``."""
    members = set(members)
    member_socket_inodes = set(member_socket_inodes)
    if not getattr(snapshot, "ok", False):
        return "socket state unknown"

    for row in snapshot.tcp_listen:
        if row["pids"] & members or row.get("inode") in member_socket_inodes:
            reason = _listener_queue_reason(row, wake_on_connect)
            if reason:
                return reason
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
            reason = _listener_queue_reason(row, wake_on_connect)
            if reason:
                return reason
            continue
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


def _listener_queue_reason(row, wake_on_connect):
    if not wake_on_connect:
        return "listening socket"
    recv_q = row.get("recv_q")
    if not isinstance(recv_q, int) or isinstance(recv_q, bool) or recv_q < 0:
        return "listener queue unknown"
    if recv_q:
        return "listener has pending connections"
    return None


def listener_descriptors(members, snapshot, member_socket_inodes=()):
    """Identify every member-owned listener for post-freeze accept-queue monitoring."""
    members = set(members)
    member_socket_inodes = set(member_socket_inodes)
    descriptors = {}
    for transport, rows in (
        ("tcp", snapshot.tcp_listen),
        ("unix", snapshot.unix),
    ):
        for row in rows:
            if row.get("state") != "LISTEN":
                continue
            if not (row.get("pids", set()) & members) and row.get(
                "inode"
            ) not in member_socket_inodes:
                continue
            inode = row.get("inode")
            if not isinstance(inode, int) or isinstance(inode, bool) or inode <= 0:
                return (), "listener identity unknown"
            descriptors[(transport, inode)] = ListenerDescriptor(transport, inode)
    return tuple(descriptors[key] for key in sorted(descriptors)), ""
