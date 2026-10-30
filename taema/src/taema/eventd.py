"""`taema-eventd`: optional root forwarder for kernel process events.

One instance per system, supervised by the existing runit service. It
subscribes to the netlink proc connector (fork, exec, exit), filters events
by uid, and forwards compact records ``(kind, pid, tgid, ppid, uid, start,
ts_ns)`` plus exe/comm facts captured while the process is still alive to
per-user sockets ``<run_dir>/<uid>.sock`` created by root with mode 0600.

The forwarder only forwards facts: it accepts no commands (inbound bytes are
ignored and never answered) and makes no decisions. Each connected consumer
has its own 4,096-record ring; a slow consumer causes counted drops and never
blocks the forwarder. A per-uid backlog ring of the same size lets a freshly
connected daemon catch up on recent births.

Per D13 the forwarder ships as a separate optional package and stays off by
default; see ``TAEMA_EVENTD`` in ``sv/taema/run``.
"""

from __future__ import annotations

import collections
import os
import select
import socket
import struct
import time
from dataclasses import dataclass


# ---- proc-connector subscription (privileged entry, root only) ----

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2
NLMSG_DONE = 3

PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000

_NLMSG_HDRLEN = 16
_CN_MSG_HDRLEN = 20
_PROC_EVENT_HDRLEN = 16


def subscription_message(listen: bool = True) -> bytes:
    """Build the netlink message that (un)subscribes from proc events."""
    op = PROC_CN_MCAST_LISTEN if listen else PROC_CN_MCAST_IGNORE
    payload = struct.pack("<i", op)
    cn_msg = struct.pack("<IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0)
    cn_msg += payload
    nlmsg_len = _NLMSG_HDRLEN + len(cn_msg)
    return struct.pack("<IHHII", nlmsg_len, NLMSG_DONE, 0, 0, 0) + cn_msg


@dataclass(frozen=True, slots=True)
class KernelEvent:
    """One decoded proc-connector event: fork, exec, or exit."""

    kind: str
    pid: int
    tgid: int
    ppid: int
    exit_code: int


def decode_kernel_frames(data: bytes) -> list[KernelEvent]:
    """Decode chained netlink proc-connector frames; ignore truncated/unknown ones."""
    events: list[KernelEvent] = []
    offset = 0
    size = len(data)
    while offset + _NLMSG_HDRLEN <= size:
        (nlmsg_len, _nl_type, _flags, _seq, _pid) = struct.unpack_from(
            "<IHHII", data, offset
        )
        if nlmsg_len < _NLMSG_HDRLEN or offset + nlmsg_len > size:
            break
        end = offset + nlmsg_len
        offset += _NLMSG_HDRLEN
        if offset + _CN_MSG_HDRLEN > end:
            continue
        (idx, val, _cn_seq, _ack, cn_len, _cn_flags) = struct.unpack_from(
            "<IIIIHH", data, offset
        )
        offset += _CN_MSG_HDRLEN
        if idx != CN_IDX_PROC or val != CN_VAL_PROC:
            continue
        if offset + _PROC_EVENT_HDRLEN > end or offset + cn_len > end:
            continue
        (what, _cpu, _ts) = struct.unpack_from("<IIQ", data, offset)
        offset += _PROC_EVENT_HDRLEN
        fields = struct.unpack_from("<IIII", data, offset)
        offset = end
        if what == PROC_EVENT_FORK:
            events.append(KernelEvent("fork", fields[2], fields[3], fields[0], 0))
        elif what == PROC_EVENT_EXEC:
            events.append(KernelEvent("exec", fields[0], fields[1], 0, 0))
        elif what == PROC_EVENT_EXIT:
            events.append(KernelEvent("exit", fields[0], fields[1], 0, fields[2]))
    return events


# ---- compact per-user record stream ----

MAGIC = b"TEv1"
RING_CAPACITY = 4096
DEFAULT_RUN_DIR = "/run/taema/events"

_KIND_TO_NUM = {"fork": 1, "exec": 2, "exit": 3}
_NUM_TO_KIND = {1: "fork", 2: "exec", 3: "exit"}


@dataclass(frozen=True, slots=True)
class CompactRecord:
    """One forwarded fact: lifecycle kind plus ids captured while alive."""

    kind: str
    pid: int
    tgid: int
    ppid: int
    uid: int
    ts_ns: int
    exit_code: int
    exe: str
    comm: str
    start: int = 0


def encode_record(record: CompactRecord) -> bytes:
    """Encode one record as a length-prefixed frame (4-byte LE length)."""
    exe = record.exe.encode("utf-8", "replace")[:256]
    comm = record.comm.encode("utf-8", "replace")[:64]
    body = struct.pack(
        "<4sBIIIIQQiHB",
        MAGIC,
        _KIND_TO_NUM[record.kind],
        record.pid,
        record.tgid,
        record.ppid,
        record.uid,
        record.start,
        record.ts_ns,
        record.exit_code,
        len(exe),
        len(comm),
    )
    return struct.pack("<I", len(body) + len(exe) + len(comm)) + body + exe + comm


def decode_records(buffer: bytes) -> tuple[list[CompactRecord], bytes]:
    """Split whole frames off the front of a stream buffer; keep the tail."""
    records: list[CompactRecord] = []
    offset = 0
    size = len(buffer)
    header_len = struct.calcsize("<4sBIIIIQQiHB")
    while offset + 4 <= size:
        (frame_len,) = struct.unpack_from("<I", buffer, offset)
        if offset + 4 + frame_len > size:
            break
        base = offset + 4
        try:
            (
                magic,
                kind_num,
                pid,
                tgid,
                ppid,
                uid,
                start,
                ts_ns,
                exit_code,
                exe_len,
                comm_len,
            ) = struct.unpack_from("<4sBIIIIQQiHB", buffer, base)
        except struct.error:
            break
        body_end = base + header_len + exe_len + comm_len
        if magic != MAGIC or kind_num not in _NUM_TO_KIND:
            break
        if body_end != base + frame_len:
            break
        exe = buffer[base + header_len : base + header_len + exe_len].decode(
            "utf-8", "replace"
        )
        comm = buffer[base + header_len + exe_len : body_end].decode("utf-8", "replace")
        records.append(
            CompactRecord(
                _NUM_TO_KIND[kind_num],
                pid,
                tgid,
                ppid,
                uid,
                ts_ns,
                exit_code,
                exe,
                comm,
                start,
            )
        )
        offset = body_end
    return records, buffer[offset:]


# ---- live-process fact capture (runs as root, best effort) ----


def uid_of(pid: int) -> int | None:
    """Return the uid owning pid, or None when the process is already gone."""
    try:
        return os.stat("/proc/%d" % pid).st_uid
    except OSError:
        return None


def proc_facts(pid: int) -> tuple[str, str, int]:
    """Return (exe, comm, start_ticks) for a live pid; blanks when gone."""
    try:
        exe = os.readlink("/proc/%d/exe" % pid)
    except OSError:
        exe = ""
    try:
        with open("/proc/%d/comm" % pid, encoding="utf-8") as stream:
            comm = stream.read().strip()
    except OSError:
        comm = ""
    start = 0
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as stream:
            parts = stream.read().rsplit(")", 1)[1].split()
            start = int(parts[19])
    except (OSError, ValueError, IndexError):
        start = 0
    return exe[:256], comm[:64], start


# ---- forwarder ----


class ConsumerRing:
    """One bounded per-consumer ring: newest records win, drops are counted."""

    def __init__(self, capacity: int = RING_CAPACITY) -> None:
        self.capacity = capacity
        self.records: collections.deque[CompactRecord] = collections.deque()
        self.drops = 0

    def push(self, record: CompactRecord) -> None:
        if len(self.records) >= self.capacity:
            self.records.popleft()
            self.drops += 1
        self.records.append(record)

    def pop_all(self) -> list[CompactRecord]:
        records = list(self.records)
        self.records.clear()
        return records


class Forwarder:
    """Filter kernel events by uid and stream them to per-user sockets."""

    def __init__(
        self,
        run_dir: str = DEFAULT_RUN_DIR,
        uid_of=uid_of,
        facts_of=proc_facts,
    ) -> None:
        self.run_dir = run_dir
        self._uid_of = uid_of
        self._facts_of = facts_of
        self._uid_cache: dict[int, int] = {}
        self._fact_cache: dict[int, tuple[str, str, int]] = {}
        self.backlog: dict[int, ConsumerRing] = {}
        self.listeners: dict[int, socket.socket] = {}
        self.consumers: dict[socket.socket, dict] = {}
        os.makedirs(run_dir, mode=0o755, exist_ok=True)

    def socket_path(self, uid: int) -> str:
        return os.path.join(self.run_dir, "%d.sock" % uid)

    def ring_for_test(self, uid: int) -> ConsumerRing:
        return self.backlog.setdefault(uid, ConsumerRing())

    def drain_for_test(self, uid: int) -> list[CompactRecord]:
        ring = self.backlog.get(uid)
        return ring.pop_all() if ring is not None else []

    def _listener(self, uid: int) -> socket.socket:
        listener = self.listeners.get(uid)
        if listener is not None:
            return listener
        path = self.socket_path(uid)
        try:
            os.unlink(path)
        except OSError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        os.chmod(path, 0o600)
        try:
            os.chown(path, uid, -1)
        except OSError:
            pass
        listener.listen(16)
        listener.setblocking(False)
        self.listeners[uid] = listener
        return listener

    def _publish(self, record: CompactRecord) -> None:
        self.ring_for_test(record.uid).push(record)
        frame = encode_record(record)
        self._listener(record.uid)
        for sock, state in list(self.consumers.items()):
            if state["uid"] != record.uid:
                continue
            state["ring"].push(record)
            state["outbox"] += frame
        self._flush()

    def feed_kernel(self, data: bytes) -> int:
        """Decode raw connector bytes and publish matching records; return count."""
        count = 0
        for event in decode_kernel_frames(data):
            if event.kind == "exit":
                uid = self._uid_cache.pop(event.pid, None)
                exe, comm, start = self._fact_cache.pop(event.pid, ("", "", 0))
                if uid is None:
                    found = self._uid_of(event.pid)
                    if found is None:
                        continue
                    uid = found
                record = CompactRecord(
                    "exit",
                    event.pid,
                    event.tgid,
                    event.ppid,
                    uid,
                    time.time_ns(),
                    event.exit_code,
                    exe,
                    comm,
                    start,
                )
            else:
                uid = self._uid_of(event.pid)
                if uid is None:
                    continue
                self._uid_cache[event.pid] = uid
                exe, comm, start = self._facts_of(event.pid)
                if len(self._fact_cache) >= 8192:
                    oldest = next(iter(self._fact_cache))
                    del self._fact_cache[oldest]
                self._fact_cache[event.pid] = (exe, comm, start)
                record = CompactRecord(
                    event.kind,
                    event.pid,
                    event.tgid,
                    event.ppid,
                    uid,
                    time.time_ns(),
                    0,
                    exe,
                    comm,
                    start,
                )
            self._publish(record)
            count += 1
        return count

    def _accept(self, listener: socket.socket, uid: int) -> None:
        try:
            conn, _peer = listener.accept()
        except OSError:
            return
        conn.setblocking(False)
        outbox = bytearray()
        ring = ConsumerRing()
        for record in self.backlog.get(uid, ConsumerRing()).records:
            ring.push(record)
            outbox += encode_record(record)
        self.consumers[conn] = {"uid": uid, "ring": ring, "outbox": outbox}
        self._flush()

    def _flush(self) -> None:
        for sock, state in list(self.consumers.items()):
            outbox = state["outbox"]
            if not outbox:
                continue
            try:
                sent = sock.send(outbox)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                self._drop(sock)
                continue
            del outbox[:sent]

    def _drop(self, sock: socket.socket) -> None:
        self.consumers.pop(sock, None)
        try:
            sock.close()
        except OSError:
            pass

    def pump_once_for_test(self, timeout: float = 0.0) -> None:
        """Run one select round: used by tests and the serve loop body."""
        readers: list[socket.socket] = list(self.listeners.values()) + list(
            self.consumers
        )
        writers = [sock for sock, state in self.consumers.items() if state["outbox"]]
        if not readers and not writers:
            return
        readable, writable, _ = select.select(readers, writers, [], timeout)
        for sock in readable:
            if sock in self.listeners.values():
                for uid, listener in self.listeners.items():
                    if listener is sock:
                        self._accept(sock, uid)
            else:
                try:
                    chunk = sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    self._drop(sock)
                    continue
                if not chunk:
                    self._drop(sock)
                # Any inbound bytes are ignored: the socket is emit-only.
        for sock in writable:
            state = self.consumers.get(sock)
            if state is not None and state["outbox"]:
                self._flush()

    def close(self) -> None:
        for sock in list(self.consumers):
            self._drop(sock)
        for listener in self.listeners.values():
            try:
                listener.close()
            except OSError:
                pass
        self.listeners.clear()


def run(run_dir: str = DEFAULT_RUN_DIR) -> int:  # pragma: no cover - needs root+netlink
    """Serve forever: subscribe to the proc connector and forward by uid."""
    forwarder = Forwarder(run_dir)
    netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
    netlink.bind((os.getpid(), CN_IDX_PROC))
    netlink.send(subscription_message(True))
    try:
        while True:
            readable, _, _ = select.select(
                [netlink] + list(forwarder.listeners.values()), [], [], 60.0
            )
            for sock in readable:
                if sock is netlink:
                    forwarder.feed_kernel(netlink.recv(65536))
                else:
                    for uid, listener in forwarder.listeners.items():
                        if listener is sock:
                            forwarder._accept(sock, uid)
            forwarder.pump_once_for_test(0.0)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            netlink.send(subscription_message(False))
        except OSError:
            pass
        netlink.close()
        forwarder.close()
    return 0


def main() -> int:  # pragma: no cover - thin privileged entry
    import sys

    run_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RUN_DIR
    return run(run_dir)


if __name__ == "__main__":  # pragma: no cover - thin privileged entry
    import sys

    sys.exit(main())
