"""Process and dependency inspection: /proc, ss, podman pause links.

An edge means an OUTSIDE process depends on a MEMBER (member is the server side).
Clients of things outside the set, shared stdio, ptys and pipes are never edges.
"""

from collections import namedtuple
import os
import re


class _LazySubprocess:
    def __getattr__(self, name):
        import subprocess as module

        return getattr(module, name)


# Preserve the patchable module seam without importing subprocess during startup.
subprocess = _LazySubprocess()

PROC = os.environ.get("TAEMA_PROCROOT", "/proc")
MAX_RESTORE_ARGV_BYTES = 16 << 10
_USERS = re.compile(r'\("([^"]*)",pid=(\d+)')
_UNIX = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)")
_TCP = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)")
_INODE = re.compile(r"\bino:(\d+)\b")


# ---- /proc ----------------------------------------------------------------------------


def all_pids():
    return [int(x) for x in os.listdir(PROC) if x.isdigit()]


def read(pid, name):
    try:
        with open("%s/%d/%s" % (PROC, pid, name), "rb") as f:
            return f.read()
    except OSError:
        return b""


def comm(pid):
    return read(pid, "comm").decode(errors="replace").strip()


def exe(pid):
    try:
        return os.readlink("%s/%d/exe" % (PROC, pid)).replace(" (deleted)", "")
    except OSError:
        return ""


def cmdline(pid):
    return read(pid, "cmdline").replace(b"\0", b" ").decode(errors="replace").strip()


def argv(pid):
    """Return a process's NUL-separated argument vector without shell parsing."""
    return [
        item.decode(errors="replace")
        for item in read(pid, "cmdline").split(b"\0")
        if item
    ]


def runtime_identity(pid):
    """Return runtime identifiers exposed by conmon or QEMU argv."""
    process_name = comm(pid)
    args = argv(pid)
    identity = {}
    if process_name == "conmon":
        for index, arg in enumerate(args[:-1]):
            if arg in ("-c", "--cid", "--container-id"):
                identity["container"] = args[index + 1]
                break
    elif process_name.startswith("qemu-system"):
        for index, arg in enumerate(args):
            if arg.startswith("-name="):
                value = arg.partition("=")[2]
            elif arg == "-name" and index + 1 < len(args):
                value = args[index + 1]
            else:
                continue
            domain = re.search(r"(?:^|,)guest=([^,]+)", value)
            identity["domain"] = (domain.group(1) if domain else value).split(",", 1)[0]
            break
    return identity


def qmp_socket_paths(pid):
    """Unix QMP/monitor socket paths declared in a QEMU process argument vector."""
    args = argv(pid)
    found = []
    chardev_paths = {}
    control_ids = set()

    def record_monitor_option(option, value):
        settings = dict(item.split("=", 1) for item in value.split(",") if "=" in item)
        if option == "-chardev":
            path = settings.get("path")
            if (
                value.partition(",")[0] == "socket"
                and settings.get("id")
                and isinstance(path, str)
                and path.startswith("/")
            ):
                chardev_paths[settings["id"]] = path
        elif settings.get("mode") == "control" and settings.get("chardev"):
            control_ids.add(settings["chardev"])

    index = 0
    while index < len(args):
        value = args[index]
        if value in ("-qmp", "-monitor") and index + 1 < len(args):
            value = args[index + 1]
            index += 1
        elif value.startswith(("-qmp=", "-monitor=")):
            value = value.partition("=")[2]
        elif value in ("-chardev", "-mon") and index + 1 < len(args):
            option = value
            value = args[index + 1]
            index += 1
            record_monitor_option(option, value)
            index += 1
            continue
        elif value.startswith(("-chardev=", "-mon=")):
            option, value = value.split("=", 1)
            record_monitor_option(option, value)
            index += 1
            continue
        else:
            index += 1
            continue
        if value.startswith("unix:"):
            path = value[5:].split(",", 1)[0]
            if path.startswith("/") and path not in found:
                found.append(path)
        index += 1
    for chardev_id in control_ids:
        path = chardev_paths.get(chardev_id)
        if path and path not in found:
            found.append(path)
    return found


def restore_command(pid):
    """Capture only argv and cwd for an explicitly opted-in, still-live process."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return None
    start = starttime(pid)
    raw = read(pid, "cmdline")
    if start is None or not raw or len(raw) > MAX_RESTORE_ARGV_BYTES:
        return None
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if not parts or not parts[0]:
        return None
    argv = [part.decode(errors="surrogateescape") for part in parts]
    try:
        cwd = os.readlink("%s/%d/cwd" % (PROC, pid))
    except OSError:
        return None
    if not cwd or not os.path.isabs(cwd) or len(cwd) > 4096:
        return None
    if starttime(pid) != start:
        return None
    return {"pid": pid, "start": start, "argv": argv, "cwd": cwd}


def restore_environment(environ):
    """Build the documented restore environment without inheriting app or daemon secrets."""
    return {
        key: value
        for key, value in environ.items()
        if isinstance(key, str)
        and isinstance(value, str)
        and (key in ("PATH", "HOME", "LANG") or key.startswith(("LC_", "XDG_")))
    }


def environ(pid):
    out = {}
    for item in read(pid, "environ").split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            out[k.decode(errors="replace")] = v.decode(errors="replace")
    return out


def uid_of(pid):
    try:
        return os.stat("%s/%d" % (PROC, pid)).st_uid
    except OSError:
        return -1


def is_kernel_thread(pid):
    return not exe(pid) and not cmdline(pid)


def unix_socket_paths(pid, limit=1024):
    """Bounded Unix socket paths owned by pid, from /proc only (no `ss` or runtime CLI)."""
    try:
        with open(PROC + "/net/unix", encoding="utf-8", errors="replace") as source:
            rows = source.read().splitlines()[1:]
    except OSError:
        return []
    paths = {}
    for row in rows:
        fields = row.split(None, 7)
        if len(fields) == 8:
            paths[fields[6]] = fields[7]
    try:
        descriptors = os.listdir("%s/%d/fd" % (PROC, pid))[:limit]
    except OSError:
        return []
    found = set()
    for descriptor in descriptors:
        try:
            target = os.readlink("%s/%d/fd/%s" % (PROC, pid, descriptor))
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            path = paths.get(target[8:-1])
            if path:
                found.add(path)
    return sorted(found)


def starttime(pid):
    """Field 22 of /proc/PID/stat (clock ticks since boot), or None when the pid is gone."""
    data = read(pid, "stat")
    rest = data.rsplit(b")", 1)[-1].split()
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None


class Proc(namedtuple("Proc", "ppid pgrp sid tty start state cpu", defaults=(0,))):
    __slots__ = ()


def _parse_stat(data):
    """Proc from /proc/PID/stat bytes, or None. comm may hold spaces/parens: split after the last ')'."""
    rest = data.rsplit(b")", 1)[-1].split()
    if len(rest) < 2:
        return None
    try:
        ints = [int(x) for x in rest[1:5]]
        ints += [0] * (4 - len(ints))
        start = int(rest[19]) if len(rest) > 19 else 0
        cpu = (
            int(rest[11]) + int(rest[12]) if len(rest) > 12 else 0
        )  # utime + stime, clock ticks
        return Proc(
            ints[0],
            ints[1],
            ints[2],
            ints[3],
            start,
            rest[0].decode(errors="replace"),
            cpu,
        )
    except ValueError:
        return None


class ProcTable:
    """One snapshot of /proc/*/stat (zombies skipped), built once per pass and shared."""

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else {}
        self.ppid = {p: r.ppid for p, r in self.rows.items()}
        self._kids = None

    @classmethod
    def scan(cls):
        rows = {}
        for pid in all_pids():
            r = _parse_stat(read(pid, "stat"))
            if r is not None and r.state != "Z":
                rows[pid] = r
        return cls(rows)

    @classmethod
    def from_ppid(cls, pp):
        """Table from a bare {pid: ppid} map (tests, compatibility)."""
        return cls({p: Proc(pa, p, p, 0, 0, "S") for p, pa in pp.items()})

    def kids(self):
        if self._kids is None:
            self._kids = {}
            for p, pa in self.ppid.items():
                self._kids.setdefault(pa, []).append(p)
        return self._kids

    def descendants(self, roots):
        out, stack, seen = [], list(roots), set()
        kids = self.kids()
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
            stack.extend(kids.get(p, []))
        return out

    def ancestors(self, pid):
        out, pp = [], self.ppid
        while pid in pp and pp[pid] > 0 and len(out) < 64:
            pid = pp[pid]
            out.append(pid)
        return out


def _table(pp):
    if isinstance(pp, ProcTable):
        return pp
    return ProcTable.from_ppid(pp) if pp is not None else ProcTable.scan()


def ppid_map():
    """{pid: ppid} from /proc/*/stat (thin wrapper over ProcTable)."""
    return dict(ProcTable.scan().ppid)


def descendants(roots, pp=None):
    """roots plus every descendant. pp: a ProcTable, a {pid: ppid} map, or None (scan now)."""
    return _table(pp).descendants(roots)


def ancestors(pid, pp=None):
    return _table(pp).ancestors(pid)


def tracer(pid):
    for line in read(pid, "status").decode(errors="replace").splitlines():
        if line.startswith("TracerPid:"):
            return int(line.split()[1])
    return 0


# ---- ss parsing -------------------------------------------------------------------------


def _pids(users):
    return {int(p) for _, p in _USERS.findall(users or "")}


def parse_ss_unix(text):
    """Rows of `ss -H -xpn` / `ss -H -xlpn` with local and peer socket facts."""
    rows = []
    for line in text.splitlines():
        m = _UNIX.match(line.strip())
        if not m:
            continue
        _, state, recv_q, send_q, lpath, linode, _ppath, pinode = m.groups()
        rows.append(
            {
                "state": state,
                "recv_q": int(recv_q),
                "send_q": int(send_q),
                "path": "" if lpath == "*" else lpath,
                "peer_path": "" if _ppath == "*" else _ppath,
                # `ino:` in extended ss output is the filesystem node inode for
                # pathname sockets; the local column is the socket inode used by /proc.
                "inode": int(linode),
                "peer_inode": int(pinode),
                "pids": _pids(line),
            }
        )
    return rows


def parse_ss_tcp(text):
    """Rows of `ss -H -tnp` / `ss -H -tlnp`: dicts with state, local, peer, pids."""
    rows = []
    for line in text.splitlines():
        m = _TCP.match(line.strip())
        if not m:
            continue
        state, recv_q, send_q, local, peer = m.groups()
        row = {
            "state": state,
            "recv_q": int(recv_q),
            "send_q": int(send_q),
            "local": local,
            "peer": peer,
            "pids": _pids(line),
        }
        inode = _INODE.search(line)
        if inode:
            row["inode"] = int(inode.group(1))
        rows.append(row)
    return rows


def _port(addr):
    return addr.rsplit(":", 1)[-1]


def _host(addr):
    return addr.rsplit(":", 1)[0].strip("[]")


def _ss(*args):
    """ss output, or None when ss failed (unknown: callers must not read it as "no sockets")."""
    try:
        r = subprocess.run(
            ["ss", "-H"] + list(args), capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


class Snapshot:
    """One consistent view of sockets, taken once per decision pass: three ss runs
    (`-xapne`, `-tanpe`, `-uanpe`); listening tcp rows are split out by state."""

    def __init__(
        self, unix_text=None, tcp_text=None, tcp_listen_text=None, udp_text=None
    ):
        self.ok = True  # False when any ss call failed: edges are unknown, not absent

        def get(given, args):
            t = given if given is not None else _ss(*args)
            if t is None:
                self.ok = False
                return ""
            return t

        self.unix = parse_ss_unix(get(unix_text, ("-xapne",)))
        if tcp_text is None and tcp_listen_text is None:
            rows = parse_ss_tcp(get(None, ("-tanpe",)))
            self.tcp = [r for r in rows if r["state"] != "LISTEN"]
            self.tcp_listen = [r for r in rows if r["state"] == "LISTEN"]
            self.udp = parse_ss_tcp(get(udp_text, ("-uanpe",)))
        else:
            self.tcp = parse_ss_tcp(get(tcp_text, ("-tnp",)))
            self.tcp_listen = parse_ss_tcp(get(tcp_listen_text, ("-tlnp",)))
            self.udp = parse_ss_tcp(udp_text or "")
        self.by_inode = {r["inode"]: r for r in self.unix}
        self.socket_inodes = {
            row["inode"]
            for row in (*self.unix, *self.tcp, *self.tcp_listen, *self.udp)
            if isinstance(row.get("inode"), int)
        }


class LazySnapshot:
    """Builds the Snapshot on first use; one instance is shared by every pass of a decision."""

    def __init__(self):
        self._snap = None

    def get(self):
        if self._snap is None:
            self._snap = Snapshot()
        return self._snap

    @property
    def built(self):
        return self._snap is not None


LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def edges(members, snap=None, pids_info=None):
    """Dependency edges from outside processes onto `members` (a set of pids).

    Returns {member_pid: [edge, ...]} with edge = {"kind", "detail", "peers"}.
    `pids_info` is for tests: {"environ": {pid: {...}}, "comm": {pid: str}, "tracer": {pid: int}}.
    """
    members = set(members)
    snap = snap or Snapshot()
    info = pids_info or {}
    get_env = (lambda p: info["environ"].get(p, {})) if "environ" in info else environ
    get_comm = (lambda p: info["comm"].get(p, "")) if "comm" in info else comm
    get_tracer = (lambda p: info["tracer"].get(p, 0)) if "tracer" in info else tracer
    out = {}

    def add(pid, kind, detail, peers):
        out.setdefault(pid, []).append(
            {"kind": kind, "detail": detail, "peers": sorted(peers)}
        )

    def unix_kind(path, unresolved=False):
        normalized = path.lower().replace("\\", "/")
        if path in qmp_paths:
            return "qmp"
        if "podman.sock" in normalized or "/podman/" in normalized:
            return "podman_api"
        if normalized.endswith("/docker.sock") or "/docker/" in normalized:
            return "docker_api"
        if normalized.endswith("/incus.sock") or "/incus/" in normalized:
            return "incus_api"
        if normalized.startswith("@lxc/") or (
            normalized.startswith("@/")
            and "/lxc/" in normalized
            and normalized.endswith("/command")
        ):
            return "lxc_api"
        if "/.vbox-" in normalized and normalized.endswith("/ipcd"):
            return "vboxsvc"
        if "/libvirt/qemu/" in normalized or "/qmp" in normalized:
            return "qmp"
        return "unix_server_unresolved" if unresolved else "unix_server"

    qmp_paths = {
        path
        for pid in members
        if get_comm(pid).startswith("qemu-system")
        for path in qmp_socket_paths(pid)
    }

    # unix: the member holds the server-side end (that end carries the bound path)
    for r in snap.unix:
        mine = r["pids"] & members
        if not mine or not r["path"] or r["state"] == "LISTEN":
            continue
        peer = snap.by_inode.get(r["peer_inode"])
        if peer is None:
            continue
        outside = peer["pids"] - members
        if outside:
            for pid in mine:
                add(pid, unix_kind(r["path"]), r["path"], outside)
        elif not peer["pids"]:
            # peer end not visible to this user (root process): conservative
            for pid in mine:
                add(pid, unix_kind(r["path"], unresolved=True), r["path"], [])

    # Rootless Podman's API service lives outside the container scope. Associate its
    # connected socket peers with the catatonit scope that shares its runtime directory.
    podman_members = {}
    for pid in members:
        if get_comm(pid) != "catatonit":
            continue
        runtime_dir = get_env(pid).get("XDG_RUNTIME_DIR")
        if isinstance(runtime_dir, str) and runtime_dir:
            socket_path = os.path.join(runtime_dir, "podman", "podman.sock")
            podman_members.setdefault(socket_path, set()).add(pid)
    for row in snap.unix:
        path = row["path"]
        scoped_members = podman_members.get(path)
        if not scoped_members or row["state"] == "LISTEN":
            continue
        # A member-owned server was handled by the ordinary Unix edge scan above.
        if row["pids"] & members:
            continue
        peer = snap.by_inode.get(row["peer_inode"])
        if peer is None:
            continue
        clients = peer["pids"] - members - row["pids"]
        if clients:
            for pid in scoped_members:
                add(pid, "podman_api", path, clients)
        elif not peer["pids"]:
            for pid in scoped_members:
                add(pid, "podman_api", path, [])

    # tcp: the member LISTENs; an established connection onto that port from outside
    listen = {}
    for r in snap.tcp_listen:
        for pid in r["pids"] & members:
            listen.setdefault(_port(r["local"]), set()).add(pid)
    if listen:
        by_local = {
            (
                _host(r["local"]),
                _port(r["local"]),
                _host(r["peer"]),
                _port(r["peer"]),
            ): r
            for r in snap.tcp
        }
        for r in snap.tcp:
            port = _port(r["local"])
            if port not in listen or r["state"] != "ESTAB":
                continue
            peer_host, peer_port = _host(r["peer"]), _port(r["peer"])
            rev = None
            if peer_host in LOOPBACK:
                rev = by_local.get((peer_host, peer_port, _host(r["local"]), port))
                if rev and rev["pids"] and rev["pids"] <= members:
                    continue
            peers = (rev["pids"] - members) if rev else set()
            for pid in listen[port]:
                add(pid, "tcp_server", r["local"] + " <- " + r["peer"], peers)

    # podman: a conmon outside the set that uses a pause process inside it
    for pid in members:
        if get_comm(pid) != "catatonit":
            continue
        rd = get_env(pid).get("XDG_RUNTIME_DIR")
        if not rd:
            continue
        candidates = info["comm"].keys() if "comm" in info else all_pids()
        users = [
            p
            for p in candidates
            if p not in members
            and get_comm(p) == "conmon"
            and get_env(p).get("XDG_RUNTIME_DIR") == rd
        ]
        if users:
            add(pid, "podman_pause", rd, users)

    # ptrace: a debugger outside the set is attached to a member
    for pid in members:
        t = get_tracer(pid)
        if t and t not in members:
            add(pid, "ptrace", "tracer %d" % t, [t])
    return out
