"""Process and dependency inspection: /proc, ss, podman pause links.

An edge means an OUTSIDE process depends on a MEMBER (member is the server side).
Clients of things outside the set, shared stdio, ptys and pipes are never edges.
"""
import os
import re
import subprocess

PROC = os.environ.get("TAEMA_PROCROOT", "/proc")
_USERS = re.compile(r'\("([^"]*)",pid=(\d+)')
_UNIX = re.compile(r"^(\S+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*(users:\(.*\))?\s*$")
_TCP = re.compile(r"^(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(users:\(.*\))?\s*$")


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


def starttime(pid):
    """Field 22 of /proc/PID/stat (clock ticks since boot), or None when the pid is gone."""
    data = read(pid, "stat")
    rest = data.rsplit(b")", 1)[-1].split()
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None


def ppid_map():
    """{pid: ppid} from /proc/*/stat. comm may contain spaces/parens: split after the last ')'."""
    m = {}
    for pid in all_pids():
        data = read(pid, "stat")
        if not data:
            continue
        rest = data.rsplit(b")", 1)[-1].split()
        if len(rest) > 1:
            m[pid] = int(rest[1])
    return m


def descendants(roots, pp=None):
    """roots plus every descendant, using the ppid map."""
    pp = pp if pp is not None else ppid_map()
    kids = {}
    for p, pa in pp.items():
        kids.setdefault(pa, []).append(p)
    out, stack = [], list(roots)
    seen = set()
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        stack.extend(kids.get(p, []))
    return out


def ancestors(pid, pp=None):
    pp = pp if pp is not None else ppid_map()
    out = []
    while pid in pp and pp[pid] > 0 and len(out) < 64:
        pid = pp[pid]
        out.append(pid)
    return out


def tracer(pid):
    for line in read(pid, "status").decode(errors="replace").splitlines():
        if line.startswith("TracerPid:"):
            return int(line.split()[1])
    return 0


# ---- ss parsing -------------------------------------------------------------------------

def _pids(users):
    return {int(p) for _, p in _USERS.findall(users or "")}


def parse_ss_unix(text):
    """Rows of `ss -H -xpn` / `ss -H -xlpn`: dicts with state, path, inode, peer_inode, pids."""
    rows = []
    for line in text.splitlines():
        m = _UNIX.match(line.strip())
        if not m:
            continue
        _, state, lpath, linode, _ppath, pinode, users = m.groups()
        rows.append({"state": state, "path": "" if lpath == "*" else lpath,
                     "inode": int(linode), "peer_inode": int(pinode), "pids": _pids(users)})
    return rows


def parse_ss_tcp(text):
    """Rows of `ss -H -tnp` / `ss -H -tlnp`: dicts with state, local, peer, pids."""
    rows = []
    for line in text.splitlines():
        m = _TCP.match(line.strip())
        if not m:
            continue
        state, local, peer, users = m.groups()
        rows.append({"state": state, "local": local, "peer": peer, "pids": _pids(users)})
    return rows


def _port(addr):
    return addr.rsplit(":", 1)[-1]


def _host(addr):
    return addr.rsplit(":", 1)[0].strip("[]")


def _ss(*args):
    """ss output, or None when ss failed (unknown: callers must not read it as "no sockets")."""
    try:
        r = subprocess.run(["ss", "-H"] + list(args), capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


class Snapshot:
    """One consistent view of sockets, taken once per decision pass."""

    def __init__(self, unix_text=None, tcp_text=None, tcp_listen_text=None):
        self.ok = True      # False when any ss call failed: edges are unknown, not absent
        texts = []
        for given, args in ((unix_text, "-xpn"), (tcp_text, "-tnp"), (tcp_listen_text, "-tlnp")):
            t = given if given is not None else _ss(args)
            if t is None:
                self.ok = False
                t = ""
            texts.append(t)
        self.unix = parse_ss_unix(texts[0])
        self.tcp = parse_ss_tcp(texts[1])
        self.tcp_listen = parse_ss_tcp(texts[2])
        self.by_inode = {r["inode"]: r for r in self.unix}


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
        out.setdefault(pid, []).append({"kind": kind, "detail": detail, "peers": sorted(peers)})

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
                add(pid, "unix_server", r["path"], outside)
        elif not peer["pids"]:
            # peer end not visible to this user (root process): conservative
            for pid in mine:
                add(pid, "unix_server_unresolved", r["path"], [])

    # tcp: the member LISTENs; an established connection onto that port from outside
    listen = {}
    for r in snap.tcp_listen:
        for pid in r["pids"] & members:
            listen.setdefault(_port(r["local"]), set()).add(pid)
    if listen:
        by_local = {(_host(r["local"]), _port(r["local"]), _host(r["peer"]), _port(r["peer"])): r
                    for r in snap.tcp}
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
        users = [p for p in candidates
                 if p not in members and get_comm(p) == "conmon"
                 and get_env(p).get("XDG_RUNTIME_DIR") == rd]
        if users:
            add(pid, "podman_pause", rd, users)

    # ptrace: a debugger outside the set is attached to a member
    for pid in members:
        t = get_tracer(pid)
        if t and t not in members:
            add(pid, "ptrace", "tracer %d" % t, [t])
    return out
