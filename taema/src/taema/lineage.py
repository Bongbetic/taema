"""Lineage: who started what, for live processes only.

Fed one ProcTable per adopt pass. Keeps, per live (pid, start): its own key, the key of its root,
parent and ancestor keys, the shell job tag (TAEMA_JOB), pgrp/sid and pty-host status. Nothing
here kills or moves anything; the daemon asks it questions (root_for, job_of, leftovers_of).

GUI root rule (see the plan): a root is a non-session-leader whose parent is owned by the user and
is not itself inside a root; children inherit it. A ppid-1 newcomer within 2 s of a root's birth
joins that root (co-birth). Nothing younger than 5 s has a root. A root that exits within 5 s
re-roots to its oldest live member (wrappers, AppImage); a survivor with the root's own exe/key is
a self-update relaunch and re-roots too. Anything else that outlives its root is a leftover.
"""
import fnmatch
import os
import re
import time

from . import inspect, policy

MIN_AGE = 5.0           # nothing younger than this has a root
COBIRTH = 2.0           # ppid-1 newcomer within this many seconds of a root's birth joins it
NEWCOMER_MAX = 30.0     # only processes this young can co-birth
KEY_SETTLE = 10.0       # re-derive the key while exec may still be in flight
JOB_WINDOW = 120.0      # environ is searched for the job tag only for processes this young
MAX_ENTRIES = 4096
MAX_JOBS = 64
MAX_GHOSTS = 256
CPU_KEEP = 12          # cpu samples kept per entry
CPU_WINDOW = 60.0       # cpu_pct looks at the last minute
CPU_MIN_SPAN = 30.0     # less history than this means unknown
GHOST_TTL = 3600.0
CHAIN = 8
ENV_LIMIT = 1 << 18
FD_LIMIT = 1024
HZ = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_TAG = re.compile(r"[0-9]+\.[0-9]+")
_NEEDLE = b"\0TAEMA_JOB="
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(s, n=64):
    """Printable text: control characters stripped, length capped."""
    return _CTRL.sub("", str(s))[:n]


def _uptime():
    try:
        with open(inspect.PROC + "/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def find_tag(pid):
    """TAEMA_JOB value from /proc/PID/environ by byte search (no env dict is ever built), or None."""
    try:
        with open("%s/%d/environ" % (inspect.PROC, pid), "rb") as f:
            data = f.read(ENV_LIMIT)
    except OSError:
        return None
    i = -1
    if data.startswith(b"TAEMA_JOB="):
        i = len(b"TAEMA_JOB=")
    else:
        j = data.find(_NEEDLE)
        if j >= 0:
            i = j + len(_NEEDLE)
    if i < 0:
        return None
    tag = data[i:data.find(b"\0", i) if data.find(b"\0", i) >= 0 else len(data)][:48].decode(errors="replace")
    return tag if _TAG.fullmatch(tag) else None


class Lineage:
    def __init__(self, cfg, uid=None):
        self.cfg = cfg
        self.uid = os.getuid() if uid is None else uid
        self.entries = {}       # (pid, start) -> entry dict
        self.by_pid = {}        # pid -> (pid, start)
        self.foreign = set()    # (pid, start) of processes of other users (not tracked)
        self.ghosts = {}        # exited root id -> {"key", "pid", "ppid", "exited"}
        self.jobs = {}          # tag -> {"first": wall birth of its oldest process, "root_key", "seen"}
        self.closed = []        # root ids that exited with live members during the last observe
        self.reroots = []       # (old root id, new root id) during the last observe
        self.born = []          # ids first seen during the last observe
        self._vanished = []
        self.now = time.time()
        self.up = None
        self.gen = 0
        self._unix = (None, {})
        self.overflow = 0

    # ---- time ----
    def _birth(self, e):
        """Wall-clock birth of an entry; first_seen when uptime or starttime is unknown."""
        if self.up is not None and e["start"] > 0:
            return self.now - (self.up - e["start"] / HZ)
        return e["first_seen"]

    def age(self, e):
        return self.now - self._birth(e)

    # ---- observe ----
    def observe(self, table, now=None, uptime=None):
        self.now = time.time() if now is None else now
        self.up = uptime if uptime is not None else _uptime()
        self.gen += 1
        rows = {p: r for p, r in table.rows.items() if r.state != "Z"}
        self._vanished, self.closed, self.reroots, self.born = [], [], [], []
        gone = [eid for eid in self.entries if rows.get(eid[0]) is None or rows[eid[0]].start != eid[1]]
        gone_entries = []
        for eid in gone:
            e = self.entries.pop(eid)
            if self.by_pid.get(eid[0]) == eid:
                del self.by_pid[eid[0]]
            gone_entries.append((eid, e))
            self._vanished.append(self._record(eid, e))
        self.foreign = {k for k in self.foreign if rows.get(k[0]) is not None and rows[k[0]].start == k[1]}
        for eid, e in self.entries.items():
            r = rows[eid[0]]
            e.update(ppid=r.ppid, pgrp=r.pgrp, sid=r.sid, tty=r.tty, state=r.state, last_seen=self.now)
            e["seen"] += 1
            e["cpu"] = (e["cpu"] + [(self.now, r.cpu)])[-CPU_KEEP:]
            if e["start"] and self.age(e) < KEY_SETTLE:
                e["key"] = policy.app_key(eid[0])
        for e in self.entries.values():     # a root's key may have settled after its members were added
            root = self.entries.get(e["root"]) if e["root"] else None
            if root is not None:
                e["root_key"] = root["key"]
        new = sorted((p for p in rows if (p, rows[p].start) not in self.entries
                      and (p, rows[p].start) not in self.foreign), key=lambda p: (rows[p].start, p))
        for pid in new:
            r = rows[pid]
            if inspect.uid_of(pid) != self.uid:
                self.foreign.add((pid, r.start))
            elif len(self.entries) >= MAX_ENTRIES:
                self.overflow += 1
            else:
                self._add(pid, r)
        for eid, e in gone_entries:
            if e["root"] == eid:
                self._root_exit(eid, e)
        self._prune_ghosts()
        return self

    def _record(self, eid, e):
        return {"pid": eid[0], "start": eid[1], "key": e["key"], "root_key": e["root_key"],
                "root": e["root"][0] if e["root"] else None, "parent_key": e["parent_key"],
                "job": e["job"], "chain": list(e["chain"])}

    def _add(self, pid, r):
        key = policy.app_key(pid)
        e = {"pid": pid, "start": r.start, "ppid": r.ppid, "pgrp": r.pgrp, "sid": r.sid, "tty": r.tty,
             "state": r.state, "cpu": [(self.now, r.cpu)], "key": key, "exe": os.path.basename(inspect.exe(pid)),
             "first_seen": self.now, "last_seen": self.now, "seen": 1, "job": None, "host": None, "root": None, "root_key": "",
             "parent_key": "", "chain": [], "chain_ids": []}
        eid = (pid, r.start)
        pe = self.entries.get(self.by_pid.get(r.ppid))
        if pe is not None:
            e["parent_key"] = pe["key"]
        anc, cur = [], pe
        while cur is not None and len(anc) < CHAIN:
            anc.append(cur)
            cur = self.entries.get(self.by_pid.get(cur["ppid"]))
        e["chain"] = [a["key"] for a in anc]
        e["chain_ids"] = [(a["pid"], a["start"]) for a in anc]
        self.entries[eid] = e
        self.by_pid[pid] = eid
        self.born.append(eid)
        if self.age(e) <= JOB_WINDOW:
            tag = find_tag(pid)
            if tag:
                e["job"] = tag
                self._note_job(e, tag)
        self._assign(eid, e, r, pe)

    def _note_job(self, e, tag):
        j = self.jobs.setdefault(tag, {"first": self._birth(e), "root_key": None, "seen": self.now})
        j["first"] = min(j["first"], self._birth(e))
        j["seen"] = self.now
        if j["root_key"] is None and e["ppid"] == int(tag.split(".")[0]):
            j["root_key"] = e["key"]
        if len(self.jobs) > MAX_JOBS:
            del self.jobs[min(self.jobs, key=lambda t: self.jobs[t]["seen"])]

    def _assign(self, eid, e, r, pe):
        if r.sid == eid[0]:         # session leader: never a root, never inside one
            return
        if pe is not None:
            if pe["root"] is not None:
                self._join(e, pe["root"], pe["root_key"])
            elif not policy.protected_reason(eid[0], self.cfg):
                e["host"] = self._scan_ptmx(eid[0])
                self._join(e, eid, e["key"])
            return
        if r.ppid <= 1 and self.up is not None and self.age(e) <= NEWCOMER_MAX:
            best = None
            for rid, root in self.entries.items():
                if root["root"] == rid and rid != eid:
                    dt = self._birth(e) - self._birth(root)
                    if 0 <= dt <= COBIRTH and (best is None or dt < best[0]):
                        best = (dt, rid, root)
            if best:
                self._join(e, best[1], best[2]["key"])

    def _join(self, e, rid, rkey):
        e["root"], e["root_key"] = rid, rkey

    def _root_exit(self, rid, e):
        members = [m for m in self.entries.values() if m["root"] == rid]
        if not members:
            return
        # young: seen alive only while under 5 s old (once, or again within 5 s) and then gone
        lived = e["last_seen"] - self._birth(e)
        young = lived < MIN_AGE and (e["seen"] == 1 or self.now - e["last_seen"] < MIN_AGE)
        same = [m for m in members if m["key"] == e["key"] or (m["exe"] and m["exe"] == e["exe"])]
        pick = members if young else same
        if pick:
            new = min(pick, key=lambda m: (m["start"], m["pid"]))
            nid = (new["pid"], new["start"])
            for m in members:
                self._join(m, nid, new["key"])
            self.reroots.append((rid, nid))
            return
        self.ghosts[rid] = {"key": e["key"], "pid": rid[0], "ppid": e["ppid"], "exited": self.now,
                            "terminal": self.is_terminal_job(e)}
        self.closed.append(rid)

    def _prune_ghosts(self):
        live = {m["root"] for m in self.entries.values() if m["root"] is not None}
        for rid in [g for g, v in self.ghosts.items() if g not in live or self.now - v["exited"] > GHOST_TTL]:
            del self.ghosts[rid]
        while len(self.ghosts) > MAX_GHOSTS:
            del self.ghosts[min(self.ghosts, key=lambda g: self.ghosts[g]["exited"])]

    # ---- queries ----
    def entry(self, pid):
        return self.entries.get(self.by_pid.get(pid))

    def vanished(self):
        """Pids that disappeared in the last observe, with their recorded key, root and parent."""
        return list(self._vanished)

    def job_of(self, pid):
        """Job identity: the TAEMA_JOB tag (only found for young processes), else 'pg:<pgrp>' when
        a tagged process shares the group, else 'sid:<sid>'; None for unknown pids."""
        e = self.entry(pid)
        if e is None:
            return None
        if e["job"]:
            return e["job"]
        for o in self.entries.values():
            if o["job"] and o["pgrp"] == e["pgrp"] and e["pgrp"] > 1:
                return o["job"]
        return "sid:%d" % e["sid"] if e["sid"] > 1 else None

    def job_members(self, tag):
        """Live entries of a job: tagged, plus anything in the pgrp of a tagged process."""
        tagged = [e for e in self.entries.values() if e["job"] == tag]
        groups = {e["pgrp"] for e in tagged if e["pgrp"] > 1}
        out = {(e["pid"], e["start"]): e for e in tagged}
        for k, e in self.entries.items():
            if e["pgrp"] in groups and e["job"] is None:
                out[k] = e
        return list(out.values())

    def job_info(self, tag):
        return self.jobs.get(tag)

    def root_for(self, pid):
        """Root pid of pid's app, or None (unrooted, session leader, or younger than 5 s)."""
        e = self.entry(pid)
        if e is None or e["root"] is None or e["sid"] == pid or self.age(e) < MIN_AGE:
            return None
        root = self.entries.get(e["root"])
        if root is not None and self.age(root) < MIN_AGE:
            return None
        return e["root"][0]

    def is_terminal_job(self, e):
        """True for a process that belongs to a shell job: tagged, on a tty, or below an
        interactive shell (session leader with a tty). GUI apps have none of these."""
        if e["job"] or e["tty"]:
            return True
        for cid in e["chain_ids"]:
            a = self.entries.get(cid)
            if a is not None and a["tty"] and a["sid"] == a["pid"]:
                return True
        return False

    def cpu_pct(self, pid, window=CPU_WINDOW, min_span=CPU_MIN_SPAN):
        """Average CPU percent of pid over the last `window` seconds from per-pass /proc stat
        samples; None (unknown) when less than `min_span` seconds of history exist."""
        e = self.entry(pid)
        cs = e.get("cpu") if e else None
        if not cs or len(cs) < 2:
            return None
        t1, c1 = cs[-1]
        t0, c0 = next(((t, c) for t, c in cs if t1 - t <= window + 2.0), (t1, c1))   # 2 s slack for pass jitter
        if t1 - t0 < min_span:
            return None
        return 100.0 * max(0, c1 - c0) / HZ / (t1 - t0)

    # ---- hosts ----
    def _scan_ptmx(self, pid):
        try:
            names = os.listdir("%s/%d/fd" % (inspect.PROC, pid))[:FD_LIMIT]
        except OSError:
            return False
        for n in names:
            try:
                t = os.readlink("%s/%d/fd/%s" % (inspect.PROC, pid, n))
            except OSError:
                continue
            if t == "/dev/ptmx" or t.endswith("/pts/ptmx"):
                return True
        return False

    def ptmx_host(self, pid):
        """True when pid holds /dev/ptmx (terminal emulator, multiplexer, pty host). Cached per (pid, start)."""
        e = self.entry(pid)
        if e is None:
            return False
        if e["host"] is None:
            e["host"] = self._scan_ptmx(pid)
        return e["host"]

    def _listeners(self):
        if self._unix[0] != self.gen:
            m = {}
            try:
                with open(inspect.PROC + "/net/unix") as f:
                    next(f, None)
                    for line in f:
                        p = line.split()
                        if len(p) >= 8 and int(p[3], 16) & 0x10000:
                            m[p[6]] = p[7]
            except (OSError, ValueError):
                pass
            self._unix = (self.gen, m)
        return self._unix[1]

    def holds_runtime_listener(self, pid):
        """True when pid listens on a unix socket under XDG_RUNTIME_DIR, GNUPGHOME or /tmp/*-<uid>
        (gpg-agent, keyboxd, ssh ControlMaster, sccache, Gradle): never asked about."""
        lst = self._listeners()
        if not lst:
            return False
        roots = [os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % self.uid,
                 os.environ.get("GNUPGHOME") or os.path.expanduser("~/.gnupg")]
        try:
            names = os.listdir("%s/%d/fd" % (inspect.PROC, pid))[:FD_LIMIT]
        except OSError:
            return False
        for n in names:
            try:
                t = os.readlink("%s/%d/fd/%s" % (inspect.PROC, pid, n))
            except OSError:
                continue
            if t.startswith("socket:["):
                path = lst.get(t[8:-1])
                if path and (any(path.startswith(r.rstrip("/") + "/") for r in roots)
                             or fnmatch.fnmatchcase(path, "/tmp/*-%d/*" % self.uid)):
                    return True
        return False

    # ---- leftovers ----
    def _seeded(self, e):
        seeds = self.cfg.get("seeds", {})
        held = set(seeds.get("share", [])) | set(seeds.get("persist", []))
        return e["key"] in held or e["exe"] in held

    def _root_id(self, pid):
        eid = self.by_pid.get(pid)
        if eid is not None:
            return eid
        return next((g for g in self.ghosts if g[0] == pid), None)

    def leftovers_of(self, job_or_root):
        """Survivors of a closed job (tag string) or exited root (pid): live, not zombies, not
        children of the live shell, not share/persist seeds, protected, pty hosts, or runtime-socket
        daemons. Returns [{"pid","start","key","comm","ppid","root_key","chain"}]."""
        if isinstance(job_or_root, str):
            members = self.job_members(job_or_root)
            try:
                shell = int(job_or_root.split(".")[0])
            except ValueError:
                shell = 0
        else:
            rid = self._root_id(job_or_root)
            members = [e for e in self.entries.values() if rid is not None and e["root"] == rid
                       and (e["pid"], e["start"]) != rid]
            g = self.ghosts.get(rid) or self.entry(job_or_root)
            shell = g["ppid"] if g else 0
            se = self.entry(shell)
            if se is None or se["sid"] != shell:
                shell = 0       # only an interactive shell (session leader) exempts its children
        out = []
        for e in sorted(members, key=lambda m: (m["start"], m["pid"])):
            pid = e["pid"]
            if e["state"] == "Z" or pid == shell:
                continue
            if shell and e["ppid"] == shell and self.entry(shell) is not None:
                continue
            if self._seeded(e) or policy.protected_reason(pid, self.cfg) or self.ptmx_host(pid):
                continue
            if e["sid"] == pid and e["tty"] == 0 and self.holds_runtime_listener(pid):
                continue
            out.append({"pid": pid, "start": e["start"], "key": e["key"], "comm": clean(inspect.comm(pid), 32),
                        "ppid": e["ppid"], "root_key": e["root_key"], "chain": list(e["chain"]),
                        "chain_ids": list(e["chain_ids"])})
        return out
