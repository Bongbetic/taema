"""cgroup v2 helpers for the delegated tree /sys/fs/cgroup/user/<uid>."""
import errno
import os
import re

CG = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
LEAF_PARENTS = ("shared", "leftover")   # top-level dirs holding removable leaves
_REL = re.compile(r"[a-z0-9][a-z0-9_./-]{0,96}")


def base(uid=None):
    return "%s/user/%d" % (CG, os.getuid() if uid is None else uid)


def valid_rel(rel):
    """A relative path under base(): lowercase segments, no '..', no empty segments."""
    if not _REL.fullmatch(rel):
        return False
    return all(seg and seg not in (".", "..") for seg in rel.split("/"))


def resolve(name, uid=None):
    """Map a user-given name to an existing leaf. Tries NAME, scope-NAME, app-NAME."""
    if not valid_rel(name):
        return None
    b = base(uid)
    for cand in (name, "scope-" + name, "app-" + name):
        p = "%s/%s" % (b, cand)
        if os.path.isdir(p):
            return p
    return None


def rel(path, uid=None):
    b = base(uid) + "/"
    return path[len(b):] if path.startswith(b) else path


def mkleaf(relpath, uid=None):
    if not valid_rel(relpath):
        raise ValueError("bad scope path: %r" % relpath)
    p = "%s/%s" % (base(uid), relpath)
    os.makedirs(p, exist_ok=True)
    return p


def _read_pids(path):
    try:
        with open(path + "/cgroup.procs") as f:
            return [int(x) for x in f.read().split()]
    except (FileNotFoundError, NotADirectoryError):
        return []


def procs(path):
    """PIDs directly in this cgroup."""
    return _read_pids(path)


def subdirs(path):
    try:
        return sorted(e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False))
    except FileNotFoundError:
        return []


def tree_procs(path):
    """PIDs in this cgroup and all descendants."""
    out = list(_read_pids(path))
    for d in subdirs(path):
        out.extend(tree_procs(d))
    return out


def populated(path):
    try:
        with open(path + "/cgroup.events") as f:
            return "populated 1" in f.read()
    except FileNotFoundError:
        return False


def memory_current(path):
    """memory.current in bytes, or None when the memory controller or file is unreadable."""
    try:
        with open(path + "/memory.current") as f:
            return int(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def memory_psi(path):
    """'some avg10=' from memory.pressure (recent memory pressure, 0-100), or None when the
    file is unreadable or has no 'some' line."""
    try:
        with open(path + "/memory.pressure") as f:
            for line in f:
                if line.startswith("some "):
                    for tok in line.split():
                        if tok.startswith("avg10="):
                            return float(tok.split("=", 1)[1])
    except (OSError, ValueError):
        return None
    return None


def kill_tree(path):
    """cgroup.kill: SIGKILL every process in path and its descendants."""
    with open(path + "/cgroup.kill", "w") as f:
        f.write("1\n")


def move(pid, dest):
    """Write pid into dest/cgroup.procs. Returns True, or False if the pid is gone."""
    try:
        with open(dest + "/cgroup.procs", "w") as f:
            f.write("%d\n" % pid)
        return True
    except OSError as e:
        if e.errno in (errno.ESRCH, errno.ENOENT):
            return False
        raise


def rmdir_tree(path):
    """Remove path and empty descendants, bottom-up. Raises OSError if a leaf is busy."""
    for d in subdirs(path):
        rmdir_tree(d)
    os.rmdir(path)


def proc_cgroup(pid):
    """The cgroup v2 path of a pid ('/2', '/user/1000/scope-x'), or None."""
    try:
        with open("%s/%d/cgroup" % (os.environ.get("TAEMA_PROCROOT", "/proc"), pid)) as f:
            for line in f:
                if line.startswith("0::"):
                    return line[3:].strip()
    except OSError:
        pass
    return None


def is_prefix(target_path, cgroup_line):
    """True when cgroup_line (as read from /proc, e.g. /user/1000/app-x/session-1) is the
    target (absolute filesystem path) or lies below it."""
    t = target_path[len(CG):] if target_path.startswith(CG) else target_path
    t = t.rstrip("/")
    c = (cgroup_line or "").rstrip("/")
    return c == t or c.startswith(t + "/")


def own_cgroup():
    return proc_cgroup(os.getpid())
