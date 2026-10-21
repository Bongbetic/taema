#!/usr/bin/python3 -I
"""taema-attach: the one privileged step of taema. Run as root through sudo.

    taema-attach attach PID NAME           move PID into /sys/fs/cgroup/user/<uid>/scope-NAME
    taema-attach move RELPATH PID...       move PIDs into /sys/fs/cgroup/user/<uid>/RELPATH
    taema-attach oom-record PID START ORIGINAL APPLIED
    taema-attach oom-restore PID START ORIGINAL APPLIED restore one caller-owned process priority

An unprivileged process cannot move a task out of its login-session cgroup: the lowest
common ancestor of the source and the destination is the root cgroup. This helper does only
that move, only for the calling user's own processes, and logs every move.

It reads only the root-owned /etc/taema/taema.toml for its hard rules ([protected]) and keeps
OOM restoration records in a private root-owned directory under /run. User configuration is
never consulted. It imports nothing outside the standard library.
"""

import fnmatch
import fcntl
import json
import os
import re
import select
import stat
import sys
import time
import tomllib

CG = "/sys/fs/cgroup"
CONFIG = "/etc/taema/taema.toml"
LOG = "/var/log/taema/attach.log"
OOM_STATE_DIR = "/run/taema-oom"
OOM_RECORD_LIMIT = 4096
OOM_STATE_MAX = 4096
OOM_MIN = -1000
OOM_MAX = 1000
REL = re.compile(r"[a-z0-9][a-z0-9_./-]{0,96}")
NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
# Allowed source cgroups: a login session (elogind names it after the numeric session id)
# or a leaf the user already owns under user/<uid>.
SESSION = re.compile(r"/[0-9]+(/.*)?")


class Refused(Exception):
    pass


def valid_rel(rel):
    return bool(REL.fullmatch(rel)) and all(
        seg and seg not in (".", "..") for seg in rel.split("/")
    )


def load_rules(path=None):
    """Fail closed: a missing, unreadable or untrusted system config refuses every request."""
    path = path or CONFIG
    try:
        st = os.stat(path)
    except OSError as e:
        raise Refused("system config %s unavailable: %s" % (path, e.strerror))
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused(
            "%s must be a regular file owned by root and not group/world writable"
            % path
        )
    try:
        with open(path, "rb") as f:
            return tomllib.load(f).get("protected", {})
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Refused("system config %s unreadable: %s" % (path, e))


def starttime(pid):
    """Field 22 of /proc/PID/stat (process start, clock ticks since boot). The comm field
    may contain spaces and parentheses, so parse after the last ')'."""
    raw = read_proc(pid, "stat").decode(errors="replace")
    return int(raw[raw.rindex(")") + 2 :].split()[19])


def pid_uid(pid):
    return os.stat("/proc/%d" % pid).st_uid


def oom_identity_matches(pid, caller, expected_start, pidfd=None):
    try:
        return (
            (pidfd is None or not pidfd_gone(pidfd))
            and pid_uid(pid) == caller
            and starttime(pid) == expected_start
        )
    except (OSError, ValueError):
        return False


def pidfd_gone(fd):
    """A pidfd becomes readable once the process has exited."""
    return bool(select.select([fd], [], [], 0)[0])


def read_proc(pid, name):
    with open("/proc/%d/%s" % (pid, name), "rb") as f:
        return f.read()


def proc_env(pid):
    out = {}
    for item in read_proc(pid, "environ").split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            out[k.decode(errors="replace")] = v.decode(errors="replace")
    return out


def proc_cgroup(pid):
    for line in read_proc(pid, "cgroup").decode().splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return ""


def check_pid(pid, caller, rules):
    """Raise Refused unless pid may be moved for caller. Returns (comm, cgroup) or None if gone."""
    if pid <= 1:
        raise Refused("bad pid %d" % pid)
    try:
        owner = os.stat("/proc/%d" % pid).st_uid
        comm = read_proc(pid, "comm").decode(errors="replace").strip()
        cg = proc_cgroup(pid)
        env = proc_env(pid)
    except (FileNotFoundError, ProcessLookupError):
        return None
    if owner != caller:
        raise Refused("pid %d is not owned by uid %d" % (pid, caller))
    if any(fnmatch.fnmatchcase(comm, p) for p in rules.get("comm", [])):
        raise Refused("pid %d (%s) is protected" % (pid, comm))
    for pre in rules.get("cgroup_prefix", []):
        full = CG + cg
        if full == pre or full.startswith(pre.rstrip("/") + "/"):
            raise Refused("pid %d is in protected cgroup %s" % (pid, pre))
    for var, prefixes in rules.get("env_prefix", {}).items():
        val = env.get(var)
        for pre in prefixes:
            if val and (val == pre or val.startswith(pre.rstrip("/") + "/")):
                raise Refused("pid %d has protected %s=%s" % (pid, var, val))
    if not (SESSION.fullmatch(cg) or cg.startswith("/user/%d/" % caller)):
        raise Refused(
            "pid %d is in %s; only login-session and own scopes may be moved"
            % (pid, cg)
        )
    return comm, cg


LOG_MAX = 1 << 20


def log(line):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        try:
            if os.stat(LOG).st_size > LOG_MAX:
                os.replace(LOG, LOG + ".1")
        except FileNotFoundError:
            pass
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def move_one(pid, caller, rel, dest, rules):
    """Move one pid, guarding against pid reuse between check and write."""
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        print("taema-attach: pid %d gone, skipped" % pid, file=sys.stderr)
        return
    except OSError as e:
        raise Refused("pidfd_open(%d) failed: %s" % (pid, e.strerror))
    try:
        info = check_pid(pid, caller, rules)
        if info is None:
            print("taema-attach: pid %d gone, skipped" % pid, file=sys.stderr)
            return
        try:
            start = starttime(pid)
            if pid_uid(pid) != caller:
                raise Refused("pid %d changed owner" % pid)
        except (FileNotFoundError, ProcessLookupError):
            print("taema-attach: pid %d gone, skipped" % pid, file=sys.stderr)
            return
        src = CG + info[1] + "/cgroup.procs"
        try:
            with open(dest + "/cgroup.procs", "w") as f:
                f.write("%d\n" % pid)
        except OSError as e:
            print(
                "taema-attach: pid %d not moved: %s" % (pid, e.strerror),
                file=sys.stderr,
            )
            return
        bad = None
        try:
            if pidfd_gone(fd):
                bad = "exited"
            elif starttime(pid) != start or pid_uid(pid) != caller:
                bad = "was replaced"
        except (FileNotFoundError, ProcessLookupError):
            bad = "exited"
        if bad:
            if bad == "was replaced":
                # The pid now names a different process: put it back where it was.
                try:
                    with open(src, "w") as f:
                        f.write("%d\n" % pid)
                except OSError:
                    pass
            log(
                "%d uid=%d pid=%d REFUSED %s during move to /user/%d/%s"
                % (time.time(), caller, pid, bad, caller, rel)
            )
            if bad == "exited":
                print(
                    "taema-attach: pid %d exited during move, skipped" % pid,
                    file=sys.stderr,
                )
                return
            raise Refused(
                "pid %d changed identity during the move (pid reuse); moved back" % pid
            )
        log(
            "%d uid=%d pid=%d comm=%s from=%s to=/user/%d/%s"
            % (time.time(), caller, pid, info[0], info[1], caller, rel)
        )
    finally:
        os.close(fd)


def restore_oom(pid, caller, expected_start, value, applied):
    """Restore only the original value registered by the privileged helper."""
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(caller, int)
        or isinstance(caller, bool)
        or caller <= 0
        or not isinstance(expected_start, int)
        or isinstance(expected_start, bool)
        or expected_start <= 0
        or not isinstance(value, int)
        or isinstance(value, bool)
        or not OOM_MIN <= value <= OOM_MAX
        or not isinstance(applied, int)
        or isinstance(applied, bool)
        or not value <= applied <= OOM_MAX
    ):
        raise Refused("invalid OOM priority restore target")
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        raise Refused("OOM priority target is gone")
    except OSError as error:
        raise Refused("pidfd_open(%d) failed: %s" % (pid, error.strerror))
    try:
        try:
            if not oom_identity_matches(pid, caller, expected_start):
                raise Refused("OOM priority target changed identity")
            record_path = _oom_record_path(caller, pid, expected_start)
            record_fd, record = _load_oom_record(
                record_path, caller, pid, expected_start
            )
            if record is None:
                raise Refused("OOM priority restore was not recorded")
            if value != record["original"]:
                raise Refused("OOM priority value was not recorded")
            if applied != record["applied"]:
                raise Refused("applied OOM priority was not recorded")
            if applied < record["original"]:
                raise Refused("OOM priority restore would lower the original value")
            target_fd = os.open(
                "/proc/%d/oom_score_adj" % pid,
                os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except (FileNotFoundError, ProcessLookupError):
            raise Refused("OOM priority target is gone")
        except OSError as error:
            raise Refused("could not open OOM priority target: %s" % error.strerror)
        try:
            if not oom_identity_matches(pid, caller, expected_start, pidfd):
                raise Refused("OOM priority target changed identity")
            current = read_oom_score(pid)
            if current == record["original"]:
                if record["state"] == 0:
                    record["state"] = 1
                    try:
                        _write_oom_record(record_fd, record)
                    except OSError as error:
                        raise Refused(
                            "could not update OOM restoration record: %s"
                            % error.strerror
                        )
                return
            if record["state"] == 1:
                raise Refused("OOM priority restoration was already completed")
            if current != record["applied"]:
                raise Refused("current OOM priority is not the recorded value")
            data = (str(value) + "\n").encode("ascii")
            if os.write(target_fd, data) != len(data):
                raise Refused("could not restore complete OOM priority value")
        except (FileNotFoundError, ProcessLookupError):
            raise Refused("OOM priority target is gone")
        except OSError as error:
            raise Refused("could not restore OOM priority: %s" % error.strerror)
        finally:
            os.close(target_fd)
        record["state"] = 1
        try:
            _write_oom_record(record_fd, record)
        except OSError as error:
            raise Refused(
                "could not update OOM restoration record: %s" % error.strerror
            )
        log(
            "%d uid=%d pid=%d oom_score_adj=%d RESTORED"
            % (time.time(), caller, pid, value)
        )
    finally:
        if "record_fd" in locals() and record_fd is not None:
            os.close(record_fd)
        os.close(pidfd)


def read_oom_score(pid):
    """Read and validate oom_score_adj directly from procfs."""
    try:
        raw = read_proc(pid, "oom_score_adj").decode("ascii").strip()
        value = int(raw, 10)
    except (OSError, UnicodeError, ValueError):
        raise Refused("could not read OOM priority target")
    if not OOM_MIN <= value <= OOM_MAX:
        raise Refused("OOM priority target is out of range")
    return value


def oom_state_dir():
    """Create/check a root-only directory for helper-authenticated OOM records."""
    parent = os.path.dirname(OOM_STATE_DIR)
    try:
        parent_stat = os.stat(parent)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != 0
            or parent_stat.st_mode & 0o022
        ):
            raise Refused("OOM record parent is not a trusted root directory")
        try:
            os.mkdir(OOM_STATE_DIR, 0o700)
        except FileExistsError:
            pass
        state_stat = os.lstat(OOM_STATE_DIR)
    except OSError as error:
        raise Refused("OOM record directory unavailable: %s" % error.strerror)
    if (
        not stat.S_ISDIR(state_stat.st_mode)
        or state_stat.st_uid != 0
        or stat.S_IMODE(state_stat.st_mode) != 0o700
    ):
        raise Refused("OOM record directory must be root-owned and mode 0700")
    return OOM_STATE_DIR


def _oom_record_path(caller, pid, expected_start, directory=None):
    directory = directory or oom_state_dir()
    return os.path.join(directory, "%d-%d-%d.json" % (caller, pid, expected_start))


def _validate_oom_record_fd(fd):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise Refused("OOM restoration record is not a private root-owned file")


def _load_oom_record(path, caller, pid, expected_start):
    try:
        fd = os.open(
            path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return None, None
    except OSError as error:
        raise Refused("could not open OOM restoration record: %s" % error.strerror)
    try:
        _validate_oom_record_fd(fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = os.read(fd, OOM_STATE_MAX + 1)
        if len(raw) > OOM_STATE_MAX:
            raise Refused("OOM restoration record is too large")
        record = json.loads(raw.decode("ascii"))
        if not isinstance(record, dict):
            raise Refused("OOM restoration record is invalid")
        expected = {"uid": caller, "pid": pid, "start": expected_start}
        for key, value in expected.items():
            stored = record.get(key)
            if (
                not isinstance(stored, int)
                or isinstance(stored, bool)
                or stored != value
            ):
                raise Refused("OOM restoration record identity is invalid")
        original, applied = record.get("original"), record.get("applied")
        state = record.get("state")
        if (
            not isinstance(original, int)
            or isinstance(original, bool)
            or not OOM_MIN <= original <= OOM_MAX
            or not isinstance(applied, int)
            or isinstance(applied, bool)
            or not OOM_MIN <= applied <= OOM_MAX
            or applied < original
            or not isinstance(state, int)
            or isinstance(state, bool)
            or state not in (0, 1)
        ):
            raise Refused("OOM restoration record values are invalid")
        return fd, record
    except (OSError, UnicodeError, ValueError) as error:
        os.close(fd)
        if isinstance(error, Refused):
            raise
        raise Refused("could not read OOM restoration record")
    except BaseException:
        os.close(fd)
        raise


def _write_oom_record(fd, record):
    """Persist the small, fixed-shape root-owned restoration record while locked."""
    fcntl.flock(fd, fcntl.LOCK_EX)
    data = json.dumps(record, separators=(",", ":")).encode("ascii")
    os.lseek(fd, 0, os.SEEK_SET)
    if os.write(fd, data) != len(data):
        raise Refused("could not write complete OOM restoration record")
    os.ftruncate(fd, len(data))
    os.fsync(fd)


def _prune_oom_records(directory, caller):
    prefix = "%d-" % caller
    count = 0
    for name in os.listdir(directory):
        if not name.startswith(prefix) or not name.endswith(".json"):
            continue
        parts = name[:-5].split("-")
        if len(parts) != 3 or not all(part.isdecimal() for part in parts):
            continue
        uid, pid, start = (int(part) for part in parts)
        if uid != caller:
            continue
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise Refused("OOM restoration record is not a private root-owned file")
            if starttime(pid) != start or pid_uid(pid) != caller:
                os.unlink(path)
                continue
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            continue
        count += 1
    return count


def record_oom(pid, caller, expected_start, original, applied):
    """Seal the daemon's original/applied pair before it raises the process score."""
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(caller, int)
        or isinstance(caller, bool)
        or caller <= 0
        or not isinstance(expected_start, int)
        or isinstance(expected_start, bool)
        or expected_start <= 0
        or isinstance(original, bool)
        or not isinstance(original, int)
        or not OOM_MIN <= original <= OOM_MAX
        or isinstance(applied, bool)
        or not isinstance(applied, int)
        or not original < applied <= OOM_MAX
    ):
        raise Refused("invalid OOM priority record")
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        raise Refused("OOM priority target is gone")
    except OSError as error:
        raise Refused("pidfd_open(%d) failed: %s" % (pid, error.strerror))
    try:
        try:
            if not oom_identity_matches(pid, caller, expected_start, pidfd):
                raise Refused("OOM priority target changed identity")
            directory = oom_state_dir()
            count = _prune_oom_records(directory, caller)
            path = _oom_record_path(caller, pid, expected_start, directory)
            current = read_oom_score(pid)
            try:
                fd = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            except FileExistsError:
                existing_fd, existing = _load_oom_record(
                    path, caller, pid, expected_start
                )
                try:
                    if existing is None or existing["original"] != original:
                        raise Refused("conflicting OOM priority record exists")
                    if current == original:
                        existing["applied"] = applied
                        existing["state"] = 0
                        _write_oom_record(existing_fd, existing)
                        return
                    if (
                        current == applied
                        and existing["applied"] == applied
                        and existing["state"] == 0
                    ):
                        return
                    raise Refused("OOM priority original does not match the live value")
                finally:
                    if existing_fd is not None:
                        os.close(existing_fd)
            except OSError as error:
                raise Refused(
                    "could not create OOM priority record: %s" % error.strerror
                )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                _validate_oom_record_fd(fd)
                if count >= OOM_RECORD_LIMIT:
                    raise Refused("too many outstanding OOM priority records")
                if current != original:
                    raise Refused("OOM priority original does not match the live value")
                record = {
                    "uid": caller,
                    "pid": pid,
                    "start": expected_start,
                    "original": original,
                    "applied": applied,
                    "state": 0,
                }
                data = json.dumps(record, separators=(",", ":")).encode("ascii")
                if os.write(fd, data) != len(data):
                    raise Refused("could not write complete OOM priority record")
                os.fsync(fd)
            except BaseException:
                os.close(fd)
                try:
                    os.unlink(path)
                except OSError:
                    pass
                raise
            os.close(fd)
        except (FileNotFoundError, ProcessLookupError):
            raise Refused("OOM priority target is gone")
        except OSError as error:
            raise Refused("could not record OOM priority: %s" % error.strerror)
        if not oom_identity_matches(pid, caller, expected_start, pidfd):
            try:
                os.unlink(path)
            except OSError:
                pass
            raise Refused("OOM priority target changed identity")
        log(
            "%d uid=%d pid=%d oom_score_adj=%d->%d RECORDED"
            % (time.time(), caller, pid, original, applied)
        )
    finally:
        os.close(pidfd)


def main(argv):
    caller = os.environ.get("SUDO_UID", "")
    if os.geteuid() != 0 or not caller.isdigit():
        raise Refused("run through sudo")
    caller = int(caller)
    if caller == 0:
        raise Refused("refusing uid 0")
    if len(argv) == 5 and argv[0] == "oom-restore":
        _, pid_s, start_s, value_s, applied_s = argv
        if not re.fullmatch(r"[0-9]+", pid_s) or not re.fullmatch(r"[0-9]+", start_s):
            raise Refused("bad OOM priority target")
        if not re.fullmatch(r"-?[0-9]+", value_s):
            raise Refused("bad OOM priority value")
        if not re.fullmatch(r"-?[0-9]+", applied_s):
            raise Refused("bad applied OOM priority value")
        pid, expected_start, value, applied = (
            int(pid_s),
            int(start_s),
            int(value_s),
            int(applied_s),
        )
        if pid <= 1 or expected_start <= 0 or not -1000 <= value <= 1000:
            raise Refused("bad OOM priority target or value")
        if not value <= applied <= 1000:
            raise Refused("bad applied OOM priority value")
        restore_oom(pid, caller, expected_start, value, applied)
        return 0
    if len(argv) == 5 and argv[0] == "oom-record":
        _, pid_s, start_s, original_s, applied_s = argv
        if not re.fullmatch(r"[0-9]+", pid_s) or not re.fullmatch(r"[0-9]+", start_s):
            raise Refused("bad OOM priority record target")
        if not re.fullmatch(r"-?[0-9]+", original_s) or not re.fullmatch(
            r"-?[0-9]+", applied_s
        ):
            raise Refused("bad OOM priority record value")
        pid, expected_start = int(pid_s), int(start_s)
        original, applied = int(original_s), int(applied_s)
        if (
            pid <= 1
            or expected_start <= 0
            or not OOM_MIN <= original < applied <= OOM_MAX
        ):
            raise Refused("bad OOM priority record target or values")
        record_oom(pid, caller, expected_start, original, applied)
        return 0
    if len(argv) >= 3 and argv[0] == "attach" and len(argv) == 3:
        _, pid_s, name = argv
        if not NAME.fullmatch(name):
            raise Refused("bad name")
        rel, pids = "scope-" + name, [pid_s]
    elif len(argv) >= 3 and argv[0] == "move":
        rel, pids = argv[1], argv[2:]
    else:
        raise Refused(
            "usage: taema-attach attach PID NAME | move RELPATH PID... | "
            "oom-record PID START ORIGINAL APPLIED | "
            "oom-restore PID START ORIGINAL APPLIED"
        )
    if not valid_rel(rel):
        raise Refused("bad path")
    dest = "%s/user/%d/%s" % (CG, caller, rel)
    try:
        st = os.stat(dest)
    except FileNotFoundError:
        raise Refused("no such scope: %s" % rel)
    if st.st_uid != caller or os.path.islink(dest):
        raise Refused("scope not owned by uid %d" % caller)
    rules = load_rules()
    for pid_s in pids:
        if not pid_s.isdigit():
            raise Refused("bad pid")
        move_one(int(pid_s), caller, rel, dest, rules)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refused as e:
        print("taema-attach: %s" % e, file=sys.stderr)
        sys.exit(1)
