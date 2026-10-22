#!/usr/bin/env python3
"""In-guest scenario API for the taema disposable Void VM harness.

This module runs as the VM test user inside a guest, and is also imported by
the host-side unit tests against temporary directories.  Stdlib only; no host
cgroup, service, or user state is ever touched (the cgroup/proc roots are
seams: TAEMA_CGROOT / TAEMA_PROCROOT, defaulting to the real paths inside a
guest).

Scenario API:
  spawn_gui_tree   start a fake GUI app root plus sleeping children
  close_root       terminate only the root; children must survive
  wait_for_event   wait for a daemon audit event (decisions.log)
  assert_scope_member / wait_for_scope / scope_members / scope_of
  capture_daemon_logs   collect daemon logs into the artifact directory
  run_privileged   run one privileged setup step (sudo -n, argv only)
"""

import argparse
import glob
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from unittest import mock

CGROOT = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
PROCROOT = os.environ.get("TAEMA_PROCROOT", "/proc")

#: The fake application root: forks out of the SSH session, spawns children,
#: records the tree, and idles. The final process is deliberately not a
#: session leader; its session-leader parent stays alive long enough for the
#: lineage scanner to see the parent relationship and classify it separately.
APP_ROOT = """\
import ctypes, json, os, signal, subprocess, sys, time

def main():
    n = int(sys.argv[1])
    workdir = sys.argv[2]
    child_argv = json.loads(sys.argv[3]) if len(sys.argv) > 3 else ["/bin/sleep", "3600"]
    root_comm = sys.argv[4] if len(sys.argv) > 4 else ""
    root_exec = json.loads(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else None

    # Popen starts this launcher as a session leader. Its child can therefore
    # create a distinct session with setsid(), then fork a non-session-leader
    # app root. Keep that session leader as the root's parent until it exits so
    # the daemon can observe the relationship instead of seeing a ppid-1
    # newcomer.
    if os.fork():
        os._exit(0)
    os.setsid()
    root = os.fork()
    if root:
        with open(os.path.join(workdir, "supervisor.pid"), "w") as f:
            f.write(str(os.getpid()))
        os.waitpid(root, 0)
        return

    if root_comm:
        ctypes.CDLL(None).prctl(15, root_comm.encode(), 0, 0, 0)

    children = []
    for _ in range(n):
        p = subprocess.Popen(child_argv, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        children.append(p.pid)
    tmp = os.path.join(workdir, "tree.json.tmp")
    with open(tmp, "w") as f:
        json.dump({"root": os.getpid(), "session": os.getsid(0),
                   "supervisor": os.getppid(), "started": time.monotonic(),
                   "children": children}, f)
    os.replace(tmp, os.path.join(workdir, "tree.json"))
    if root_exec:
        os.execv(root_exec[0], root_exec)
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        signal.pause()

main()
"""

M3_HOG_WORKER = """\
import ctypes, os, sys, time
# The caller supplies taema-m3-hog or taema-m3-peer for the score comparison.
gate, pidfile, progress, limitfile, comm = sys.argv[1:]
ctypes.CDLL(None).prctl(15, comm.encode(), 0, 0, 0)
open(pidfile, "w").write(str(os.getpid()))
while not os.path.exists(gate):
    time.sleep(0.1)
step = 4 * 1024 * 1024
pages = []
used = 0
while True:
    try:
        limit = int(open(limitfile).read().strip())
    except (OSError, ValueError):
        limit = 64 * 1024 * 1024
    if used >= limit:
        time.sleep(0.25)
        continue
    block = bytearray(min(step, limit - used))
    for offset in range(0, len(block), 4096):
        block[offset] = 1
    pages.append(block)
    used += len(block)
    open(progress, "w").write(str(used))
    time.sleep(1.0)
"""

M3_CACHE_WORKER = """\
import ctypes, os, sys, time
path, ready = sys.argv[1:]
ctypes.CDLL(None).prctl(15, b'm3cache', 0, 0, 0)
with open(path, 'w+b') as cache:
    cache.write(b'x' * (16 * 1024 * 1024))
    cache.flush()
    os.fsync(cache.fileno())
    cache.seek(0)
    cache.read()
with open(ready, 'w') as marker:
    marker.write('ready')
time.sleep(3600)
"""

M3_QMP_SERVER = """\
import ctypes, os, socket, sys, time
path, pidfile, ready = sys.argv[1:4]
ctypes.CDLL(None).prctl(15, b'qemu-system-m3', 0, 0, 0)
try:
    os.unlink(path)
except FileNotFoundError:
    pass
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
open(pidfile, 'w').write(str(os.getpid()))
open(ready, 'w').write('listening')
client, _address = server.accept()
while client.recv(4096):
    pass
client.close()
while True:
    time.sleep(0.1)
"""


class ScenarioError(Exception):
    """A scenario step failed or an expected state did not appear in time."""


def default_state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "taema")


def configured_adopt_interval():
    """Read the daemon's adopt cadence from system and user TOML config."""
    interval = 15.0
    paths = (
        "/etc/taema/taema.toml",
        os.path.join(os.path.expanduser("~"), ".config", "taema", "taema.toml"),
    )
    for path in paths:
        section = ""
        try:
            with open(path) as f:
                for raw in f:
                    line = raw.split("#", 1)[0].strip()
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].strip()
                    elif section == "timers":
                        match = re.match(
                            r"adopt_interval\s*=\s*([0-9]+(?:\.[0-9]+)?)$", line
                        )
                        if match:
                            interval = max(0.1, float(match.group(1)))
        except OSError:
            continue
    return interval


# ---- process tree ----------------------------------------------------------


def spawn_gui_tree(
    workdir, children=2, timeout=10, child_argv=None, root_comm=None, root_exec=None
):
    """Start a detached fake GUI app with `children` sleeping descendants.

    Returns root/child/supervisor pids, session id, workdir, and launcher Popen.
    The root has its own session but is not a session leader; the smoke scenario
    keeps the SSH login session open until after the root is closed.
    """
    os.makedirs(workdir, exist_ok=True)
    app = os.path.join(workdir, "app_root.py")
    with open(app, "w") as f:
        f.write(APP_ROOT)
    log = open(os.path.join(workdir, "root.log"), "w")
    argv = [sys.executable, app, str(children), workdir]
    if child_argv is not None or root_comm is not None or root_exec is not None:
        child_argv = child_argv or ["/bin/sleep", "3600"]
        argv.append(json.dumps([str(arg) for arg in child_argv]))
        argv.append(str(root_comm or ""))
        argv.append(json.dumps([str(arg) for arg in root_exec]) if root_exec else "")
    proc = subprocess.Popen(
        argv, cwd=workdir, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
    )
    log.close()
    treefile = os.path.join(workdir, "tree.json")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(treefile):
            with open(treefile) as f:
                data = json.load(f)
            return {
                "root": int(data["root"]),
                "children": [int(p) for p in data["children"]],
                "session": int(data["session"]),
                "supervisor": int(data["supervisor"]),
                "started": float(data["started"]),
                "workdir": workdir,
                "proc": proc,
            }
        time.sleep(0.05)
    rc = proc.poll()
    raise ScenarioError(
        "app root did not report its tree within %ss (launcher rc=%s)" % (timeout, rc)
    )


def _reaped(pid):
    """True when pid is our child and has been waited for (or is not ours)."""
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == pid


def _alive(pid):
    """Whether pid can still run; a zombie has exited even if its parent has not reaped it."""
    try:
        with open(os.path.join(PROCROOT, str(pid), "stat")) as f:
            stat = f.read()
        end = stat.rfind(")")
        if end >= 0 and stat[end + 2 : end + 3] == "Z":
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def close_root(root_pid, timeout=10):
    """Terminate the app root only; its children are left running."""
    if not _alive(root_pid) and not _reaped(root_pid):
        return
    try:
        os.kill(root_pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _reaped(root_pid) or not _alive(root_pid):
            return
        time.sleep(0.05)
    try:
        os.kill(root_pid, signal.SIGKILL)
    except OSError:
        pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if _reaped(root_pid) or not _alive(root_pid):
            return
        time.sleep(0.05)
    raise ScenarioError("root pid %d survived SIGKILL" % root_pid)


def kill_tree(tree, timeout=5):
    """Best-effort teardown of a spawned tree (root first, then children)."""
    try:
        close_root(tree["root"], timeout=timeout)
    except (KeyError, ScenarioError):
        pass
    for pid in tree.get("children", []):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.monotonic() + timeout
    for pid in tree.get("children", []):
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
    proc = tree.get("proc")
    if proc is not None:
        try:
            proc.wait(timeout=timeout)
        except Exception:
            pass
    supervisor = tree.get("supervisor")
    if supervisor:
        try:
            os.kill(supervisor, signal.SIGKILL)
        except OSError:
            pass


# ---- daemon events ---------------------------------------------------------


def wait_for_event(log_path, pattern, timeout=60, poll=0.25):
    """Wait until a line containing `pattern` appears in the daemon audit log."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with open(log_path) as f:
                for line in f:
                    if pattern in line:
                        return line.rstrip("\n")
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise ScenarioError(
                "no line matching %r in %s within %ss" % (pattern, log_path, timeout)
            )
        time.sleep(poll)


# ---- scope membership ------------------------------------------------------


def scope_of(pid, cgroot=None, procroot=None):
    """Relative cgroup path of pid under cgroot (e.g. user/1000/app-x-1)."""
    cgroot = cgroot or CGROOT
    procroot = procroot or PROCROOT
    path = os.path.join(procroot, str(pid), "cgroup")
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        raise ScenarioError("pid %d has no readable cgroup" % pid)
    rel = ""
    for line in raw.splitlines():
        if line.startswith("0::"):
            cgpath = line[3:]
            if cgpath.startswith("/sys/fs/cgroup"):
                cgpath = cgpath[len("/sys/fs/cgroup") :]
            rel = cgpath.lstrip("/")
            break
    return rel


def daemon_scope(rel):
    """Drop the delegated user prefix used by /proc from daemon-relative scope paths."""
    parts = rel.split("/", 2)
    if len(parts) == 3 and parts[0] == "user" and parts[1].isdigit():
        return parts[2]
    return rel


def scope_matches(rel, prefix):
    p = str(prefix).rstrip("/")
    return any(seg.startswith(p) for seg in rel.split("/"))


def scope_members(rel, cgroot=None):
    """Pids listed in the cgroup.procs of a scope relative to cgroot."""
    cgroot = cgroot or CGROOT
    path = os.path.join(cgroot, rel, "cgroup.procs")
    try:
        with open(path) as f:
            return [int(x) for x in f.read().split()]
    except OSError:
        raise ScenarioError("no cgroup.procs at %s" % path)


def assert_scope_member(pid, prefix, cgroot=None, procroot=None):
    """Assert pid lives in a scope whose path matches `prefix`; return the scope."""
    rel = scope_of(pid, cgroot=cgroot, procroot=procroot)
    if not scope_matches(rel, prefix):
        raise ScenarioError(
            "pid %d is in scope %r which does not match %r" % (pid, rel, prefix)
        )
    members = scope_members(rel, cgroot=cgroot)
    if pid not in members:
        raise ScenarioError(
            "pid %d is not a member of %r (members: %s)" % (pid, rel, members)
        )
    return rel


def wait_for_scope(pid, prefixes, timeout=90, poll=0.5, cgroot=None, procroot=None):
    """Wait until pid's scope matches one of `prefixes`; return the scope."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            rel = scope_of(pid, cgroot=cgroot, procroot=procroot)
            if any(scope_matches(rel, p) for p in prefixes):
                return rel
        except ScenarioError:
            pass
        if time.monotonic() >= deadline:
            raise ScenarioError(
                "pid %d not in any scope matching %s within %ss"
                % (pid, prefixes, timeout)
            )
        time.sleep(poll)


def wait_for_scope_gone(rel, timeout=20, poll=0.1, cgroot=None):
    """Wait for a proc-relative scope directory under cgroot to disappear."""
    path = os.path.join(cgroot or CGROOT, rel)
    deadline = time.monotonic() + timeout
    while os.path.isdir(path):
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)
    return True


# ---- logs and privileged steps --------------------------------------------


def capture_daemon_logs(dest_dir, state_dir=None, extra_dirs=()):
    """Copy user state and privileged daemon logs into dest_dir."""
    state = state_dir or default_state_dir()
    os.makedirs(dest_dir, exist_ok=True)
    copied = []
    for name in (
        "decisions.log",
        "decisions.log.1",
        "knowledge.json",
        "feedback.jsonl",
        "feedback.jsonl.replay",
    ):
        src = os.path.join(state, name)
        if os.path.isfile(src):
            dst = os.path.join(dest_dir, name)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o644)
            copied.append(dst)
    for d in extra_dirs:
        if not os.path.exists(d):
            continue
        root_dst = os.path.join(dest_dir, os.path.basename(d.rstrip("/")) or "log")
        listing = run_privileged(
            ["find", d, "-type", "f", "!", "-name", "lock", "-print0"]
        )
        if listing.returncode != 0:
            raise OSError(
                "cannot list privileged logs under %s: %s" % (d, listing.stderr.strip())
            )
        for src in listing.stdout.split("\0"):
            if not src:
                continue
            rel = os.path.relpath(src, d)
            dst = os.path.join(root_dst, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            copied_file = run_privileged(["install", "-m", "0644", src, dst])
            if copied_file.returncode != 0:
                raise OSError(
                    "cannot copy privileged log %s: %s"
                    % (src, copied_file.stderr.strip())
                )
            copied.append(dst)
    return copied


def run_privileged(argv, timeout=60):
    """Run one privileged setup step as root (argv only, never a shell line)."""
    return subprocess.run(
        ["sudo", "-n"] + [str(a) for a in argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run(argv, timeout=60):
    return subprocess.run(
        [str(a) for a in argv], capture_output=True, text=True, timeout=timeout
    )


def wait_for_auto_status(timeout=30, poll=0.5):
    """Wait for the per-user daemon socket to appear and answer status."""
    deadline = time.monotonic() + timeout
    attempts = 0
    while True:
        attempts += 1
        result = _run(["/usr/bin/taema", "status"], timeout=10)
        if result.returncode == 0 and '"mode": "auto"' in result.stdout:
            return result, attempts
        if time.monotonic() >= deadline:
            return result, attempts
        time.sleep(poll)


def runtime_socket_detail():
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    path = os.path.join(runtime_dir, "taema.sock")
    try:
        st = os.stat(path)
        return "%s mode=%04o uid=%d gid=%d" % (
            path,
            st.st_mode & 0o7777,
            st.st_uid,
            st.st_gid,
        )
    except OSError as e:
        return "%s unavailable: %s" % (path, e)


# ---- results ---------------------------------------------------------------


class ResultRecorder:
    """Collects step outcomes and writes <artifacts>/<name>.json."""

    def __init__(self, name, artifacts):
        self.name = name
        self.artifacts = artifacts
        self.steps = []
        self.started = time.time()
        os.makedirs(artifacts, exist_ok=True)

    def step(self, name, ok, detail=""):
        self.steps.append(
            {"name": name, "ok": bool(ok), "detail": str(detail).strip()[:4000]}
        )
        return ok

    def finish(self, ok):
        data = {
            "scenario": self.name,
            "ok": bool(ok),
            "started": self.started,
            "duration_s": round(time.time() - self.started, 3),
            "steps": self.steps,
        }
        path = os.path.join(self.artifacts, self.name + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return path


# ---- scenarios -------------------------------------------------------------


def scenario_smoke(rec, args, tree_holder):
    """Contain a GUI-like tree, close the root, verify survivor containment."""
    timeout = args.timeout
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    runner_pid = os.getpid()
    runner_sid = os.getsid(0)
    runner_scope = scope_of(runner_pid)
    rec.step(
        "runner-session-leader",
        runner_sid == runner_pid,
        "pid=%d sid=%d pgrp=%d scope=%s"
        % (runner_pid, runner_sid, os.getpgrp(), runner_scope),
    )
    rec.step(
        "login-session-env",
        bool(runtime_dir),
        "XDG_RUNTIME_DIR=%s" % (runtime_dir or "<unset>"),
    )

    service = run_privileged(["sv", "status", "/var/service/taema"])
    rec.step(
        "service-status",
        service.returncode == 0,
        (service.stdout + service.stderr).strip()[:300],
    )

    status, attempts = wait_for_auto_status(timeout=30)
    rec.step(
        "daemon-status",
        status.returncode == 0 and '"mode": "auto"' in status.stdout,
        "attempts=%d HOME=%s XDG_RUNTIME_DIR=%s socket={%s} %s"
        % (
            attempts,
            os.environ.get("HOME", "<unset>"),
            runtime_dir or "<unset>",
            runtime_socket_detail(),
            (status.stdout or status.stderr)[:600],
        ),
    )

    tree = spawn_gui_tree(os.path.join(args.artifacts, "work"), children=2)
    tree_holder.append(tree)
    rec.step("spawn", True, "root=%d children=%s" % (tree["root"], tree["children"]))
    rec.step(
        "fixture-session",
        tree["root"] != tree["session"] and tree["session"] != runner_sid,
        "root=%d session=%d runner_session=%d supervisor=%d"
        % (tree["root"], tree["session"], runner_sid, tree["supervisor"]),
    )

    rel = wait_for_scope(tree["root"], ["app-"], timeout=timeout)
    rec.step("root-contained", rel != "", "scope=%s" % rel)
    rec.step(
        "root-distinct-scope",
        rel != runner_scope,
        "root=%s runner=%s" % (rel, runner_scope),
    )

    # decisions.log records the scope leaf (app-...), while cgroup paths
    # include the user/session prefix (user/<uid>/...).
    event = wait_for_event(
        os.path.join(args.state_dir, "decisions.log"),
        os.path.basename(rel),
        timeout=timeout,
    )
    rec.step("daemon-event", True, event[:300])

    # The lineage model treats a root seen only once as a short-lived wrapper.
    # Keep the app alive through one full configured interval after the first
    # adoption event so the next pass records a second sighting before close.
    adopt_interval = configured_adopt_interval()
    observation_window = adopt_interval + 1.0
    time.sleep(observation_window)
    stable_scope = scope_of(tree["root"])
    root_age = time.monotonic() - tree["started"]
    second_sighting = (
        _alive(tree["root"]) and stable_scope == rel and root_age >= observation_window
    )
    rec.step(
        "root-observed-twice",
        second_sighting,
        "first_adopt=%s held=%.3fs adopt_interval=%.3fs root_age=%.3fs scope=%s"
        % (event[:200], observation_window, adopt_interval, root_age, stable_scope),
    )

    close_started = time.monotonic()
    close_root(tree["root"], timeout=15)
    closed_at = time.monotonic()
    rec.step(
        "close-root",
        True,
        "root=%d terminated in %.3fs" % (tree["root"], closed_at - close_started),
    )

    alive = [p for p in tree["children"] if _alive(p)]
    rec.step(
        "children-alive",
        len(alive) == len(tree["children"]),
        "alive=%s of %s" % (alive, tree["children"]),
    )

    first = tree["children"][0]
    leftover = wait_for_scope(first, ["leftover/"], timeout=timeout)
    promotion_latency = time.monotonic() - closed_at
    rec.step("survivors-contained", leftover != "", "scope=%s" % leftover)
    rec.step(
        "survivor-promotion-latency",
        promotion_latency <= timeout,
        "scope=%s seconds_after_root_close=%.3f timeout=%ds"
        % (leftover, promotion_latency, timeout),
    )

    both = [assert_scope_member(p, "leftover/") for p in tree["children"]]
    rec.step("assert-scope-membership", both[0] == both[1], "members=%s" % both)

    review_event = wait_for_event(
        os.path.join(args.state_dir, "decisions.log"), "review_created", timeout=timeout
    )
    review = _run(["/usr/bin/taema", "review"], timeout=30)
    rec.step(
        "review-created",
        review.returncode == 0
        and "review #" in review.stdout
        and "survivors=" in review.stdout,
        (review_event + "\n" + review.stdout + review.stderr)[:800],
    )

    return all(s["ok"] for s in rec.steps)


def _m0_config_paths():
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    taema_dir = os.path.join(config_home, "taema")
    return (
        os.path.join(taema_dir, "taema.toml"),
        os.path.join(taema_dir, "units", "m0-pause.toml"),
    )


def _m0_snapshot(paths):
    snapshot = {}
    for path in paths:
        try:
            with open(path, "rb") as f:
                snapshot[path] = f.read()
        except FileNotFoundError:
            snapshot[path] = None
    return snapshot


def _m0_write_mode(mode, idle_grace=3600, adopt_interval=2, gc_interval=3600):
    config_path, unit_path = _m0_config_paths()
    os.makedirs(os.path.dirname(unit_path), exist_ok=True)
    with open(config_path, "w") as f:
        f.write(
            'mode = "%s"\n\n[timers]\nadopt_interval = %s\ngc_interval = %s\n'
            "idle_grace = %s\nleftover_expire_days = 0\n"
            % (mode, adopt_interval, gc_interval, idle_grace)
        )
    with open(unit_path, "w") as f:
        f.write(
            '[unit]\nname = "app-m0pause"\nkind = "app"\n'
            'group_by_env = "XDG_RUNTIME_DIR"\nstop_when_unneeded = true\n\n'
            '[match]\ncomm = "m0pause"\n\n'
            '[gc]\nenv_dir_missing = "XDG_RUNTIME_DIR"\n'
            "keep_while_children = true\n"
        )
    restart = run_privileged(["sv", "restart", "taema"], timeout=45)
    if restart.returncode != 0:
        raise ScenarioError(
            "could not restart taema for mode %s: %s%s"
            % (mode, restart.stdout, restart.stderr)
        )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status = _run(["/usr/bin/taema", "status"], timeout=10)
        if status.returncode == 0 and '"mode": "%s"' % mode in status.stdout:
            return status
        time.sleep(0.25)
    raise ScenarioError(
        "taema did not restart in %s mode: %s%s" % (mode, status.stdout, status.stderr)
    )


def _m0_restore(snapshot):
    for path, contents in snapshot.items():
        if contents is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(contents)
    return run_privileged(["sv", "restart", "taema"], timeout=45)


def _m3_enable_wake_freeze():
    """Enable a bounded, guest-local auto-freeze policy for the wake check."""
    config_path, _unit_path = _m0_config_paths()
    snapshot = _m0_snapshot([config_path])
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as target:
        target.write(
            'mode = "enforce"\n\n'
            "[timers]\nadopt_interval = 1\ngc_interval = 3600\n"
            "idle_grace = 3600\nleftover_expire_days = 0\n\n"
            "[mem]\nidle_reclaim_grace = 0\n\n"
            "[freeze]\nenabled = true\nadopt = false\nafter = 0\n"
            "wake_on_connect = true\nmax_frozen = 4\ncpu_idle_max = 0.5\n\n"
            "[guard]\nenabled = true\navailable_floor = 18\n"
            'psi_some = "150ms/2s"\npsi_full = "50ms/2s"\n'
            "cooldown = 10\nfreeze_in_adopt = true\n"
            "oom_adj_leftover = 500\n\n"
            "[experimental]\nfreeze = true\nguard = true\n"
        )
    restart = run_privileged(["sv", "restart", "taema"], timeout=45)
    if restart.returncode != 0:
        _m0_restore(snapshot)
        raise ScenarioError(
            "could not enable M3 wake policy: %s%s" % (restart.stdout, restart.stderr)
        )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        mode, status = _m3_read_status_mode()
        if status.returncode == 0 and mode == "enforce":
            return snapshot
        time.sleep(0.25)
    _m0_restore(snapshot)
    raise ScenarioError(
        "taema did not load M3 wake policy: %s%s" % (status.stdout, status.stderr)
    )


def _m3_read_status_mode():
    """Read the loaded mode from Taema's stable JSON status view."""
    result = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
    if result.returncode != 0:
        return None, result
    try:
        model = json.loads(result.stdout)
    except (TypeError, ValueError):
        return None, result
    status = model.get("status") if isinstance(model, dict) else None
    mode = status.get("mode") if isinstance(status, dict) else None
    return mode if isinstance(mode, str) else None, result


def _wait_for_frozen_scope(rel, timeout=90):
    """Wait until cgroup v2 reports the complete target scope frozen."""
    path = os.path.join(CGROOT, rel, "cgroup.events")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="ascii") as source:
                if "frozen 1" in source.read().splitlines():
                    return True
        except OSError:
            return False
        time.sleep(0.1)
    return False


def _m3_enable_pressure_policy():
    """Use adopt mode for the bounded stress phase; only the guard may freeze."""
    config_path, _unit_path = _m0_config_paths()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as target:
        target.write(
            'mode = "adopt"\n\n'
            "[timers]\nadopt_interval = 1\ngc_interval = 3600\n"
            "idle_grace = 3600\nleftover_expire_days = 0\n\n"
            "[mem]\nreclaim = true\nreclaim_interval = 2\n"
            "reclaim_cooldown = 0\nreclaim_max = \"4M\"\n"
            "reclaim_minimum = \"1M\"\nmin_headroom = \"0M\"\n"
            "headroom_percent = 0\nidle_reclaim_grace = 0\n"
            "swap_reclaim = false\n\n"
            "[freeze]\nenabled = true\nadopt = false\nafter = 0\n"
            "wake_on_connect = false\nmax_frozen = 4\ncpu_idle_max = 0.5\n\n"
            "[guard]\nenabled = true\navailable_floor = 35\n"
            'psi_some = "1ms/2s"\npsi_full = "1ms/2s"\n'
            "cooldown = 10\nfreeze_in_adopt = true\n"
            "oom_adj_leftover = 500\noom_group_leftover = true\n\n"
            "[experimental]\nfreeze = true\nguard = true\n"
        )
    restart = run_privileged(["sv", "restart", "taema"], timeout=45)
    if restart.returncode != 0:
        raise ScenarioError(
            "could not enable M3 pressure policy: %s%s"
            % (restart.stdout, restart.stderr)
        )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        mode, status = _m3_read_status_mode()
        if status.returncode == 0 and mode == "adopt":
            return
        time.sleep(0.25)
    raise ScenarioError(
        "taema did not load M3 pressure policy: %s%s"
        % (status.stdout, status.stderr)
    )


def _m3_oom_score_adj(pid):
    try:
        with open(os.path.join(PROCROOT, str(pid), "oom_score_adj"), encoding="ascii") as source:
            value = source.read().strip()
        return int(value)
    except (OSError, ValueError):
        return None


def _m3_oom_score(pid):
    try:
        with open(os.path.join(PROCROOT, str(pid), "oom_score"), encoding="ascii") as source:
            return int(source.read().strip())
    except (OSError, ValueError):
        return None


def _m3_pressure_snapshot():
    """Capture guest availability and PSI alongside an observed guard action."""
    meminfo = {}
    with open(os.path.join(PROCROOT, "meminfo"), encoding="ascii") as source:
        for line in source:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parts = value.split()
            if parts and parts[0].isdigit():
                meminfo[key] = int(parts[0]) * 1024
    total = meminfo.get("MemTotal")
    available = meminfo.get("MemAvailable")

    def read_pressure(path):
        try:
            with open(path, encoding="ascii") as source:
                return [line.strip() for line in source if line.strip()]
        except OSError as error:
            return {"error": str(error)}

    return {
        "sampled_at_wall": time.time(),
        "sampled_at_monotonic": time.monotonic(),
        "MemTotal_bytes": total,
        "MemAvailable_bytes": available,
        "MemAvailable_percent": round(100.0 * available / total, 3)
        if isinstance(total, int) and total > 0 and isinstance(available, int)
        else None,
        "global_memory_pressure": read_pressure(
            os.path.join(PROCROOT, "pressure", "memory")
        ),
        "user_cgroup_memory_pressure": read_pressure(
            os.path.join(CGROOT, "user", str(os.getuid()), "memory.pressure")
        ),
    }


def _m3_bounded_worker_cap(total_bytes, available_bytes, reserve_percent=38):
    """Return a total worker budget that leaves a measured guest-memory reserve."""
    if not isinstance(total_bytes, int) or total_bytes <= 0:
        raise ScenarioError("M3 worker cap requires a positive MemTotal")
    if not isinstance(available_bytes, int) or available_bytes <= 0:
        raise ScenarioError("M3 worker cap requires a positive MemAvailable")
    reserve = total_bytes * reserve_percent // 100
    # Keep an absolute workload cap as well as a live available-memory reserve.
    budget = min(total_bytes // 2, available_bytes - reserve)
    if budget < 8 * 1024 * 1024:
        raise ScenarioError(
            "M3 has insufficient MemAvailable for a bounded pressure workload"
        )
    return budget


def _m3_pressure_scope_preflight(item, expected_prefix):
    """Capture and validate a pressure worker's live proc/cgroup membership."""
    pid = item["pid"]
    proc_cgroup_path = os.path.join(PROCROOT, str(pid), "cgroup")
    try:
        with open(proc_cgroup_path, encoding="utf-8", errors="replace") as source:
            proc_cgroup = source.read().strip()
    except OSError as error:
        proc_cgroup = "unreadable: %s" % error
    try:
        scope = scope_of(pid)
    except ScenarioError as error:
        scope = None
        scope_error = str(error)
    else:
        scope_error = None
    cgroup_path = os.path.join(CGROOT, scope) if scope else None
    exists = bool(cgroup_path and os.path.isdir(cgroup_path))
    try:
        listing = sorted(os.listdir(cgroup_path)) if exists else []
    except OSError as error:
        listing = ["unreadable: %s" % error]
    members = []
    member_error = None
    if exists:
        try:
            members = scope_members(scope)
        except ScenarioError as error:
            member_error = str(error)
    high_path = os.path.join(cgroup_path, "memory.high") if cgroup_path else None
    high_available = bool(high_path and os.path.isfile(high_path))
    try:
        with open(high_path, encoding="ascii") as source:
            high_value = source.read().strip()
    except OSError as error:
        high_value = "unavailable: %s" % error
    evidence = {
        "pid": pid,
        "expected_scope_prefix": expected_prefix,
        "proc_cgroup": proc_cgroup,
        "scope": scope,
        "cgroup_path": cgroup_path,
        "cgroup_exists": exists,
        "cgroup_listing": listing,
        "cgroup_procs": members,
        "cgroup_member": pid in members,
        "memory_high_available": high_available,
        "memory_high_value": high_value,
        "scope_error": scope_error,
        "member_error": member_error,
    }
    ok = (
        scope is not None
        and scope_matches(scope, expected_prefix)
        and exists
        and pid in members
    )
    if ok:
        item["scope"] = scope
    return ok, evidence


def _m3_worker_progress(item):
    try:
        with open(item["progress"], encoding="ascii") as source:
            value = int(source.read().strip())
    except (OSError, ValueError):
        return 0
    return max(0, value)


def _m3_memory_allocation_evidence(expected_memory_mb):
    """Compare guest MemTotal with the QEMU memory requested by the harness."""
    sample = _m3_pressure_snapshot()
    expected_bytes = expected_memory_mb * 1024 * 1024
    actual_bytes = sample.get("MemTotal_bytes")
    lower_bytes = expected_bytes * 90 // 100
    upper_bytes = expected_bytes * 102 // 100
    matches = (
        isinstance(actual_bytes, int)
        and lower_bytes <= actual_bytes <= upper_bytes
    )
    return matches, {
        "requested_memory_mib": expected_memory_mb,
        "requested_bytes": expected_bytes,
        "MemTotal_bytes": actual_bytes,
        "MemTotal_mib": round(actual_bytes / (1024 * 1024), 2)
        if isinstance(actual_bytes, int)
        else None,
        "kernel_reserved_bytes": expected_bytes - actual_bytes
        if isinstance(actual_bytes, int)
        else None,
        "accepted_range_bytes": [lower_bytes, upper_bytes],
        "sample": sample,
    }


def _m3_promote_to_leftover(tree, pid, timeout=90):
    """Stabilize app adoption before closing its root and waiting for promotion."""
    app_scope = wait_for_scope(pid, ["app-"], timeout=timeout)
    time.sleep(max(5.5, configured_adopt_interval() + 1.0))
    close_root(tree["root"], timeout=15)
    leftover_scope = wait_for_scope(pid, ["leftover/"], timeout=timeout)
    return app_scope, leftover_scope


def _m3_pressure_run(rec, args, tracked):
    """Apply bounded guest pressure, then verify earlyoom's score choice."""
    _m3_enable_pressure_policy()
    baseline = _m3_pressure_snapshot()
    total, available = baseline["MemTotal_bytes"], baseline["MemAvailable_bytes"]
    floor_percent = baseline["MemAvailable_percent"]
    rec.step(
        "pressure-starts-above-guard-floor",
        isinstance(floor_percent, (int, float)) and floor_percent > 40,
        json.dumps(
            {
                "sample": baseline,
                "guard_floor_percent": 35,
                "fallback_floor_percent": 12,
            },
            sort_keys=True,
        ),
    )
    if not isinstance(total, int) or not isinstance(available, int):
        raise ScenarioError("M3 pressure run requires MemTotal and MemAvailable")
    if floor_percent <= 40:
        raise ScenarioError("guest begins too close to the configured 35% guard floor")

    cache_dir = os.path.join(args.artifacts, "m3-cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "cache.bin")
    cache_ready = os.path.join(cache_dir, "ready")
    cache_tree = spawn_gui_tree(
        cache_dir,
        children=1,
        child_argv=[
            sys.executable,
            "-c",
            M3_CACHE_WORKER,
            cache_file,
            cache_ready,
        ],
        root_comm="m3cache-root",
        root_exec=["/bin/sleep", "3600"],
    )
    tracked.append(cache_tree)
    cache_pid = cache_tree["children"][0]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not os.path.isfile(cache_ready):
        time.sleep(0.1)
    cache_ready_ok = os.path.isfile(cache_ready)
    rec.step("pressure-cache-leftover-prepared", cache_ready_ok, "16 MiB file cache")
    if not cache_ready_ok:
        raise ScenarioError("M3 cache process did not prepare its bounded file")
    cache_app_scope, cache_scope = _m3_promote_to_leftover(cache_tree, cache_pid)
    rec.step(
        "pressure-cache-adopted-before-leftover",
        True,
        "app_scope=%s leftover_scope=%s pid=%d"
        % (cache_app_scope, cache_scope, cache_pid),
    )

    phase1_start = _m3_pressure_snapshot()
    phase1_total = phase1_start.get("MemTotal_bytes")
    phase1_available = phase1_start.get("MemAvailable_bytes")
    if not isinstance(phase1_total, int) or not isinstance(phase1_available, int):
        raise ScenarioError("M3 cannot calculate a safe guest pressure budget")
    phase1_cap = _m3_bounded_worker_cap(phase1_total, phase1_available)
    each_phase1_limit = phase1_cap // 2
    rec.step(
        "pressure-workload-bounded-to-guest-memory",
        True,
        json.dumps(
            {
                "sample_before_worker_start": phase1_start,
                "total_worker_budget_bytes": phase1_cap,
                "worker_limit_bytes": each_phase1_limit,
                "max_worker_percent_of_memtotal": 50,
                "reserved_memavailable_percent": 38,
            },
            sort_keys=True,
        ),
    )

    def spawn_worker(name, leftover, comm, initial_limit):
        workdir = os.path.join(args.artifacts, name)
        os.makedirs(workdir, exist_ok=True)
        gate = os.path.join(workdir, "start")
        pidfile = os.path.join(workdir, "pid")
        progress = os.path.join(workdir, "progress")
        limitfile = os.path.join(workdir, "limit")
        with open(limitfile, "w", encoding="ascii") as target:
            target.write(str(initial_limit))
        tree = spawn_gui_tree(
            workdir,
            children=1,
            child_argv=[
                sys.executable,
                "-c",
                M3_HOG_WORKER,
                gate,
                pidfile,
                progress,
                limitfile,
                comm,
            ],
            root_comm=name + "-root",
            root_exec=["/bin/sleep", "3600"],
        )
        tracked.append(tree)
        pid = tree["children"][0]
        if leftover:
            app_scope, scope = _m3_promote_to_leftover(tree, pid)
        else:
            scope = wait_for_scope(pid, ["app-"], timeout=90)
            app_scope = scope
        return {
            "tree": tree,
            "gate": gate,
            "limitfile": limitfile,
            "progress": progress,
            "pid": pid,
            "app_scope": app_scope,
            "scope": scope,
            "expected_prefix": "leftover/" if leftover else "app-",
        }

    hog = spawn_worker("m3-hog", True, "taema-m3-hog", each_phase1_limit)
    peer = spawn_worker("m3-peer", False, "taema-m3-peer", each_phase1_limit)
    pressure_config_snapshot = None
    preflight = {}
    for name, item in (("hog", hog), ("peer", peer)):
        ok, detail = _m3_pressure_scope_preflight(
            item, item["expected_prefix"]
        )
        preflight[name] = detail
        rec.step(
            "pressure-%s-scope-preflight" % name,
            ok,
            json.dumps(detail, sort_keys=True),
        )
        if not ok:
            _run(["/usr/bin/taema", "thaw", "--all"], timeout=30)
            raise ScenarioError(
                "M3 %s worker failed live cgroup membership preflight" % name
            )

    decision_path = os.path.join(args.state_dir, "decisions.log")
    try:
        offset = os.path.getsize(decision_path)
    except OSError:
        offset = 0
    guard_events, action_samples = [], []
    try:
        with open(hog["gate"], "w", encoding="ascii") as target:
            target.write("go\n")
        with open(peer["gate"], "w", encoding="ascii") as target:
            target.write("go\n")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                with open(decision_path, encoding="utf-8", errors="replace") as source:
                    source.seek(offset)
                    lines = source.readlines()
                    offset = source.tell()
            except OSError:
                lines = []
            for line in lines:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("event") == "guard_step":
                    guard_events.append(event)
                    action_samples.append(
                        {
                            "event": event,
                            "pressure_sample": _m3_pressure_snapshot(),
                            "worker_progress_bytes": {
                                "hog": _m3_worker_progress(hog),
                                "peer": _m3_worker_progress(peer),
                            },
                        }
                    )
            page_cache_seen = any(
                event.get("step") == "page_cache"
                and event.get("status") == "acted"
                and daemon_scope(cache_scope) in event.get("scopes", [])
                for event in guard_events
            )
            freeze_seen = any(
                event.get("step") == "freeze"
                and event.get("status") == "acted"
                and any(
                    scope in event.get("scopes", [])
                    for scope in (daemon_scope(cache_scope), daemon_scope(hog["scope"]))
                )
                for event in guard_events
            )
            if page_cache_seen and freeze_seen:
                break
            time.sleep(0.05)

        page_index = next(
            (
                index
                for index, event in enumerate(guard_events)
                if event.get("step") == "page_cache"
                and event.get("status") == "acted"
                and daemon_scope(cache_scope) in event.get("scopes", [])
            ),
            None,
        )
        freeze_index = next(
            (
                index
                for index, event in enumerate(guard_events)
                if event.get("step") == "freeze"
                and event.get("status") == "acted"
                and any(
                    scope in event.get("scopes", [])
                    for scope in (daemon_scope(cache_scope), daemon_scope(hog["scope"]))
                )
            ),
            None,
        )
        page_sample = action_samples[page_index]["pressure_sample"] if page_index is not None else None
        freeze_sample = action_samples[freeze_index]["pressure_sample"] if freeze_index is not None else None
        samples_above_floors = all(
            isinstance(sample, dict)
            and isinstance(sample.get("MemAvailable_percent"), (int, float))
            and sample["MemAvailable_percent"] > 35
            and sample["MemAvailable_percent"] > 12
            for sample in (page_sample, freeze_sample)
        )
        ordered = page_index is not None and freeze_index is not None and page_index < freeze_index
        evidence = {
            "guard_floor_percent": 35,
            "fallback_floor_percent": 12,
            "page_cache_event": guard_events[page_index] if page_index is not None else None,
            "page_cache_sample": page_sample,
            "freeze_event": guard_events[freeze_index] if freeze_index is not None else None,
            "freeze_sample": freeze_sample,
            "page_cache_worker_progress_bytes": action_samples[page_index]["worker_progress_bytes"] if page_index is not None else None,
            "freeze_worker_progress_bytes": action_samples[freeze_index]["worker_progress_bytes"] if freeze_index is not None else None,
            "initial_worker_scope_preflight": preflight,
            "bounded_worker_budget_bytes": phase1_cap,
            "all_guard_events": guard_events,
        }
        rec.step(
            "guard-page-cache-then-freezes-above-floors",
            ordered and samples_above_floors,
            json.dumps(evidence, sort_keys=True),
        )
        if not (ordered and samples_above_floors):
            raise ScenarioError("guard did not reclaim cache then freeze above both available floors")

        after_guard = _m3_pressure_snapshot()
        available_after_guard = after_guard["MemAvailable_bytes"]
        if not isinstance(available_after_guard, int):
            raise ScenarioError("M3 could not sample MemAvailable after guard actions")
        if available_after_guard <= total * 14 // 100:
            raise ScenarioError("guard phase left too little margin for a bounded earlyoom gate")
        progress_before_earlyoom = {
            "hog": _m3_worker_progress(hog),
            "peer": _m3_worker_progress(peer),
        }
        current_total = sum(progress_before_earlyoom.values())
        bytes_to_earlyoom = max(0, available_after_guard - total * 8 // 100)
        bytes_to_six_percent = max(0, available_after_guard - total * 6 // 100)
        total_worker_cap = total * 82 // 100
        remaining_worker_capacity = total_worker_cap - current_total
        if bytes_to_earlyoom > remaining_worker_capacity:
            raise ScenarioError(
                "M3 bounded workers cannot safely reach earlyoom threshold"
            )
        target_total = min(bytes_to_six_percent, remaining_worker_capacity)
        if target_total < bytes_to_earlyoom:
            target_total = bytes_to_earlyoom
        hog_extra = target_total // 2
        peer_extra = target_total - hog_extra
        absolute_targets = {
            "hog": progress_before_earlyoom["hog"] + hog_extra,
            "peer": progress_before_earlyoom["peer"] + peer_extra,
        }
        for name, item in (("hog", hog), ("peer", peer)):
            with open(item["limitfile"], "w", encoding="ascii") as target:
                target.write(str(absolute_targets[name]))
        rec.step(
            "earlyoom-phase-worker-limits-extend-current-progress",
            sum(absolute_targets.values()) <= total_worker_cap
            and all(
                absolute_targets[name] >= progress_before_earlyoom[name]
                for name in absolute_targets
            ),
            json.dumps(
                {
                    "sample_after_guard": after_guard,
                    "progress_before_extension_bytes": progress_before_earlyoom,
                    "remaining_to_earlyoom_8_percent_bytes": bytes_to_earlyoom,
                    "remaining_to_6_percent_bytes": bytes_to_six_percent,
                    "additional_bounded_target_bytes": target_total,
                    "absolute_worker_limits_bytes": absolute_targets,
                    "combined_worker_limit_bytes": sum(absolute_targets.values()),
                    "combined_worker_cap_bytes": total_worker_cap,
                },
                sort_keys=True,
            ),
        )
        if sum(absolute_targets.values()) > total_worker_cap:
            raise ScenarioError("M3 earlyoom worker limits exceed the guest safety cap")
        adj_deadline = time.monotonic() + 30
        hog_adj = _m3_oom_score_adj(hog["pid"])
        peer_adj = _m3_oom_score_adj(peer["pid"])
        while (hog_adj != 500 or peer_adj != 0) and time.monotonic() < adj_deadline:
            time.sleep(0.25)
            hog_adj = _m3_oom_score_adj(hog["pid"])
            peer_adj = _m3_oom_score_adj(peer["pid"])
        adj_ok = hog_adj == 500 and peer_adj == 0
        rec.step(
            "leftover-oom-score-adj-500-peer-zero",
            adj_ok,
            "leftover pid=%d scope=%s oom_score_adj=%s; peer pid=%d scope=%s oom_score_adj=%s"
            % (hog["pid"], hog["scope"], hog_adj, peer["pid"], peer["scope"], peer_adj),
        )
        if not adj_ok:
            raise ScenarioError("Taema did not apply +500 to the leftover and 0 to the app peer")
        earlyoom_log = os.path.join(args.artifacts, "earlyoom.log")
        earlyoom_args = ["/usr/bin/earlyoom", "-m", "8,3", "-s", "100"]
        earlyoom = None
        scores = None
        victim = None
        earlyoom_output = ""
        try:
            with open(earlyoom_log, "w", encoding="utf-8") as output:
                earlyoom = subprocess.Popen(
                    earlyoom_args,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                time.sleep(1)
                try:
                    with open(os.path.join(PROCROOT, str(earlyoom.pid), "cmdline"), "rb") as source:
                        earlyoom_argv = [part.decode("utf-8", "replace") for part in source.read().split(b"\0") if part]
                except OSError:
                    earlyoom_argv = []
                running = earlyoom.poll() is None
                rec.step(
                    "earlyoom-running-at-8-percent",
                    running
                    and "-m" in earlyoom_argv
                    and earlyoom_argv[earlyoom_argv.index("-m") + 1] == "8,3"
                    and "-s" in earlyoom_argv
                    and earlyoom_argv[earlyoom_argv.index("-s") + 1] == "100"
                    and "--prefer" not in earlyoom_argv,
                    "argv=%s log=%s" % (earlyoom_argv, earlyoom_log),
                )
                if not running:
                    raise ScenarioError("guest earlyoom did not remain running at its configured thresholds")
                rec.step(
                    "bounded-global-pressure-phase-starts-without-cgroup-cap",
                    True,
                    json.dumps(
                        {
                            "memory_high_was_modified": False,
                            "phase1_progress_bytes": progress_before_earlyoom,
                            "additional_bounded_target_bytes": target_total,
                            "absolute_worker_limits_bytes": absolute_targets,
                            "combined_worker_cap_bytes": total_worker_cap,
                            "earlyoom_argv": earlyoom_argv,
                            "sample_at_phase_boundary": _m3_pressure_snapshot(),
                        },
                        sort_keys=True,
                    ),
                )
                thaw = _run(["/usr/bin/taema", "thaw", "--all"], timeout=30)
                rec.step("pressure-phase-thawed", thaw.returncode == 0, (thaw.stdout or thaw.stderr).strip()[:300])
                if thaw.returncode != 0:
                    raise ScenarioError("M3 could not thaw phase-one guard freezes before earlyoom")

                config_path, _unit_path = _m0_config_paths()
                pressure_config_snapshot = _m0_snapshot([config_path])
                with open(config_path, encoding="utf-8") as source:
                    pressure_config = source.read()
                earlyoom_config = _m3_pressure_freeze_config(
                    pressure_config, False
                )
                with open(config_path, "w", encoding="utf-8") as target:
                    target.write(earlyoom_config)
                restart = run_privileged(["sv", "restart", "taema"], timeout=45)
                freeze_disabled = (
                    restart.returncode == 0
                    and "freeze_in_adopt = false" in earlyoom_config
                    and "[guard]\nenabled = true" in earlyoom_config
                    and "[mem]\nreclaim = true" in earlyoom_config
                )
                rec.step(
                    "guard-freeze-disabled-only-for-earlyoom-pressure-phase",
                    freeze_disabled,
                    json.dumps(
                        {
                            "reason": "the 2.5s worker cadence may satisfy the configured 0.5% CPU-idle gate during global pressure",
                            "guard_remains_enabled": "[guard]\nenabled = true" in earlyoom_config,
                            "reclaim_remains_enabled": "[mem]\nreclaim = true" in earlyoom_config,
                            "freeze_in_adopt": False,
                            "restart": (restart.stdout + restart.stderr).strip()[-300:],
                        },
                        sort_keys=True,
                    ),
                )
                if not freeze_disabled:
                    raise ScenarioError("M3 could not disable only guard freezing for the pressure phase")
                for item in (hog, peer):
                    with open(item["gate"], "w", encoding="ascii") as target:
                        target.write("go\n")
                death_deadline = time.monotonic() + 360
                while time.monotonic() < death_deadline and _alive(hog["pid"]) and _alive(peer["pid"]):
                    scores = {
                        "leftover": {
                            "pid": hog["pid"],
                            "scope": hog["scope"],
                            "oom_score_adj": _m3_oom_score_adj(hog["pid"]),
                            "oom_score": _m3_oom_score(hog["pid"]),
                        },
                        "peer": {
                            "pid": peer["pid"],
                            "scope": peer["scope"],
                            "oom_score_adj": _m3_oom_score_adj(peer["pid"]),
                            "oom_score": _m3_oom_score(peer["pid"]),
                        },
                    }
                    time.sleep(0.25)
                victim = hog["pid"] if not _alive(hog["pid"]) else peer["pid"] if not _alive(peer["pid"]) else None
                if earlyoom.poll() is None:
                    earlyoom.terminate()
                    try:
                        earlyoom.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        earlyoom.kill()
                        earlyoom.wait(timeout=5)
            with open(earlyoom_log, encoding="utf-8", errors="replace") as source:
                earlyoom_output = source.read()
        finally:
            if earlyoom is not None and earlyoom.poll() is None:
                earlyoom.terminate()
                try:
                    earlyoom.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    earlyoom.kill()
                    earlyoom.wait(timeout=5)

        selected = (
            victim == hog["pid"]
            and scores is not None
            and scores["leftover"]["oom_score"] is not None
            and scores["peer"]["oom_score"] is not None
            and scores["leftover"]["oom_score"] > scores["peer"]["oom_score"]
            and str(hog["pid"]) in earlyoom_output
            and re.search(r"SIG(?:TERM|KILL)", earlyoom_output, re.IGNORECASE)
        )
        rec.step(
            "earlyoom-selected-higher-score-leftover",
            selected and adj_ok,
            json.dumps(
                {
                    "argv": earlyoom_args,
                    "selection": "default oom_score ranking; no --prefer selector",
                    "scores": scores,
                    "oom_score_adj": {"leftover": hog_adj, "peer": peer_adj},
                    "victim_pid": victim,
                    "victim_scope": hog["scope"] if victim == hog["pid"] else peer["scope"] if victim == peer["pid"] else None,
                    "earlyoom_log": earlyoom_output[-1500:],
                },
                sort_keys=True,
            ),
        )
        if not (selected and adj_ok):
            raise ScenarioError("earlyoom did not select the higher-scoring +500 leftover")
    finally:
        if pressure_config_snapshot is not None:
            restored_config = _m0_restore(pressure_config_snapshot)
            rec.step(
                "pressure-freeze-policy-restored",
                restored_config.returncode == 0,
                (restored_config.stdout + restored_config.stderr).strip()[-300:],
            )
        _run(["/usr/bin/taema", "thaw", "--all"], timeout=30)
        for tree in (
            cache_tree,
            hog.get("tree") if isinstance(hog, dict) else None,
            peer.get("tree") if isinstance(peer, dict) else None,
        ):
            if tree is not None:
                kill_tree(tree, timeout=5)

    return {"cache_tree": cache_tree, "hog_tree": hog["tree"], "peer_tree": peer["tree"]}


def _m3_daemon_metrics():
    """Return taema daemon PID, resident KiB, and CPU ticks from procfs."""
    for entry in os.listdir(PROCROOT):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(os.path.join(PROCROOT, entry, "cmdline"), "rb") as source:
                argv = [item.decode("utf-8", "replace") for item in source.read().split(b"\0")]
            module_launcher = any(
                argv[index : index + 3] == ["-m", "taema", "daemon"]
                for index in range(max(0, len(argv) - 2))
            )
            script_launcher = any(
                os.path.basename(argv[index]) == "taema"
                and index + 1 < len(argv)
                and argv[index + 1] == "daemon"
                for index in range(len(argv))
            )
            if not module_launcher and not script_launcher:
                continue
            with open(os.path.join(PROCROOT, entry, "status"), encoding="ascii") as source:
                status = source.read()
            rss = next(
                int(line.split()[1])
                for line in status.splitlines()
                if line.startswith("VmRSS:")
            )
            with open(os.path.join(PROCROOT, entry, "stat"), encoding="ascii") as source:
                stat = source.read()
            fields = stat[stat.rfind(")") + 1 :].split()
            ticks = int(fields[11]) + int(fields[12])
            return pid, rss, ticks
        except (OSError, StopIteration, ValueError, IndexError):
            continue
    raise ScenarioError("could not find the taema daemon in procfs")


def _m3_memory_samples(state_dir):
    """Read the daemon's persisted memory sample heartbeat without modifying it."""
    _policy, _signature, Store = _store_modules()
    store = Store(state_dir, {}, read_only=True)
    return store.latest_memory_samples()


def _m3_idle_footprint(rec, state_dir, duration=600):
    """Measure daemon RSS/CPU during ten quiet minutes with sampling and guard enabled."""
    config_path, _unit_path = _m0_config_paths()
    with open(config_path, encoding="utf-8") as source:
        config = source.read()
    enabled = (
        'mode = "enforce"' in config
        and "[guard]" in config
        and "available_floor = 18" in config
        and "[experimental]" in config
        and "guard = true" in config
        and "[freeze]" in config
    )
    rec.step("idle-sampling-and-pressure-triggers-enabled", enabled, "10-minute idle gate")
    if not enabled:
        raise ScenarioError("M3 idle gate requires memory sampling and pressure triggers")

    before = _m3_memory_samples(state_dir)
    started_wall = time.time()
    started = time.monotonic()
    previous_pid, previous_rss, previous_ticks = _m3_daemon_metrics()
    max_rss = previous_rss
    total_ticks = 0
    samples = 1
    while time.monotonic() - started < duration:
        time.sleep(min(10.0, duration - (time.monotonic() - started)))
        pid, rss, ticks = _m3_daemon_metrics()
        max_rss = max(max_rss, rss)
        if pid == previous_pid and ticks >= previous_ticks:
            total_ticks += ticks - previous_ticks
        previous_pid, previous_rss, previous_ticks = pid, rss, ticks
        samples += 1
    elapsed = time.monotonic() - started
    cpu_percent = 100.0 * total_ticks / os.sysconf("SC_CLK_TCK") / elapsed

    deadline = time.monotonic() + 75
    after = {}
    while time.monotonic() < deadline:
        after = _m3_memory_samples(state_dir)
        if any(
            isinstance(row.get("ts"), (int, float))
            and row["ts"] >= started_wall + duration - 2
            for row in after.values()
        ):
            break
        time.sleep(2)
    sample_heartbeat = any(
        isinstance(row.get("ts"), (int, float))
        and row["ts"] >= started_wall + duration - 2
        for row in after.values()
    )
    detail = {
        "duration_s": round(elapsed, 1),
        "samples": samples,
        "max_rss_kib": max_rss,
        "cpu_percent_one_core": round(cpu_percent, 4),
        "memory_sample_scopes_before": len(before),
        "memory_sample_scopes_after": len(after),
        "sample_heartbeat": sample_heartbeat,
    }
    rec.step(
        "idle-vm-footprint-under-limits",
        elapsed >= duration
        and max_rss <= 30 * 1024
        and cpu_percent <= 0.2
        and sample_heartbeat,
        json.dumps(detail, sort_keys=True),
    )


def _process_running(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            stat_line = f.read()
        return stat_line.rsplit(")", 1)[1].lstrip().split()[0] != "Z"
    except (OSError, IndexError):
        return False


def _wait_process_dead(pid, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_running(pid):
            return True
        time.sleep(0.1)
    return not _process_running(pid)


def _spawn_bound_tree(name, workdir, child_argv, timeout=10):
    os.makedirs(workdir, exist_ok=True)
    gate = os.path.join(workdir, "release-owner")
    script = (
        "import json, os, subprocess, sys, time; "
        "work, gate = sys.argv[1:3]; "
        "child = subprocess.Popen(json.loads(sys.argv[3]), "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "open(os.path.join(work, 'bound.json'), 'w').write(json.dumps("
        "{'owner': os.getpid(), 'child': child.pid})); "
        "exec('while not os.path.exists(gate):\\n time.sleep(0.05)')"
    )
    proc = subprocess.Popen(
        [
            "/usr/bin/taema",
            "run",
            "--bind",
            name,
            sys.executable,
            "-c",
            script,
            workdir,
            gate,
            json.dumps([str(x) for x in child_argv]),
        ],
        cwd=workdir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=False,
    )
    marker_path = os.path.join(workdir, "bound.json")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(marker_path):
            with open(marker_path) as f:
                pids = json.load(f)
            return {
                "root": int(pids["owner"]),
                "children": [int(pids["child"])],
                "workdir": workdir,
                "proc": proc,
                "gate": gate,
            }
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    raise ScenarioError(
        "taema run --bind %s did not start its fixture (rc=%s)" % (name, proc.poll())
    )


def _spawn_pause_process(workdir, runtime_dir, timeout=10):
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)
    marker = os.path.join(workdir, "pause.pid")
    script = (
        "import ctypes, os, signal, sys; "
        "libc = ctypes.CDLL(None, use_errno=True); "
        "libc.prctl(15, ctypes.c_char_p(b'm0pause'), 0, 0, 0); "
        "open(sys.argv[1], 'w').write(str(os.getpid())); signal.pause()"
    )
    env = dict(os.environ, XDG_RUNTIME_DIR=runtime_dir)
    proc = subprocess.Popen(
        [sys.executable, "-c", script, marker],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(marker):
            with open(marker) as f:
                pid = int(f.read())
            return {
                "root": pid,
                "children": [],
                "proc": proc,
                "workdir": workdir,
                "runtime_dir": runtime_dir,
            }
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    raise ScenarioError("m0 pause fixture did not start (rc=%s)" % proc.poll())


def _event_lines(path, event, scope=None):
    try:
        with open(path) as f:
            lines = [json.loads(line) for line in f if line.strip()]
    except OSError:
        return []
    return [
        item
        for item in lines
        if item.get("event") == event and (scope is None or item.get("scope") == scope)
    ]


def wait_for_audit_event(path, event, scope, trigger=None, timeout=60, poll=0.25):
    """Wait for one audit event matching its event name, exact scope, and optional trigger."""
    deadline = time.monotonic() + timeout
    while True:
        matches = _event_lines(path, event, scope)
        for item in matches:
            if trigger is None or item.get("trigger") == trigger:
                return item
        if time.monotonic() >= deadline:
            raise ScenarioError(
                "no %s audit event for %s (trigger=%s) within %ss"
                % (event, scope, trigger, timeout)
            )
        time.sleep(poll)


def scenario_m0(rec, args, tree_holder):
    """Exercise the 0.3.0 adopt, auto, owner-exit and observe acceptance in a live guest."""
    config_paths = _m0_config_paths()
    snapshot = _m0_snapshot(config_paths)
    log_path = os.path.join(args.state_dir, "decisions.log")
    tail = shutil.which("tail") or "/usr/bin/tail"
    if not os.path.isfile(tail):
        raise ScenarioError("tail is required by the VM survivor fixtures")
    tracked = []
    idle_fixture = None
    simulated_state_dir = os.path.join(args.artifacts, "m0-simulated-gc")
    ok = False

    def record(name, passed, detail=""):
        rec.step(name, passed, detail)
        if not passed:
            raise ScenarioError("%s: %s" % (name, detail))

    def track(tree):
        tracked.append(tree)
        tree_holder.append(tree)
        return tree

    try:
        status = _m0_write_mode("adopt", idle_grace=3600, adopt_interval=2)
        record("adopt-mode-ready", status.returncode == 0, status.stdout[:300])

        tree = track(
            spawn_gui_tree(os.path.join(args.artifacts, "m0-adopt"), children=2)
        )
        adopted = wait_for_scope(tree["root"], ["app-"], timeout=30)
        record(
            "adopt-root-contained", True, "root=%d scope=%s" % (tree["root"], adopted)
        )
        time.sleep(max(5.5, configured_adopt_interval() + 1.0))
        adopt_interval = configured_adopt_interval()
        close_root(tree["root"], timeout=15)
        closed_at = time.monotonic()
        leftover = wait_for_scope(
            tree["children"][0], ["leftover/"], timeout=adopt_interval + 2.0, poll=0.05
        )
        contained_at = time.monotonic()
        containment_latency = contained_at - closed_at
        members = [assert_scope_member(pid, "leftover/") for pid in tree["children"]]
        record(
            "adopt-survivors-contained",
            members[0] == members[1] == leftover,
            "scope=%s members=%s" % (leftover, members),
        )
        record(
            "adopt-containment-within-one-interval",
            containment_latency <= adopt_interval + 0.1,
            "close_to_containment=%.3fs adopt_interval=%.3fs poll_tolerance=0.1s"
            % (containment_latency, adopt_interval),
        )
        review = _run(["/usr/bin/taema", "review"], timeout=30)
        leftover_leaf = daemon_scope(leftover)
        review_events = _event_lines(log_path, "review_created", leftover_leaf)
        record(
            "adopt-review-lists-contained-survivors",
            review.returncode == 0
            and "open reviews:" in review.stdout
            and "owner=" in review.stdout
            and "survivors=sleep" in review.stdout
            and bool(review_events),
            "scope=%s review=%s event=%s"
            % (
                leftover,
                (review.stdout + review.stderr)[:700],
                review_events[-1:] or "missing",
            ),
        )

        veto = _run(["/usr/bin/taema", "do-not-kill", "app:sleep"], timeout=30)
        record(
            "adopt-do-not-kill-app",
            veto.returncode == 0,
            (veto.stdout + veto.stderr).strip()[:400],
        )
        refused = _run(["/usr/bin/taema", "kill", leftover_leaf], timeout=30)
        record(
            "adopt-manual-kill-refused-with-four",
            refused.returncode == 4
            and "app sleep" in (refused.stdout + refused.stderr)
            and all(_process_running(pid) for pid in tree["children"]),
            "rc=%d output=%s"
            % (refused.returncode, (refused.stdout + refused.stderr).strip()[:500]),
        )

        bound = track(
            _spawn_bound_tree(
                "m0-bind",
                os.path.join(args.artifacts, "m0-bind"),
                [tail, "-f", "/dev/null"],
            )
        )
        bound_scope = wait_for_scope(bound["root"], ["scope-m0-bind"], timeout=30)
        open(bound["gate"], "w").close()
        bound["proc"].wait(timeout=20)
        bound_child_dead = _wait_process_dead(bound["children"][0])
        bound_scope_gone = wait_for_scope_gone(bound_scope, timeout=20, poll=0.05)
        record(
            "adopt-bind-owner-exit-stops-scope",
            bound_child_dead and bound_scope_gone,
            "scope=%s child=%d child_dead=%s scope_gone=%s"
            % (bound_scope, bound["children"][0], bound_child_dead, bound_scope_gone),
        )

        bound_veto = track(
            _spawn_bound_tree(
                "m0-veto",
                os.path.join(args.artifacts, "m0-veto"),
                ["/bin/sleep", "3600"],
            )
        )
        veto_scope = wait_for_scope(bound_veto["root"], ["scope-m0-veto"], timeout=30)
        veto_leaf = daemon_scope(veto_scope)
        refused = _run(["/usr/bin/taema", "kill", "m0-veto"], timeout=30)
        record(
            "app-vetoed-bound-manual-kill-refused-with-four",
            refused.returncode == 4
            and "app sleep" in (refused.stdout + refused.stderr)
            and _process_running(bound_veto["children"][0]),
            "rc=%d output=%s"
            % (refused.returncode, (refused.stdout + refused.stderr).strip()[:500]),
        )
        open(bound_veto["gate"], "w").close()
        bound_veto["proc"].wait(timeout=20)
        owner_veto_event = wait_for_audit_event(
            log_path, "vetoed", veto_leaf, trigger="owner_exit", timeout=30
        )
        record(
            "app-vetoed-owner-close-stops-nothing",
            _process_running(bound_veto["children"][0])
            and scope_of(bound_veto["children"][0]) == veto_scope
            and "app sleep" in owner_veto_event.get("target", ""),
            "scope=%s child=%d event=%s"
            % (veto_scope, bound_veto["children"][0], owner_veto_event),
        )

        status = _m0_write_mode("observe", idle_grace=3600, adopt_interval=2)
        record("observe-mode-ready", status.returncode == 0, status.stdout[:300])
        observed = track(
            spawn_gui_tree(
                os.path.join(args.artifacts, "m0-observe"),
                children=1,
                child_argv=[tail, "-f", "/dev/null"],
            )
        )
        original_scope = scope_of(observed["children"][0])
        wait_for_event(log_path, "adopt_would", timeout=30)
        time.sleep(max(5.5, configured_adopt_interval() + 1.0))
        close_root(observed["root"], timeout=15)
        wait_for_event(log_path, "would_contain", timeout=30)
        record(
            "observe-close-mutates-no-scope-or-process",
            _process_running(observed["children"][0])
            and scope_of(observed["children"][0]) == original_scope
            and not scope_matches(original_scope, "app-")
            and not scope_matches(original_scope, "leftover/"),
            "child=%d before=%s after=%s"
            % (
                observed["children"][0],
                original_scope,
                scope_of(observed["children"][0]),
            ),
        )

        status = _m0_write_mode(
            "auto", idle_grace=0, adopt_interval=2, gc_interval=3600
        )
        record("auto-mode-ready", status.returncode == 0, status.stdout[:300])
        automatic = track(
            spawn_gui_tree(
                os.path.join(args.artifacts, "m0-auto-leftover"),
                children=1,
                child_argv=[tail, "-f", "/dev/null"],
            )
        )
        wait_for_scope(automatic["root"], ["app-"], timeout=30)
        time.sleep(max(5.5, configured_adopt_interval() + 1.0))
        close_root(automatic["root"], timeout=15)
        auto_leftover = wait_for_scope(
            automatic["children"][0], ["leftover/"], timeout=30
        )
        gc_result = _run(["/usr/bin/taema", "gc"], timeout=30)
        review = _run(["/usr/bin/taema", "review"], timeout=30)
        auto_leaf = daemon_scope(auto_leftover)
        auto_review_events = _event_lines(log_path, "review_created", auto_leaf)
        record(
            "auto-keeps-and-reviews-unlearned-leftover",
            gc_result.returncode == 0
            and review.returncode == 0
            and _process_running(automatic["children"][0])
            and scope_of(automatic["children"][0]) == auto_leftover
            and "survivors=tail" in review.stdout
            and bool(auto_review_events),
            "scope=%s gc=%s review=%s event=%s"
            % (
                auto_leftover,
                gc_result.stdout[-500:],
                review.stdout[-700:],
                auto_review_events[-1:] or "missing",
            ),
        )

        eligible = track(
            _spawn_pause_process(
                os.path.join(args.artifacts, "m0-pause-eligible"),
                os.path.join(args.artifacts, "runtime-eligible"),
            )
        )
        vetoed = track(
            _spawn_pause_process(
                os.path.join(args.artifacts, "m0-pause-vetoed"),
                os.path.join(args.artifacts, "runtime-vetoed"),
            )
        )
        eligible_scope = wait_for_scope(eligible["root"], ["app-m0pause-"], timeout=30)
        vetoed_scope = wait_for_scope(vetoed["root"], ["app-m0pause-"], timeout=30)
        vetoed_leaf = daemon_scope(vetoed_scope)
        time.sleep(35)
        scope_veto = _run(
            ["/usr/bin/taema", "do-not-kill", "scope:" + vetoed_leaf], timeout=30
        )
        record(
            "auto-pause-veto-registered",
            scope_veto.returncode == 0,
            (scope_veto.stdout + scope_veto.stderr).strip()[:400],
        )
        os.rmdir(eligible["runtime_dir"])
        eligible_gc = _run(["/usr/bin/taema", "gc"], timeout=30)
        eligible_process_dead = _wait_process_dead(eligible["root"])
        eligible_scope_gone = wait_for_scope_gone(eligible_scope, timeout=20, poll=0.05)
        record(
            "auto-stops-idle-pause-after-runtime-disappears",
            eligible_gc.returncode == 0
            and eligible_process_dead
            and eligible_scope_gone,
            "scope=%s process_dead=%s scope_gone=%s gc=%s"
            % (
                eligible_scope,
                eligible_process_dead,
                eligible_scope_gone,
                eligible_gc.stdout[-700:],
            ),
        )
        os.rmdir(vetoed["runtime_dir"])
        vetoed_gc = _run(["/usr/bin/taema", "gc"], timeout=30)
        gc_veto_event = wait_for_audit_event(
            log_path, "vetoed", vetoed_leaf, trigger="gc_stop", timeout=30
        )
        record(
            "auto-gc-veto-keeps-pause-scope",
            vetoed_gc.returncode == 0
            and _process_running(vetoed["root"])
            and scope_of(vetoed["root"]) == vetoed_scope,
            "scope=%s gc=%s event=%s"
            % (vetoed_scope, vetoed_gc.stdout[-700:], gc_veto_event),
        )

        # Create a genuine app scope in adopt mode, then restart in observe mode so the
        # real-hour GC can only report its would-stop decision.
        status = _m0_write_mode("adopt", idle_grace=3600, adopt_interval=2)
        record("idle-gc-adopt-mode-ready", status.returncode == 0, status.stdout[:300])
        idle_runtime = os.path.join(args.artifacts, "runtime-idle-hour")
        idle_fixture = track(
            _spawn_pause_process(
                os.path.join(args.artifacts, "m0-idle-hour"), idle_runtime
            )
        )
        idle_pid = idle_fixture["root"]
        idle_scope = wait_for_scope(idle_pid, ["app-m0pause"], timeout=30)
        idle_leaf = daemon_scope(idle_scope)
        idle_scope_path = os.path.join(CGROOT, idle_scope)
        record(
            "idle-gc-process-in-daemon-scope",
            assert_scope_member(idle_pid, "app-m0pause/") == idle_scope
            and os.path.isdir(idle_runtime),
            "pid=%d scope=%s runtime=%s" % (idle_pid, idle_scope, idle_runtime),
        )

        status = _m0_write_mode("observe", idle_grace=3600, adopt_interval=2)
        record(
            "simulated-gc-observe-mode-ready",
            status.returncode == 0,
            status.stdout[:300],
        )
        sys.path.insert(0, "/usr/lib/taema")
        from taema import (
            daemon as taema_daemon,
            engine as taema_engine,
            policy as taema_policy,
        )

        cfg = taema_policy.load_config()
        cfg["mode"] = "observe"
        cfg["timers"]["idle_grace"] = 3600
        cfg["paths"]["state_dir"] = simulated_state_dir
        simulated_daemon = taema_daemon.Daemon(cfg)
        started = time.time()
        simulated_now = [started]
        simulated_daemon.store.now = lambda: simulated_now[0]
        with mock.patch.object(
            taema_engine,
            "gc_candidates",
            return_value=[(idle_scope_path, "idle 3600s >= grace 3600s")],
        ):
            result = simulated_daemon.gc_pass()
            first_event = _event_lines(
                simulated_daemon.store.log_path, "gc_would_stop", idle_leaf
            )
            for minute in range(1, 24 * 60 + 1):
                simulated_now[0] = started + minute * 60
                simulated_daemon.gc_pass()
        all_events = _event_lines(
            simulated_daemon.store.log_path, "gc_would_stop", idle_leaf
        )
        record(
            "one-hour-idle-and-simulated-day-deduplicate-would-stop",
            bool(result)
            and result[0][2] == "would"
            and len(first_event) == 1
            and len(all_events) == 1
            and _process_running(idle_pid)
            and daemon_scope(scope_of(idle_pid)) == idle_leaf,
            "simulated_result=%s minutes=1440 would_stop_lines=%d"
            % (result, len(all_events)),
        )

        initial_gc = _run(["/usr/bin/taema", "gc"], timeout=30)
        initial_events = _event_lines(log_path, "gc_would_stop", idle_leaf)
        record(
            "real-hour-idle-window-started",
            initial_gc.returncode == 0
            and not initial_events
            and _process_running(idle_pid)
            and daemon_scope(scope_of(idle_pid)) == idle_leaf,
            "scope=%s gc=%s prior_would_stop_lines=%d"
            % (idle_leaf, initial_gc.stdout[-500:], len(initial_events)),
        )
        real_idle_started = time.monotonic()
        time.sleep(3602)
        real_passes = [_run(["/usr/bin/taema", "gc"], timeout=30) for _ in range(3)]
        real_elapsed = time.monotonic() - real_idle_started
        real_events = _event_lines(log_path, "gc_would_stop", idle_leaf)
        record(
            "one-hour-idle-would-stop-is-deduplicated",
            real_elapsed >= 3600
            and all(r.returncode == 0 for r in real_passes)
            and len(real_events) == 1
            and _process_running(idle_pid)
            and daemon_scope(scope_of(idle_pid)) == idle_leaf,
            "real_idle_seconds=%.1f scope=%s gc_passes=3 would_stop_lines=%d last_gc=%s"
            % (
                real_elapsed,
                idle_leaf,
                len(real_events),
                real_passes[-1].stdout[-500:],
            ),
        )
        ok = all(step["ok"] for step in rec.steps)
    finally:
        for tree in tracked:
            kill_tree(tree, timeout=5)
        if idle_fixture is not None:
            try:
                shutil.rmtree(idle_fixture["runtime_dir"])
            except OSError:
                pass
        # The Store makes this directory private (0700/0600). Keep the
        # simulated audit log in the step evidence and remove private state
        # before vmh recursively collects the public artifact tree as vmadmin.
        try:
            shutil.rmtree(simulated_state_dir)
        except OSError:
            pass
        restored = _m0_restore(snapshot)
        ok = ok and restored.returncode == 0
    return ok


def _store_modules():
    """Load the installed store in a guest or the source package in host tests."""
    installed = "/usr/lib/taema"
    source = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    )
    if os.path.isfile(os.path.join(source, "taema", "config", "policy.py")):
        module_path = source
    elif os.path.isfile(os.path.join(installed, "taema", "config", "policy.py")):
        module_path = installed
    else:
        raise ScenarioError("taema store modules are unavailable")
    if module_path not in sys.path:
        sys.path.insert(0, module_path)
    sys.dont_write_bytecode = True
    from taema.config import policy
    from taema.core import signature as survivor_signature
    from taema.store.knowledge import Store

    return policy, survivor_signature, Store


def replay_learning_fixture(fixture_path, state_dir):
    """Replay the committed anonymized learning history and return safety evidence."""
    policy, survivor_signature, Store = _store_modules()
    day = 86400
    with open(fixture_path, encoding="utf-8") as stream:
        fixture = json.load(stream)
    now = [0.0]
    store = Store(state_dir, {}, now=lambda: now[0])
    signature_ids = {}
    stop_decision_ids = []

    for event in fixture["events"]:
        now[0] = event["at_day"] * day + event.get("after_seconds", 0)
        owner, leftover, operation = (
            event["owner"],
            event["leftover"],
            event["op"],
        )
        pair = (owner, leftover)
        if operation == "inferred_kill":
            store.observe_kill_inferred(owner, leftover, day=event["day"])
        elif operation == "close":
            store.observe_close(owner, leftover)
        elif operation == "answer":
            store.answer(owner, leftover, event["choice"])
        elif operation == "signature_stop":
            store.observe_close(owner, leftover)
            descriptor = survivor_signature.signature(owner, [leftover])
            descriptor = store.observe_signature_close(descriptor)
            if not descriptor or not store.answer_signature(owner, descriptor, "stop"):
                raise ScenarioError("fixture signature answer was rejected")
            signature_ids[pair] = descriptor["id"]
        elif operation == "auto_stop":
            authority, why = event.get("authority"), event.get("why")
            if not isinstance(authority, str) or not authority or not why:
                raise ScenarioError("fixture stop is missing authorization evidence")
            signature_id = signature_ids[pair]
            with store.decision_context(
                "stop",
                scope="leftover/replay",
                owner=owner,
                authority=authority,
                why=why,
            ) as decision:
                store.auto_stopped(owner, leftover, signature_id)
                action = store.record_auto_action(
                    "leftover/replay",
                    why,
                    [(owner, leftover)],
                    apps=[leftover],
                    decision=decision,
                    owner=owner,
                    authority=authority,
                    signature_id=signature_id,
                )
            stop_decision_ids.append(action["decision_id"])
        elif operation == "respawn_and_regret":
            signature_id = signature_ids[pair]
            store.auto_stop_respawn(owner, leftover, signature_id)
            store.regret(owner, leftover, signature_id)
        else:
            raise ScenarioError("unknown replay operation %r" % operation)

    now[0] = fixture["now_day"] * day
    store.save()
    reopened = Store(state_dir, {}, now=lambda: now[0], read_only=True)
    generic_owners = [
        pair["owner"]
        for pair in reopened.pairs_summary(limit=1000)
        if pair.get("action") != "invalid" and policy.bad_owner(pair.get("owner"))
    ]
    decisions = [reopened.decision(identifier) for identifier in stop_decision_ids]
    return {
        "active_generic_owners": sorted(set(generic_owners)),
        "stop_count": len(decisions),
        "stops_without_reason": sum(
            not decision or not decision.get("authority") or not decision.get("why")
            for decision in decisions
        ),
        "reopened_pairs": len(reopened.pairs_summary(limit=1000)),
    }


def wait_for_status(timeout=60, poll=0.5):
    """Wait for the current per-user daemon to answer the public status command."""
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        result = _run(["/usr/bin/taema", "status"], timeout=10)
        if result.returncode == 0:
            return result
        time.sleep(poll)
    return result or _run(["/usr/bin/taema", "status"], timeout=10)


def audit_events_after(path, offset):
    try:
        with open(path, "rb") as stream:
            stream.seek(offset)
            lines = stream.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def audit_stopped_pid(event, pid):
    """Whether a stop event records a kill for the given process."""
    if pid in event.get("pids", []):
        return True
    return any(decision.get("pid") == pid for decision in event.get("decisions", []))


def wait_for_audit_event_after(
    path, offset, name, predicate=None, timeout=60, poll=0.25
):
    """Wait for a matching event appended after a scenario-specific log cursor."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in audit_events_after(path, offset):
            if event.get("event") == name and (predicate is None or predicate(event)):
                return event
        time.sleep(poll)
    raise ScenarioError("no new %s audit event appeared within %ss" % (name, timeout))


def wait_for_review_signature(Store, state_dir, review_id, timeout=15, poll=0.25):
    """Wait for the daemon's audit event and SQLite review row to converge."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reviews = Store(state_dir, {}, read_only=True).open_reviews()
        review = next((row for row in reviews if row.get("id") == review_id), None)
        if review and review.get("sig"):
            return review["sig"]
        time.sleep(poll)
    return None


def wait_for_auto_action(Store, state_dir, decision_id, timeout=15, poll=0.25):
    """Wait until the stop's audit event is committed to the SQLite store."""
    if not isinstance(decision_id, int) or isinstance(decision_id, bool):
        store = Store(state_dir, {}, read_only=True)
        return store, None, None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        store = Store(state_dir, {}, read_only=True)
        action = store.auto_action(decision_id)
        decision = store.decision(decision_id)
        if action and decision:
            return store, action, decision
        time.sleep(poll)
    return store, action, decision


def wait_for_signature_veto(Store, state_dir, signature_id, timeout=15, poll=0.25):
    """Wait for an undo's signature veto to appear in the durable store."""
    if not signature_id:
        return None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        veto = Store(state_dir, {}, read_only=True).match_veto(signature=signature_id)
        if veto:
            return veto
        time.sleep(poll)
    return None


def install_previous_release(rec, args):
    """Install and verify the previous package used by upgrade acceptance cases."""
    prevdir = os.path.dirname(args.previous)
    index = run_privileged(["xbps-rindex", "-f", "-a", args.previous])
    rec.step(
        "index-previous", index.returncode == 0, (index.stdout + index.stderr)[-600:]
    )
    installed = run_privileged(
        ["xbps-install", "-y", "-i", "--repository", prevdir, "taema"]
    )
    rec.step(
        "install-previous",
        installed.returncode == 0,
        (installed.stdout + installed.stderr)[-600:],
    )
    version = _run(["/usr/bin/taema", "--version"])
    rec.step(
        "previous-version",
        args.previous_version in (version.stdout + version.stderr),
        (version.stdout + version.stderr).strip()[:200],
    )


def install_current_release(rec, args):
    """Install and verify the current package from the transferred repository."""
    installed = run_privileged(
        ["xbps-install", "-y", "-i", "--repository", args.package_dir, "taema"]
    )
    rec.step(
        "install-current",
        installed.returncode == 0,
        (installed.stdout + installed.stderr)[-600:],
    )
    version = _run(["/usr/bin/taema", "--version"])
    rec.step(
        "current-version",
        args.current_version in (version.stdout + version.stderr),
        (version.stdout + version.stderr).strip()[:200],
    )
    status = wait_for_status()
    rec.step(
        "current-daemon-ready",
        status.returncode == 0,
        (status.stdout or status.stderr)[:300],
    )
    service = run_privileged(["sv", "status", "/var/service/taema"])
    rec.step(
        "service-up",
        service.returncode == 0,
        (service.stdout + service.stderr).strip()[:300],
    )


def scenario_m1(rec, args, tree_holder):
    """Upgrade a live VM from 0.3 JSON state to the SQLite release."""
    if not args.previous or not args.package_dir or not args.migration_fixture:
        raise ScenarioError(
            "M1 needs previous/current packages and a migration fixture"
        )

    tree = spawn_gui_tree(os.path.join(args.artifacts, "m1-live-app"), children=2)
    tree_holder.append(tree)
    original_scope = wait_for_scope(tree["root"], ["app-"], timeout=90)
    app_scope = daemon_scope(original_scope)
    rec.step("live-app-managed", True, "scope=%s" % app_scope)

    state_dir = args.state_dir
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    old_daemon = run_privileged(["sv", "down", "/var/service/taema"])
    rec.step("stop-old-daemon", old_daemon.returncode == 0, old_daemon.stderr[-400:])
    removed = run_privileged(["xbps-remove", "-y", "taema"])
    rec.step("remove-current-package", removed.returncode == 0, removed.stderr[-400:])

    for name in ("state.db", "state.db-wal", "state.db-shm"):
        try:
            os.unlink(os.path.join(state_dir, name))
        except FileNotFoundError:
            pass
    legacy_path = os.path.join(state_dir, "knowledge.json")
    shutil.copyfile(args.migration_fixture, legacy_path)
    os.chmod(legacy_path, 0o600)
    migration_log = os.path.join(state_dir, "decisions.log")
    try:
        with open(migration_log, "rb") as stream:
            log_offset = os.fstat(stream.fileno()).st_size
    except OSError:
        log_offset = 0

    install_previous_release(rec, args)
    install_current_release(rec, args)

    _policy, _signature, Store = _store_modules()
    migrated = Store(state_dir, {}, read_only=True)
    stop = migrated.pair_decision("npm", "vite")[0]
    keep = migrated.pair_decision("editor", "language-server")[0]
    invalid = migrated.pair_decision("MainThread", "sh")[0]
    review = next(
        (
            item
            for item in migrated.open_reviews()
            if item.get("kind") == "legacy-invalid"
            and item.get("owner") == "MainThread"
            and item.get("answer") == "stop"
        ),
        None,
    )
    backups = sorted(glob.glob(legacy_path + ".backup-*"))
    backup_ok = False
    if backups:
        try:
            with open(backups[-1], encoding="utf-8") as stream:
                backup = json.load(stream)
            pair = backup.get("pairs", {}).get("npm\0vite", {})
            backup_ok = (
                pair.get("ex_last") == "stop"
                and os.stat(backups[-1]).st_mode & 0o777 == 0o600
            )
        except (OSError, ValueError):
            backup_ok = False
    rec.step(
        "valid-decisions-preserved",
        stop == "stop" and keep == "keep",
        "stop=%s keep=%s" % (stop, keep),
    )
    rec.step(
        "invalid-answer-reviewed",
        invalid == "invalid" and review is not None,
        "pair=%s review=%s" % (invalid, bool(review)),
    )
    rec.step("private-backup-kept", backup_ok, "files=%d" % len(backups))

    stop_events = [
        event
        for event in audit_events_after(migration_log, log_offset)
        if event.get("event") in ("stop", "auto_stop")
    ]
    live = all(_alive(pid) for pid in [tree["root"]] + tree["children"])
    scope_after = daemon_scope(scope_of(tree["root"]))
    no_stop = live and scope_after == app_scope and not stop_events
    rec.step(
        "migration-stopped-nothing",
        no_stop,
        "live=%s same_scope=%s stop_events=%d"
        % (live, scope_after == app_scope, len(stop_events)),
    )
    return all(step["ok"] for step in rec.steps)


def scenario_m2(rec, args, tree_holder):
    """Exercise live signature stops, undo, offline vetoes, and replay safety."""
    if not args.replay_fixture:
        raise ScenarioError("M2 needs the committed anonymized replay fixture")
    with tempfile.TemporaryDirectory(prefix="taema-learning-replay-") as replay_state:
        replay = replay_learning_fixture(args.replay_fixture, replay_state)
    replay_ok = (
        not replay["active_generic_owners"] and not replay["stops_without_reason"]
    )
    rec.step(
        "replay-fixture-authorization", replay_ok, json.dumps(replay, sort_keys=True)
    )

    _policy, _signature, Store = _store_modules()
    config_path = _m0_config_paths()[0]
    config_snapshot = _m0_snapshot((config_path,))
    tracked = []
    log_path = os.path.join(args.state_dir, "decisions.log")

    def track(tree):
        tracked.append(tree)
        tree_holder.append(tree)
        return tree

    def start_signature_tree(workdir, child_argv=None, sample_cpu=False):
        for name in ("tree.json", "tree.json.tmp", "supervisor.pid"):
            try:
                os.unlink(os.path.join(workdir, name))
            except FileNotFoundError:
                pass
        tree = track(spawn_gui_tree(workdir, children=1, child_argv=child_argv))
        scope = wait_for_scope(tree["root"], ["app-"], timeout=90)
        ready_delay = max(5.5, configured_adopt_interval() + 1.0)
        if sample_cpu:
            # Auto-stop refuses a process until lineage has at least 30 seconds
            # of CPU history; give the guest clock one extra sampling interval.
            ready_delay = max(ready_delay, 31.5)
        time.sleep(ready_delay)
        return tree, scope

    def log_offset():
        try:
            return os.stat(log_path).st_size
        except OSError:
            return 0

    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as stream:
            stream.write(
                'mode = "adopt"\n\n[timers]\n'
                "adopt_interval = 2\ngc_interval = 3600\n\n"
                "[learn]\nrespawn_window = 0\nregret_window = 0\n"
            )
        restarted = run_privileged(["sv", "restart", "/var/service/taema"])
        ready = wait_for_status()
        rec.step(
            "adopt-mode-ready",
            restarted.returncode == 0
            and ready.returncode == 0
            and "mode: adopt" in ready.stdout,
            (ready.stdout or ready.stderr)[:300],
        )

        workdir = os.path.join(args.artifacts, "m2-signature-app")
        first, first_app_scope = start_signature_tree(workdir)
        first_offset = log_offset()
        close_root(first["root"], timeout=15)
        first_review = wait_for_audit_event_after(
            log_path,
            first_offset,
            "review_created",
            predicate=lambda event: bool(event.get("id") and event.get("owner")),
            timeout=60,
        )
        first_signature_id = wait_for_review_signature(
            Store, args.state_dir, first_review["id"]
        )
        first_leftover = wait_for_scope(first["children"][0], ["leftover/"], timeout=30)
        first_kept = (
            _alive(first["children"][0])
            and assert_scope_member(first["children"][0], "leftover/") == first_leftover
        )
        rec.step(
            "initial-signature-review-keeps-survivor",
            first_kept
            and daemon_scope(first_app_scope).startswith("app-")
            and bool(first_signature_id),
            "review=%s signature=%s scope=%s alive=%s"
            % (first_review.get("id"), first_signature_id, first_leftover, first_kept),
        )
        answer = _run(
            ["/usr/bin/taema", "answer", str(first_review["id"]), "stop"], timeout=30
        )
        rec.step(
            "explicit-signature-stop-answered",
            answer.returncode == 0,
            (answer.stdout or answer.stderr).strip()[:300],
        )

        identical, _identical_app_scope = start_signature_tree(workdir, sample_cpu=True)
        identical_offset = log_offset()
        close_root(identical["root"], timeout=15)
        stop_event = wait_for_audit_event_after(
            log_path,
            identical_offset,
            "stop",
            predicate=lambda event: audit_stopped_pid(event, identical["children"][0]),
            timeout=60,
        )
        decision_id = stop_event.get("decision_id")
        _stop_store, action, decision = wait_for_auto_action(
            Store, args.state_dir, decision_id
        )
        killed = _wait_process_dead(identical["children"][0], timeout=20)
        undo_payload = decision.get("undo") if decision else None
        signature_id = (
            undo_payload.get("signature_id") if isinstance(undo_payload, dict) else None
        )
        rec.step(
            "identical-signature-relaunch-is-stopped",
            killed
            and action is not None
            and decision is not None
            and decision.get("kind") in ("stop", "auto_stop")
            and decision.get("authority")
            and decision.get("why")
            and signature_id
            and signature_id == first_signature_id,
            "pid=%d killed=%s action=%s signature_matches_review=%s decision=%s"
            % (
                identical["children"][0],
                killed,
                bool(action),
                signature_id == first_signature_id,
                {
                    "kind": decision.get("kind") if decision else None,
                    "authority": decision.get("authority") if decision else None,
                    "why": decision.get("why") if decision else None,
                },
            ),
        )

        undo = _run(["/usr/bin/taema", "undo", str(decision_id)], timeout=30)
        undo_veto = wait_for_signature_veto(Store, args.state_dir, signature_id)
        rec.step(
            "cli-undo-vetoes-signature",
            undo.returncode == 0
            and undo_veto is not None
            and undo_veto.get("reason") == "undo automatic stop",
            (undo.stdout or undo.stderr).strip()[:300],
        )

        after_undo_tree, _after_undo_app_scope = start_signature_tree(
            workdir, sample_cpu=True
        )
        after_undo_offset = log_offset()
        close_root(after_undo_tree["root"], timeout=15)
        after_undo_scope = wait_for_scope(
            after_undo_tree["children"][0], ["leftover/"], timeout=30
        )
        after_undo_review = wait_for_audit_event_after(
            log_path,
            after_undo_offset,
            "review_created",
            predicate=lambda event: (
                event.get("scope") == daemon_scope(after_undo_scope)
            ),
            timeout=60,
        )
        after_undo_events = audit_events_after(log_path, after_undo_offset)
        next_stop = any(
            event.get("event") == "stop"
            and audit_stopped_pid(event, after_undo_tree["children"][0])
            for event in after_undo_events
        )
        veto_still_active = (
            wait_for_signature_veto(Store, args.state_dir, signature_id) is not None
        )
        rec.step(
            "undo-blocks-next-identical-stop",
            _alive(after_undo_tree["children"][0])
            and not next_stop
            and veto_still_active
            and bool(after_undo_review),
            "pid=%d alive=%s stopped=%s veto=%s review=%s"
            % (
                after_undo_tree["children"][0],
                _alive(after_undo_tree["children"][0]),
                next_stop,
                veto_still_active,
                after_undo_review.get("id"),
            ),
        )

        tail = shutil.which("tail") or "/usr/bin/tail"
        changed, _changed_app_scope = start_signature_tree(
            workdir, child_argv=[tail, "-f", "/dev/null"], sample_cpu=True
        )
        changed_offset = log_offset()
        close_root(changed["root"], timeout=15)
        changed_scope = wait_for_scope(
            changed["children"][0], ["leftover/"], timeout=30
        )
        changed_review = wait_for_audit_event_after(
            log_path,
            changed_offset,
            "review_created",
            predicate=lambda event: event.get("scope") == daemon_scope(changed_scope),
            timeout=60,
        )
        changed_events = audit_events_after(log_path, changed_offset)
        changed_stopped = any(
            event.get("event") == "stop"
            and audit_stopped_pid(event, changed["children"][0])
            for event in changed_events
        )
        changed_signature = wait_for_review_signature(
            Store, args.state_dir, changed_review["id"]
        )
        rec.step(
            "changed-signature-does-not-inherit-stop",
            _alive(changed["children"][0])
            and not changed_stopped
            and bool(changed_review)
            and changed_signature
            and changed_signature != signature_id,
            "pid=%d alive=%s stopped=%s prior_signature=%s changed_signature=%s"
            % (
                changed["children"][0],
                _alive(changed["children"][0]),
                changed_stopped,
                signature_id,
                changed_signature,
            ),
        )

        tree = track(
            spawn_gui_tree(os.path.join(args.artifacts, "m2-offline-veto"), children=1)
        )
        rel = wait_for_scope(tree["root"], ["app-"], timeout=90)
        scope = daemon_scope(rel)
        down = run_privileged(["sv", "down", "/var/service/taema"])
        veto = _run(
            [
                "/usr/bin/taema",
                "do-not-kill",
                "--scope",
                scope,
                "--reason",
                "VM offline veto acceptance",
            ]
        )
        refused = _run(["/usr/bin/taema", "kill", "scope:" + scope], timeout=30)
        survives = all(_alive(pid) for pid in [tree["root"]] + tree["children"])
        rec.step("stop-daemon-for-veto", down.returncode == 0, down.stderr[-300:])
        rec.step(
            "offline-veto-queues",
            veto.returncode == 0,
            (veto.stdout or veto.stderr).strip()[:300],
        )
        rec.step(
            "kill-refuses-with-exit-4",
            refused.returncode == 4 and survives,
            "rc=%d alive=%s output=%s"
            % (
                refused.returncode,
                survives,
                (refused.stderr or refused.stdout).strip()[:300],
            ),
        )
        restarted = run_privileged(["sv", "up", "/var/service/taema"])
        status = wait_for_status()
        rec.step(
            "daemon-restored-after-offline-veto",
            restarted.returncode == 0 and status.returncode == 0,
            (status.stdout or status.stderr)[:300],
        )
    finally:
        restored = _m0_restore(config_snapshot)
        rec.step(
            "daemon-config-restored",
            restored.returncode == 0,
            (restored.stdout + restored.stderr).strip()[:300],
        )
        for tree in tracked:
            kill_tree(tree, timeout=5)

    return all(step["ok"] for step in rec.steps)


def _m3_qmp_save_hook(rec, args, tracked):
    """Prove an attached QMP client blocks a fake VM save-and-stop hook."""
    config_path, example_unit = _m0_config_paths()
    unit_path = os.path.join(os.path.dirname(example_unit), "m3-qmp.toml")
    config_snapshot = _m0_snapshot([config_path, unit_path])
    workdir = os.path.join(args.artifacts, "m3-qmp")
    os.makedirs(workdir, exist_ok=True)
    qmp_path = os.path.join(workdir, "monitor.sock")
    pidfile = os.path.join(workdir, "server.pid")
    ready = os.path.join(workdir, "ready")
    saved = os.path.join(workdir, "saved")
    tree = None
    client = None
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as target:
            target.write(_m3_qmp_probe_config())
        save_script = "import sys; open(sys.argv[1], 'w').write('saved\\n')"
        unit = (
            '[unit]\nname = "app-m3-qmp"\nkind = "app"\nclass = "vm"\n'
            'domain = "m3-vm"\ngroup_by_qmp = true\nstop_when_unneeded = true\n\n'
            '[match]\ncomm = "qemu-system-m3"\n\n'
            '[mem]\nidle_reclaim = true\nsave_state = [%s, "-c", %s, %s]\n\n'
            '[gc]\nqmp_socket = true\nno_attach_grace = 0\n'
            % (json.dumps(sys.executable), json.dumps(save_script), json.dumps(saved))
        )
        os.makedirs(os.path.dirname(unit_path), exist_ok=True)
        with open(unit_path, "w", encoding="utf-8") as target:
            target.write(unit)
        restart = run_privileged(["sv", "restart", "taema"], timeout=45)
        rec.step(
            "fake-qmp-unit-loaded",
            restart.returncode == 0,
            (restart.stdout + restart.stderr).strip()[-300:],
        )
        if restart.returncode != 0:
            raise ScenarioError("could not load the fake QMP save-hook unit")

        tree = spawn_gui_tree(
            workdir,
            children=1,
            child_argv=[
                sys.executable,
                "-c",
                M3_QMP_SERVER,
                qmp_path,
                pidfile,
                ready,
                "-qmp",
                "unix:%s,server=on,wait=off" % qmp_path,
                "-name",
                "guest=m3-vm",
            ],
            root_comm="m3qmp-root",
            root_exec=["/bin/sleep", "3600"],
        )
        tracked.append(tree)
        server_pid = tree["children"][0]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not os.path.isfile(ready):
            time.sleep(0.1)
        ready_ok = os.path.isfile(ready) and os.path.exists(qmp_path)
        rec.step("fake-qmp-server-ready", ready_ok, "pid=%d socket=%s" % (server_pid, qmp_path))
        if not ready_ok:
            raise ScenarioError("fake QMP server did not bind its monitor socket")
        scope = wait_for_scope(server_pid, ["app-m3-qmp-"], timeout=90)

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(3)
        client.connect(qmp_path)
        client.sendall(b'{"execute":"qmp_capabilities"}\n')
        time.sleep(0.5)
        attached_gc = _run(
            ["/usr/bin/taema", "gc", "--memory", "--json"], timeout=60
        )
        try:
            attached_model = json.loads(attached_gc.stdout)
            attached_result = attached_model.get("result", {})
        except (ValueError, AttributeError):
            attached_result = {}
        attached_candidates = attached_result.get("candidates", [])
        attached_candidate = any(
            isinstance(row, list)
            and row
            and row[0] == daemon_scope(scope)
            for row in attached_candidates
        )
        attached_memory = attached_result.get("memory", [])
        attached_scope_result = next(
            (
                row
                for row in attached_memory
                if isinstance(row, dict) and row.get("scope") == daemon_scope(scope)
            ),
            {},
        )
        blocked = (
            attached_gc.returncode == 0
            and _process_running(server_pid)
            and not os.path.exists(saved)
            and not attached_candidate
            and "dependency" in attached_scope_result.get("reason", "")
        )
        rec.step(
            "qmp-client-blocks-save-and-stop",
            blocked,
            "scope=%s pid=%d gc=%s hook_marker=%s"
            % (
                scope,
                server_pid,
                (attached_gc.stdout + attached_gc.stderr).strip()[-600:],
                os.path.exists(saved),
            ),
        )
        if not blocked:
            raise ScenarioError("an attached QMP client did not block fake VM save and stop")

        client.close()
        client = None
        deadline = time.monotonic() + 45
        stopped = False
        gc_output = ""
        eligible = False
        first_gc = True
        while time.monotonic() < deadline and not os.path.exists(saved):
            result = _run(
                ["/usr/bin/taema", "gc", "--memory", "--json"], timeout=60
            )
            gc_output = (result.stdout + result.stderr).strip()
            if result.returncode != 0:
                break
            try:
                model = json.loads(result.stdout)
                gc_result = model.get("result", {})
            except (ValueError, AttributeError):
                gc_result = {}
            if first_gc:
                eligible = any(
                    isinstance(row, list)
                    and row
                    and row[0] == daemon_scope(scope)
                    and len(row) >= 2
                    and str(row[1]).startswith("no attachment for")
                    for row in gc_result.get("candidates", [])
                )
                rec.step(
                    "qmp-scope-eligible-immediately-after-disconnect",
                    eligible,
                    "scope=%s candidates=%s" % (
                        daemon_scope(scope),
                        gc_result.get("candidates", []),
                    ),
                )
                first_gc = False
            if _wait_process_dead(server_pid, timeout=0.2):
                stopped = True
                break
            # _reclaim_idle needs two CPU samples at least five seconds apart.
            time.sleep(5.25)
        hook_called = os.path.isfile(saved)
        stopped = stopped or _wait_process_dead(server_pid, timeout=2)
        rec.step(
            "qmp-disconnect-allows-save-and-stop",
            hook_called and stopped and eligible,
            "scope=%s pid=%d hook_marker=%s stopped=%s eligible=%s gc=%s"
            % (scope, server_pid, hook_called, stopped, eligible, gc_output[-600:]),
        )
        if not (hook_called and stopped and eligible):
            raise ScenarioError("QMP disconnect did not permit the fake save hook and VM stop")
        return tree
    finally:
        if client is not None:
            client.close()
        if tree is not None and _process_running(tree["children"][0]):
            kill_tree(tree, timeout=5)
        _m0_restore(config_snapshot)


def _m3_qmp_probe_config():
    """Remove unrelated memory pressure/grace gates for the isolated fake QMP probe."""
    return (
        'mode = "enforce"\n\n'
        "[timers]\nadopt_interval = 1\ngc_interval = 3600\n"
        "idle_grace = 0\nleftover_expire_days = 0\n\n"
        "[mem]\nenabled = true\nreclaim = true\nreclaim_interval = 1\n"
        'reclaim_cooldown = 0\nreclaim_max = "4M"\n'
        'reclaim_minimum = "1M"\nmin_headroom = "0M"\n'
        "headroom_percent = 0\nidle_reclaim_grace = 0\n"
        "pressure_gate = 0\npressure_ceiling = 100\nswap_reclaim = true\n"
    )


def _m3_pressure_freeze_config(config_text, freeze_in_adopt):
    """Change only the guard freeze switch for the bounded earlyoom phase."""
    old = "freeze_in_adopt = %s" % ("false" if freeze_in_adopt else "true")
    new = "freeze_in_adopt = %s" % ("true" if freeze_in_adopt else "false")
    if not isinstance(config_text, str) or config_text.count(old) != 1:
        raise ScenarioError("M3 pressure policy did not contain one guard freeze gate")
    return config_text.replace(old, new, 1)


def scenario_m3(rec, args, tree_holder):
    """Exercise pressure, idle cost, QMP save safety, and loopback wake behavior."""
    config_snapshot = None
    tracked = []
    try:
        expected_memory_mb = getattr(args, "expected_memory_mb", 768)
        memory_matches, memory_detail = _m3_memory_allocation_evidence(
            expected_memory_mb
        )
        rec.step(
            "guest-memory-matches-requested-m3-allocation",
            memory_matches,
            json.dumps(memory_detail, sort_keys=True),
        )
        if not memory_matches:
            raise ScenarioError(
                "guest MemTotal is inconsistent with the requested %d MiB M3 allocation"
                % expected_memory_mb
            )
        package = run_privileged(["xbps-install", "-S", "-y", "earlyoom"], timeout=180)
        rec.step(
            "earlyoom-installed-in-disposable-guest",
            package.returncode == 0 and os.path.isfile("/usr/bin/earlyoom"),
            (package.stdout + package.stderr).strip()[-400:],
        )
        if package.returncode != 0 or not os.path.isfile("/usr/bin/earlyoom"):
            raise ScenarioError(
                "M3 requires guest earlyoom; run vmh with --allow-network: %s%s"
                % (package.stdout, package.stderr)
            )
        config_path, _unit_path = _m0_config_paths()
        config_snapshot = _m0_snapshot([config_path])
        _m3_pressure_run(rec, args, tracked)
        tree_holder.extend(tracked)
        _m3_enable_wake_freeze()
        _m3_idle_footprint(rec, args.state_dir, duration=600)
        qmp_tree = _m3_qmp_save_hook(rec, args, tracked)
        tree_holder.append(qmp_tree)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        workdir = os.path.join(args.artifacts, "m3-http")
        os.makedirs(workdir, exist_ok=True)
        with open(os.path.join(workdir, "index.html"), "w", encoding="utf-8") as f:
            f.write("taema-m3-wake\n")
        tree = spawn_gui_tree(
            workdir,
            children=1,
            child_argv=[
                sys.executable,
                "-m",
                "http.server",
                str(port),
                "--bind",
                "127.0.0.1",
                "--directory",
                workdir,
            ],
            root_comm="m3wake",
            root_exec=["/bin/sleep", "3600"],
        )
        tracked.append(tree)
        tree_holder.append(tree)
        server_pid = tree["children"][0]
        app_scope = wait_for_scope(tree["root"], ["app-"], timeout=90)
        rec.step(
            "http-server-contained",
            assert_scope_member(server_pid, "app-") == app_scope,
            "root=%s server=%d scope=%s" % (app_scope, server_pid, scope_of(server_pid)),
        )

        ready = False
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                connection.request("GET", "/")
                response = connection.getresponse()
                body = response.read()
                connection.close()
                if response.status == 200 and b"taema-m3-wake" in body:
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        rec.step("http-server-ready", ready, "127.0.0.1:%d" % port)
        if not ready:
            raise ScenarioError("M3 loopback HTTP server did not become ready")

        app_scope, leftover = _m3_promote_to_leftover(tree, server_pid)
        rec.step(
            "http-server-promoted-to-leftover",
            True,
            "pid=%d app_scope=%s leftover_scope=%s"
            % (server_pid, app_scope, leftover),
        )
        frozen = _wait_for_frozen_scope(leftover, timeout=100)
        rec.step(
            "idle-leftover-frozen",
            frozen,
            "scope=%s events=%s"
            % (
                leftover,
                open(os.path.join(CGROOT, leftover, "cgroup.events"), encoding="ascii")
                .read()
                .strip()
                if os.path.isfile(os.path.join(CGROOT, leftover, "cgroup.events"))
                else "unavailable",
            ),
        )
        if not frozen:
            raise ScenarioError("M3 HTTP leftover was not frozen by Taema")

        started = time.monotonic()
        status = None
        body = b""
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
            connection.request("GET", "/")
            response = connection.getresponse()
            status = response.status
            body = response.read()
            connection.close()
        except OSError as error:
            rec.step(
                "frozen-http-wakes-within-3s",
                False,
                "%s after %.3fs" % (error, time.monotonic() - started),
            )
        else:
            elapsed = time.monotonic() - started
            rec.step(
                "frozen-http-wakes-within-3s",
                status == 200 and b"taema-m3-wake" in body and elapsed <= 3.0,
                "status=%s elapsed=%.3fs body=%r" % (status, elapsed, body[:80]),
            )
    finally:
        thaw = _run(["/usr/bin/taema", "thaw", "--all"], timeout=30)
        rec.step(
            "m3-managed-freezes-thawed",
            thaw.returncode == 0,
            (thaw.stdout or thaw.stderr).strip()[:300],
        )
        for item in tracked:
            kill_tree(item, timeout=10)
        if config_snapshot is not None:
            restored = _m0_restore(config_snapshot)
            rec.step(
                "m3-config-restored",
                restored.returncode == 0,
                (restored.stdout + restored.stderr).strip()[:300],
            )
    return all(step["ok"] for step in rec.steps)


def scenario_upgrade(rec, args, tree_holder):
    """Install the previous release, then upgrade back to the working tree."""
    stopped = run_privileged(["sv", "down", "/var/service/taema"])
    rec.step("stop-current-daemon", stopped.returncode == 0, stopped.stderr[-300:])
    removed = run_privileged(["xbps-remove", "-y", "taema"])
    rec.step("remove-current-package", removed.returncode == 0, removed.stderr[-500:])
    install_previous_release(rec, args)
    install_current_release(rec, args)
    return all(s["ok"] for s in rec.steps)


def scenario_remove(rec, args, tree_holder):
    """Remove the package and verify the guest is cleaned up."""
    rm = run_privileged(["xbps-remove", "-y", "taema"])
    rec.step("remove-package", rm.returncode == 0, (rm.stdout + rm.stderr)[-600:])

    q = run_privileged(["xbps-query", "taema"])
    rec.step(
        "package-gone",
        q.returncode != 0,
        "rc=%d %s" % (q.returncode, (q.stdout + q.stderr).strip()[:200]),
    )

    missing = [p for p in ("/usr/bin/taema", "/usr/lib/taema") if not os.path.exists(p)]
    rec.step("binaries-gone", len(missing) == 2, "absent=%s" % missing)

    rec.step(
        "service-gone", not os.path.lexists("/var/service/taema"), "/var/service/taema"
    )

    leftovers = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        try:
            with open(os.path.join("/proc", entry, "cmdline"), "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "taema daemon" in cmd:
            leftovers.append((entry, cmd[:120]))
    rec.step("daemon-stopped", not leftovers, "running=%s" % leftovers)
    return all(s["ok"] for s in rec.steps)


SCENARIOS = {
    "smoke": scenario_smoke,
    "m0": scenario_m0,
    "m1": scenario_m1,
    "m2": scenario_m2,
    "m3": scenario_m3,
    "upgrade": scenario_upgrade,
    "remove": scenario_remove,
}


def ensure_session_leader():
    """Exclude the CLI runner from app-root adoption without moving cgroups."""
    pid = os.getpid()
    if os.getsid(0) == pid:
        return True
    # setsid(2) rejects process-group leaders. In that unusual launch shape,
    # leave the process in place and let the smoke assertion report the issue.
    if os.getpgrp() == pid:
        return False
    try:
        os.setsid()
    except OSError:
        return False
    return os.getsid(0) == pid


def main(argv):
    parser = argparse.ArgumentParser(
        prog="scenario.py", description="taema VM scenario runner"
    )
    sub = parser.add_subparsers(dest="name", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--artifacts",
        required=True,
        help="directory where results and logs are written",
    )
    common.add_argument(
        "--state-dir",
        default=default_state_dir(),
        help="taema user state directory (decisions.log lives here)",
    )
    common.add_argument(
        "--timeout", type=int, default=180, help="per-step wait timeout in seconds"
    )
    common.add_argument(
        "--expected-memory-mb",
        type=int,
        default=768,
        help="QEMU memory allocation expected by the M3 scenario",
    )
    common.add_argument(
        "--package-dir", help="local repository with the current package (upgrade)"
    )
    common.add_argument("--previous", help="path to the previous release .xbps")
    common.add_argument("--previous-version", help="expected previous version")
    common.add_argument("--current-version", help="expected current version")
    common.add_argument("--migration-fixture", help="0.3.0 JSON migration fixture")
    common.add_argument("--replay-fixture", help="anonymized learner replay fixture")
    for name in sorted(SCENARIOS):
        sub.add_parser(name, parents=[common])
    args = parser.parse_args(argv)

    rec = ResultRecorder(args.name, args.artifacts)
    tree_holder = []
    ok = False
    try:
        ok = SCENARIOS[args.name](rec, args, tree_holder)
    except ScenarioError as e:
        rec.step("fatal", False, str(e))
        ok = False
    except Exception as e:  # noqa: BLE001 - any crash is a scenario failure
        rec.step("fatal", False, "%s: %s" % (type(e).__name__, e))
        ok = False
    finally:
        for tree in tree_holder:
            kill_tree(tree, timeout=10)
        try:
            copied = capture_daemon_logs(
                os.path.join(args.artifacts, "daemon-logs"),
                state_dir=args.state_dir,
                extra_dirs=("/var/log/taema",),
            )
            captured = bool(copied)
            detail = "files=%d" % len(copied)
        except OSError as e:
            captured = False
            detail = "%s: %s" % (type(e).__name__, e)
        rec.step("capture-daemon-logs", captured, detail)
        ok = ok and captured
        rec.finish(ok)
    print("%s: %s" % (args.name, "PASS" if ok else "FAIL"))
    for step in rec.steps:
        print("  [%s] %s" % ("ok" if step["ok"] else "FAIL", step["name"]))
    return 0 if ok else 1


if __name__ == "__main__":
    ensure_session_leader()
    sys.exit(main(sys.argv[1:]))
