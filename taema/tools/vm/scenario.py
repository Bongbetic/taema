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
import math
import glob
import http.client
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import struct
import zlib
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

M3_GUARD_PSI_THRESHOLDS = {"some": "1us/2s", "full": "1us/2s"}

M3_CACHE_WORKER = """\
import ctypes, json, mmap, os, sys, time
path, gate, ready = sys.argv[1:]
ctypes.CDLL(None).prctl(15, b'm3cache', 0, 0, 0)
while not os.path.exists(gate):
    time.sleep(0.05)
with open(path, 'w+b') as cache:
    cache.write(b'x' * (16 * 1024 * 1024))
    cache.flush()
    os.fsync(cache.fileno())
    with mmap.mmap(cache.fileno(), 0, access=mmap.ACCESS_WRITE) as mapped:
        mapped.seek(0)
        mapped.read()
        cold_advice = getattr(mmap, 'MADV_COLD', 20)
        mapped.madvise(cold_advice)
with open(ready, 'w') as marker:
    json.dump({'file_bytes': os.path.getsize(path), 'cold_advice': cold_advice,
               'cold_advice_applied': True,
               'gate_observed': os.path.exists(gate)}, marker)
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
        result = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
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


def scenario_setup(rec, args, tree_holder):
    """Fresh account to a working setup via `taema setup --yes` in under 2 minutes."""
    del tree_holder
    home = os.path.join(args.artifacts, "setup-home")
    config_home = os.path.join(home, ".config")
    os.makedirs(config_home, exist_ok=True)
    env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=config_home)
    begun = time.monotonic()
    first = subprocess.run(
        ["/usr/bin/taema", "setup", "--yes"],
        capture_output=True,
        text=True,
        timeout=110,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    elapsed = time.monotonic() - begun
    rec.step("setup-exit-zero", first.returncode == 0, first.stderr.strip()[:1000])
    rec.step("setup-under-two-minutes", elapsed < 120, "%.1fs" % elapsed)
    dropin = os.path.join(config_home, "taema", "taema.d", "40-setup.toml")
    try:
        with open(dropin, encoding="utf-8") as stream:
            body = stream.read()
    except OSError as error:
        body = "missing: %s" % error
    rec.step("setup-dropin-mode", 'mode = "' in body, body.strip()[:300])
    autostart = os.path.join(config_home, "autostart", "taema-agent.desktop")
    rec.step("setup-agent-autostart", os.path.isfile(autostart), autostart)
    units = os.path.join(config_home, "taema", "units")
    rec.step(
        "setup-units-dir",
        os.path.isdir(units),
        ",".join(sorted(os.listdir(units)))[:1000] if os.path.isdir(units) else "missing",
    )
    second = subprocess.run(
        ["/usr/bin/taema", "setup", "--yes"],
        capture_output=True,
        text=True,
        timeout=110,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    rec.step("setup-second-exit-zero", second.returncode == 0, second.stderr.strip()[:1000])
    rec.step(
        "setup-idempotent",
        "wrote " not in second.stdout,
        second.stdout.strip()[-500:],
    )
    return all(step["ok"] for step in rec.steps)


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
    review = None
    deadline = time.monotonic() + 15
    while True:
        review = _run(["/usr/bin/taema", "review"], timeout=30)
        if (
            review.returncode == 0
            and "review #" in review.stdout
            and "survivors=" in review.stdout
        ) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
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
        status = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
        if status.returncode == 0:
            try:
                doc = json.loads(status.stdout)
                if (doc.get("status") or {}).get("mode") == mode:
                    return status
            except ValueError:
                pass
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
            # Adoption is independent of wake-on-connect's two-second poll below.
            "[timers]\nadopt_interval = 15\ngc_interval = 3600\n"
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
        pressure_config = (
            'mode = "adopt"\n\n'
            "[timers]\nadopt_interval = 1\ngc_interval = 3600\n"
            "idle_grace = 3600\nleftover_expire_days = 0\n\n"
            "[mem]\nreclaim = true\nreclaim_interval = 2\n"
            "reclaim_cooldown = 0\npressure_gate = 100\n"
            "reclaim_max = \"4M\"\n"
            "reclaim_minimum = \"1M\"\nmin_headroom = \"0M\"\n"
            "headroom_percent = 0\nidle_reclaim_grace = 0\n"
            "swap_reclaim = false\n\n"
            "[freeze]\nenabled = true\nadopt = false\nafter = 0\n"
            "wake_on_connect = false\nmax_frozen = 4\ncpu_idle_max = 0.5\n\n"
            "[guard]\nenabled = true\navailable_floor = 35\n"
            'psi_some = "%s"\npsi_full = "%s"\n'
            "cooldown = 10\nfreeze_in_adopt = true\n"
            "oom_adj_leftover = 500\noom_group_leftover = true\n\n"
            "[experimental]\nfreeze = true\nguard = true\n"
        )
        target.write(
            pressure_config
            % (
                M3_GUARD_PSI_THRESHOLDS["some"],
                M3_GUARD_PSI_THRESHOLDS["full"],
            )
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


def _m3_cache_fixture_paths(artifact_dir, home=None):
    """Keep pressure markers in artifacts and the charged cache file on guest disk."""
    home = home or os.path.expanduser("~")
    marker_dir = os.path.join(artifact_dir, "m3-cache")
    os.makedirs(marker_dir, exist_ok=True)
    cache_root = os.path.join(home, ".cache", "taema")
    os.makedirs(cache_root, mode=0o700, exist_ok=True)
    cache_dir = tempfile.mkdtemp(prefix="m3-cache-", dir=cache_root)
    cache_file = os.path.join(cache_dir, "cache.bin")
    # An empty inode lets findmnt verify the backing filesystem before the
    # worker is released. File contents are created only after leftover move.
    with open(cache_file, "wb"):
        pass
    return {
        "marker_dir": marker_dir,
        "cache_dir": cache_dir,
        "cache_file": cache_file,
        "gate": os.path.join(marker_dir, "populate"),
        "ready": os.path.join(marker_dir, "ready"),
    }


def _m3_cache_mount_info(path):
    """Use findmnt to identify the real filesystem backing the M3 cache file."""
    if not shutil.which("findmnt"):
        return {"ok": False, "path": path, "error": "findmnt is unavailable"}
    result = _run(
        ["findmnt", "--json", "--target", path, "--output", "FSTYPE,TARGET,SOURCE"],
        timeout=10,
    )
    try:
        filesystems = json.loads(result.stdout).get("filesystems", [])
    except (TypeError, ValueError):
        filesystems = []
    mount = filesystems[0] if filesystems and isinstance(filesystems[0], dict) else {}
    fstype = mount.get("fstype")
    return {
        "ok": result.returncode == 0 and fstype == "ext4",
        "path": path,
        "fstype": fstype,
        "target": mount.get("target"),
        "source": mount.get("source"),
        "error": result.stderr.strip()[-300:] if result.returncode else None,
    }


def _m3_cache_scope_counters(scope):
    """Read the cgroup file-LRU counters used to decide page-cache reclaim."""
    path = os.path.join(CGROOT, scope)
    values = {}
    try:
        with open(os.path.join(path, "memory.stat"), encoding="ascii") as source:
            for line in source:
                fields = line.split()
                if len(fields) < 2:
                    continue
                try:
                    values[fields[0]] = int(fields[1])
                except ValueError:
                    continue
    except OSError as error:
        return {
            "scope": scope,
            "cgroup_path": path,
            "error": "%s: %s" % (type(error).__name__, error),
        }
    file_bytes = values.get("file")
    inactive_file = values.get("inactive_file")
    shmem = values.get("shmem", 0)
    reclaimable = (
        max(0, min(inactive_file, file_bytes - shmem))
        if isinstance(file_bytes, int) and isinstance(inactive_file, int)
        else None
    )
    return {
        "scope": scope,
        "cgroup_path": path,
        "file_bytes": file_bytes,
        "inactive_file_bytes": inactive_file,
        "shmem_bytes": shmem,
        "reclaimable_bytes": reclaimable,
    }


def _m3_wait_for_reclaimable_cache(scope, timeout=15):
    """Wait for the promoted worker's file pages to be visible as reclaimable."""
    deadline = time.monotonic() + timeout
    counters = _m3_cache_scope_counters(scope)
    while time.monotonic() < deadline:
        if all(
            isinstance(counters.get(name), int) and counters[name] > 0
            for name in ("file_bytes", "inactive_file_bytes", "reclaimable_bytes")
        ):
            return True, counters
        time.sleep(0.1)
        counters = _m3_cache_scope_counters(scope)
    return False, counters


def _m3_guard_trigger_evidence():
    """Return the active trigger source from the public status JSON view."""
    result = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
    try:
        model = json.loads(result.stdout)
    except (TypeError, ValueError):
        model = {}
    status = model.get("status") if isinstance(model, dict) else None
    guard = status.get("guard") if isinstance(status, dict) else None
    guard = guard if isinstance(guard, dict) else {}
    return {
        "source": guard.get("psi_trigger_source"),
        "path": guard.get("psi_trigger_path"),
        "writable": guard.get("psi_trigger_writable") is True,
        "metrics": guard.get("psi_trigger_metrics", []),
        "status_error": result.stderr.strip()[-200:] if result.returncode else None,
    }


def _m3_compact_guard_action(event, sample):
    """Keep only evidence needed to prove selected guard ordering in the artifact."""
    event = event if isinstance(event, dict) else {}
    sample = sample if isinstance(sample, dict) else {}
    return {
        "event": {
            key: event.get(key)
            for key in ("step", "status", "scopes", "bytes_freed", "trigger")
            if key in event
        },
        "sample": sample.get("pressure_sample"),
        "guard_psi_thresholds": sample.get("guard_psi_thresholds"),
        "worker_progress_bytes": sample.get("worker_progress_bytes"),
        "psi_trigger": sample.get("psi_trigger"),
    }


def _m3_decision_events_since(path, offset):
    """Read complete JSON decision records appended after an existing offset."""
    try:
        with open(path, encoding="utf-8", errors="replace") as source:
            source.seek(offset)
            lines = source.readlines()
            next_offset = source.tell()
    except OSError:
        return [], offset
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events, next_offset


def _m3_cache_reclaims_before_pressure(events, scope):
    """Find ordinary reclaim actions against the prepared cache leftover."""
    target = daemon_scope(scope)
    return [
        event
        for event in events
        if event.get("event") == "memory_reclaimed" and event.get("scope") == target
    ]


def _m3_selected_guard_evidence(guard_events, action_samples, page_index, freeze_index):
    """Build compact, parseable evidence for the selected page-cache and freeze events."""
    def selected(index):
        if index is None or index >= len(guard_events) or index >= len(action_samples):
            return None
        return _m3_compact_guard_action(guard_events[index], action_samples[index])

    return {
        "page_cache": selected(page_index),
        "freeze": selected(freeze_index),
    }


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
    decision_path = os.path.join(args.state_dir, "decisions.log")
    try:
        prepressure_offset = os.path.getsize(decision_path)
    except OSError:
        prepressure_offset = 0
    _m3_enable_pressure_policy()
    baseline = _m3_pressure_snapshot()
    psi_trigger = _m3_guard_trigger_evidence()
    total, available = baseline["MemTotal_bytes"], baseline["MemAvailable_bytes"]
    floor_percent = baseline["MemAvailable_percent"]
    rec.step(
        "pressure-starts-above-guard-floor",
        isinstance(floor_percent, (int, float))
        and floor_percent > 40
        and psi_trigger["writable"]
        and psi_trigger["source"] in ("delegated-cgroup", "host-proc"),
        json.dumps(
            {
                "sample": baseline,
                "guard_floor_percent": 35,
                "fallback_floor_percent": 12,
                "psi_trigger": psi_trigger,
            },
            sort_keys=True,
        ),
    )
    if not isinstance(total, int) or not isinstance(available, int):
        raise ScenarioError("M3 pressure run requires MemTotal and MemAvailable")
    if floor_percent <= 40:
        raise ScenarioError("guest begins too close to the configured 35% guard floor")
    if not psi_trigger["writable"] or psi_trigger["source"] not in (
        "delegated-cgroup",
        "host-proc",
    ):
        raise ScenarioError("M3 requires a writable guard PSI trigger source")

    cache_paths = _m3_cache_fixture_paths(args.artifacts)
    cache_dir = cache_paths["marker_dir"]
    cache_file = cache_paths["cache_file"]
    cache_ready = cache_paths["ready"]
    cache_tree = spawn_gui_tree(
        cache_dir,
        children=1,
        child_argv=[
            sys.executable,
            "-c",
            M3_CACHE_WORKER,
            cache_file,
            cache_paths["gate"],
            cache_ready,
        ],
        root_comm="m3cache-root",
        root_exec=["/bin/sleep", "3600"],
    )
    cache_tree["m3_cleanup_cache_dir"] = cache_paths["cache_dir"]
    tracked.append(cache_tree)
    cache_pid = cache_tree["children"][0]
    cache_app_scope, cache_scope = _m3_promote_to_leftover(cache_tree, cache_pid)
    cache_item = {"pid": cache_pid, "scope": cache_scope}
    cache_member_ok, cache_preflight = _m3_pressure_scope_preflight(
        cache_item, "leftover/"
    )
    cache_scope = cache_item.get("scope", cache_scope)
    cache_mount = _m3_cache_mount_info(cache_file)
    home = os.path.realpath(os.path.expanduser("~"))
    cache_realpath = os.path.realpath(cache_file)
    cache_inside_home = os.path.commonpath((home, cache_realpath)) == home
    cache_inside_artifacts = os.path.commonpath(
        (os.path.realpath(args.artifacts), cache_realpath)
    ) == os.path.realpath(args.artifacts)
    gate_preconditions = (
        cache_member_ok
        and cache_preflight.get("scope") == cache_scope
        and cache_mount.get("ok") is True
        and cache_inside_home
        and not cache_inside_artifacts
        and os.path.getsize(cache_file) == 0
        and not os.path.exists(cache_paths["gate"])
    )
    rec.step(
        "pressure-cache-ext4-leftover-before-population",
        gate_preconditions,
        json.dumps(
            {
                "proc_cgroup": cache_preflight.get("proc_cgroup"),
                "pid": cache_pid,
                "scope": cache_scope,
                "cgroup_member": cache_preflight.get("cgroup_member"),
                "cgroup_path": cache_preflight.get("cgroup_path"),
                "findmnt": cache_mount,
                "inside_guest_home": cache_inside_home,
                "inside_artifacts_tmpfs": cache_inside_artifacts,
                "file_size_before_worker_gate": os.path.getsize(cache_file),
                "worker_gate_open": os.path.exists(cache_paths["gate"]),
            },
            sort_keys=True,
        ),
    )
    if not gate_preconditions:
        raise ScenarioError(
            "M3 cache worker must be in its leftover cgroup on ext4 before file population"
        )
    with open(cache_paths["gate"], "w", encoding="ascii") as target:
        target.write("populate\n")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not os.path.isfile(cache_ready):
        if not _alive(cache_pid):
            break
        time.sleep(0.1)
    try:
        with open(cache_ready, encoding="utf-8") as source:
            cache_ready_detail = json.load(source)
    except (OSError, ValueError):
        cache_ready_detail = {}
    cache_ready_ok = (
        os.path.isfile(cache_ready)
        and os.path.getsize(cache_file) == 16 * 1024 * 1024
        and cache_ready_detail.get("file_bytes") == 16 * 1024 * 1024
        and cache_ready_detail.get("cold_advice_applied") is True
        and cache_ready_detail.get("gate_observed") is True
    )
    rec.step(
        "pressure-cache-worker-populated-after-leftover",
        cache_ready_ok,
        json.dumps(
            {
                "pid": cache_pid,
                "scope": cache_scope,
                "cache_file": cache_file,
                "ready": cache_ready_detail,
            },
            sort_keys=True,
        ),
    )
    if not cache_ready_ok:
        raise ScenarioError("M3 cache process did not populate its 16 MiB file after promotion")
    counters_ok, cache_counters = _m3_wait_for_reclaimable_cache(cache_scope)
    rec.step(
        "pressure-cache-leftover-has-reclaimable-file-pages",
        counters_ok,
        json.dumps(cache_counters, sort_keys=True),
    )
    if not counters_ok:
        raise ScenarioError(
            "M3 cache leftover has no nonzero file/inactive_file/reclaimable counters"
        )
    prepressure_events, _ = _m3_decision_events_since(
        decision_path, prepressure_offset
    )
    prepressure_cache_reclaims = _m3_cache_reclaims_before_pressure(
        prepressure_events, cache_scope
    )
    rec.step(
        "pressure-cache-not-reclaimed-before-workload-start",
        not prepressure_cache_reclaims,
        json.dumps(
            {
                "cache_scope": daemon_scope(cache_scope),
                "non_guard_pressure_gate_percent": 100,
                "prepressure_memory_reclaimed": prepressure_cache_reclaims,
            },
            sort_keys=True,
        ),
    )
    if prepressure_cache_reclaims:
        raise ScenarioError(
            "ordinary reclaim acted on the prepared cache before pressure started"
        )
    rec.step(
        "pressure-cache-adopted-before-leftover",
        True,
        json.dumps(
            {
                "app_scope": cache_app_scope,
                "leftover_scope": cache_scope,
                "pid": cache_pid,
                "file_counters_before_pressure": cache_counters,
            },
            sort_keys=True,
        ),
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
                            "guard_psi_thresholds": dict(M3_GUARD_PSI_THRESHOLDS),
                            "worker_progress_bytes": {
                                "hog": _m3_worker_progress(hog),
                                "peer": _m3_worker_progress(peer),
                            },
                            "psi_trigger": psi_trigger,
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
        # The daemon attempts page_cache before freeze in every guard
        # pass. A freeze may still be the first *acted* step when reclaim
        # was blocked waiting for idle evidence ("stable CPU sample" /
        # "second idle sample"); freeze has its own fail-closed idle
        # gates, so that order is safe. Any other freeze-first order
        # fails: reclaim must act before freeze when it can.
        prior_reclaim = [
            event
            for event in (guard_events[:freeze_index] if freeze_index is not None else [])
            if event.get("step") == "page_cache"
            and any(
                daemon_scope(cache_scope) == str(candidate.get("scope", ""))
                for candidate in event.get("skipped_candidates", [])
                if isinstance(candidate, dict)
            )
        ]
        reclaim_blocked = bool(prior_reclaim) and all(
            any(
                "stable CPU sample" in str(candidate.get("reason", ""))
                or "second idle sample" in str(candidate.get("reason", ""))
                for candidate in event.get("skipped_candidates", [])
                if isinstance(candidate, dict)
            )
            for event in prior_reclaim
        )
        ordered = page_index is not None and freeze_index is not None and (
            page_index < freeze_index or reclaim_blocked
        )
        evidence = {
            "guard_floor_percent": 35,
            "fallback_floor_percent": 12,
            "page_cache_pre_pressure_counters": cache_counters,
            "bounded_worker_budget_bytes": phase1_cap,
            "selected_actions": _m3_selected_guard_evidence(
                guard_events, action_samples, page_index, freeze_index
            ),
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
                    sampled = {
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
                    # A dying pid reads oom_score 0; keep the last
                    # snapshot taken while both processes were alive.
                    if _alive(hog["pid"]) and _alive(peer["pid"]):
                        scores = sampled
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


def _m3_daemon_process_ids(current_uid_only=False):
    """Return matching daemons, preferring or requiring the scenario user's UID."""
    matches = []
    scenario_uid = os.getuid()
    for entry in os.listdir(PROCROOT):
        if not entry.isdigit():
            continue
        proc_dir = os.path.join(PROCROOT, entry)
        try:
            with open(os.path.join(proc_dir, "cmdline"), "rb") as source:
                argv = [item.decode("utf-8", "replace") for item in source.read().split(b"\0")]
        except OSError:
            continue
        script_launcher = any(
            os.path.basename(argv[index]) == "taema"
            and index + 1 < len(argv)
            and argv[index + 1] == "daemon"
            for index in range(len(argv))
        )
        if _is_taema_daemon_argv(argv) or script_launcher:
            uid = None
            try:
                with open(os.path.join(proc_dir, "status"), encoding="ascii") as source:
                    uid_line = next(line for line in source if line.startswith("Uid:"))
                uid = int(uid_line.split()[1])
            except (OSError, StopIteration, ValueError, IndexError):
                pass
            if current_uid_only and uid != scenario_uid:
                continue
            matches.append((uid != scenario_uid, int(entry)))
    return [pid for _other_uid, pid in sorted(matches)]


def _m3_daemon_metrics():
    """Return scenario-UID daemon PID, resident KiB, and CPU ticks from procfs."""
    # Config reloads restart the daemon; tolerate a brief absence.
    deadline = time.monotonic() + 30
    while True:
        result = _m3_daemon_metrics_once()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    raise ScenarioError("could not find the taema daemon for the scenario UID in procfs")


def _m3_daemon_metrics_once():
    for pid in _m3_daemon_process_ids(current_uid_only=True):
        proc_dir = os.path.join(PROCROOT, str(pid))
        try:
            with open(os.path.join(proc_dir, "status"), encoding="ascii") as source:
                status = source.read()
            rss = next(
                int(line.split()[1])
                for line in status.splitlines()
                if line.startswith("VmRSS:")
            )
            with open(os.path.join(proc_dir, "stat"), encoding="ascii") as source:
                stat = source.read()
            fields = stat[stat.rfind(")") + 1 :].split()
            ticks = int(fields[11]) + int(fields[12])
            return pid, rss, ticks
        except (OSError, StopIteration, ValueError, IndexError):
            continue
    return None


def _m3_daemon_profiles():
    """Read concise RSS and smaps_rollup evidence for each matching daemon process."""
    selected = (
        "Rss",
        "Pss",
        "Anonymous",
        "Pss_Anon",
        "Pss_File",
        "Pss_Shmem",
        "Shared_Clean",
        "Shared_Dirty",
        "Private_Clean",
        "Private_Dirty",
        "Swap",
    )
    profiles = []
    for pid in _m3_daemon_process_ids():
        proc_dir = os.path.join(PROCROOT, str(pid))
        profile = {"pid": pid, "rss_kib": None, "smaps_rollup": {}}
        try:
            with open(os.path.join(proc_dir, "status"), encoding="ascii") as source:
                profile["rss_kib"] = next(
                    int(line.split()[1])
                    for line in source
                    if line.startswith("VmRSS:")
                )
        except (OSError, StopIteration, ValueError, IndexError) as error:
            profile["status_error"] = "%s: %s" % (type(error).__name__, error)
        try:
            values = {}
            with open(
                os.path.join(proc_dir, "smaps_rollup"), encoding="ascii"
            ) as source:
                for line in source:
                    name, separator, raw = line.partition(":")
                    if name not in selected or not separator:
                        continue
                    fields = raw.split()
                    if fields and fields[0].isdecimal():
                        values[name] = int(fields[0])
            rss = values.get("Rss")
            anonymous = values.get("Anonymous")
            rollup = {
                "rss_kib": rss,
                "pss_kib": values.get("Pss"),
                "anonymous_kib": anonymous,
                "file_or_shmem_kib": (
                    max(0, rss - anonymous)
                    if isinstance(rss, int) and isinstance(anonymous, int)
                    else None
                ),
                "pss_anon_kib": values.get("Pss_Anon"),
                "pss_file_kib": values.get("Pss_File"),
                "pss_shmem_kib": values.get("Pss_Shmem"),
                "shared_clean_kib": values.get("Shared_Clean"),
                "shared_dirty_kib": values.get("Shared_Dirty"),
                "private_clean_kib": values.get("Private_Clean"),
                "private_dirty_kib": values.get("Private_Dirty"),
                "swap_kib": values.get("Swap"),
            }
            profile["smaps_rollup"] = rollup
            if rss is None or anonymous is None:
                profile["smaps_error"] = "smaps_rollup lacks Rss or Anonymous"
        except OSError as error:
            profile["smaps_error"] = "%s: %s" % (type(error).__name__, error)
        profiles.append(profile)
    return profiles


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
    daemon_profiles_start = _m3_daemon_profiles()
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
    daemon_profiles_end = _m3_daemon_profiles()

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
        "daemon_profiles_start": daemon_profiles_start,
        "daemon_profiles_end": daemon_profiles_end,
        "memory_sample_scopes_before": len(before),
        "memory_sample_scopes_after": len(after),
        "sample_heartbeat": sample_heartbeat,
    }
    # RSS gate is 40 MiB, not the 30 MiB product aspiration: ADR-0008
    # records the idle-RSS criterion as triggered (~32 MiB in this guest,
    # PSS ~20 MiB) and accepted for 1.0.0, with this as the tripwire.
    # CPU gate is 0.3% in the VM: musl guests measure 0.22-0.24% where
    # glibc measures 0.15% (ADR-0008); the 0.2% product criterion is
    # gated on the host by tests.test_perf, which passes.
    rec.step(
        "idle-vm-footprint-under-limits",
        elapsed >= duration
        and max_rss <= 40 * 1024
        and cpu_percent <= 0.3
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


def _m3_qmp_release_probe(pid, scope, saved_path, timeout=45):
    """Poll memory GC through its stable-CPU wait until the fake VM stops."""
    daemon_scope_name = daemon_scope(scope)
    deadline = time.monotonic() + timeout
    evidence = {
        "eligible": False,
        "eligible_candidates": [],
        "first_reason": "",
        "hook_called": False,
        "stopped": False,
        "gc_calls": 0,
        "stable_cpu_waits": 0,
        "last_gc": "",
    }
    first_call = True
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        result = _run(
            ["/usr/bin/taema", "gc", "--memory", "--json"],
            timeout=min(15, remaining),
        )
        evidence["gc_calls"] += 1
        evidence["last_gc"] = (result.stdout + result.stderr).strip()[-700:]
        try:
            model = json.loads(result.stdout)
            gc_result = model.get("result", {})
        except (ValueError, AttributeError):
            gc_result = {}
        candidates = gc_result.get("candidates", [])
        if first_call:
            evidence["eligible_candidates"] = [
                row
                for row in candidates
                if isinstance(row, list)
                and row
                and row[0] == daemon_scope_name
            ]
            evidence["eligible"] = any(
                len(row) >= 2 and str(row[1]).startswith("no attachment for")
                for row in evidence["eligible_candidates"]
            )
            first_call = False
        memory_rows = gc_result.get("memory", [])
        scope_result = next(
            (
                row
                for row in memory_rows
                if isinstance(row, dict) and row.get("scope") == daemon_scope_name
            ),
            {},
        )
        reason = str(scope_result.get("reason", ""))
        if not evidence["first_reason"]:
            evidence["first_reason"] = reason
        if reason == "waiting for a stable CPU sample":
            evidence["stable_cpu_waits"] += 1
        if result.returncode != 0:
            break
        if not _process_running(pid):
            evidence["stopped"] = True
            break
        if reason == "waiting for a stable CPU sample":
            time.sleep(min(5.25, max(0.0, deadline - time.monotonic())))
        else:
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    evidence["hook_called"] = os.path.isfile(saved_path)
    evidence["stopped"] = evidence["stopped"] or not _process_running(pid)
    return evidence


def _m3_wait_for_daemon(timeout=30, poll=0.25):
    """Wait for status JSON to confirm that this guest's daemon is serving."""
    deadline = time.monotonic() + timeout
    last_detail = "no status response"
    while True:
        result = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
        last_detail = (result.stdout or result.stderr).strip()[-500:]
        try:
            status = json.loads(result.stdout).get("status", {})
        except (ValueError, AttributeError):
            status = {}
        if result.returncode == 0 and status.get("daemon") == "running":
            return True, last_detail
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, last_detail
        if poll > 0:
            time.sleep(min(poll, remaining))


def _m3_ensure_daemon_ready(timeout=30):
    """Wait for a restored daemon, then restart the guest service once if needed."""
    ready, detail = _m3_wait_for_daemon(timeout=min(timeout, 10))
    if ready:
        return True, detail
    restarted = run_privileged(["sv", "restart", "taema"], timeout=45)
    ready, final_detail = _m3_wait_for_daemon(timeout=timeout)
    return ready, json.dumps(
        {
            "initial_status": detail,
            "restart_rc": restarted.returncode,
            "restart_output": (restarted.stdout + restarted.stderr).strip()[-300:],
            "final_status": final_detail,
        },
        sort_keys=True,
    )


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
        # The daemon persists the review at the end of its pass; poll the
        # CLI briefly instead of racing that commit.
        review = _run(["/usr/bin/taema", "review"], timeout=30)
        review_deadline = time.monotonic() + 30
        while (
            "exe:sleep" not in review.stdout
            and time.monotonic() < review_deadline
        ):
            time.sleep(0.5)
            review = _run(["/usr/bin/taema", "review"], timeout=30)
        leftover_leaf = daemon_scope(leftover)
        review_events = _event_lines(log_path, "review_created", leftover_leaf)
        record(
            "adopt-review-lists-contained-survivors",
            review.returncode == 0
            and ("open reviews:" in review.stdout or "review #" in review.stdout)
            and "owner=" in review.stdout
            and "survivors=" in review.stdout
            and "exe:sleep" in review.stdout
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
            and "vetoed:" in (refused.stdout + refused.stderr)
            and "sleep" in (refused.stdout + refused.stderr)
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
            and "vetoed:" in (refused.stdout + refused.stderr)
            and "sleep" in (refused.stdout + refused.stderr)
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
            and "sleep" in owner_veto_event.get("target", ""),
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
        review_deadline = time.monotonic() + 30
        while "exe:tail" not in review.stdout and time.monotonic() < review_deadline:
            time.sleep(0.5)
            review = _run(["/usr/bin/taema", "review"], timeout=30)
        auto_leaf = daemon_scope(auto_leftover)
        auto_review_events = _event_lines(log_path, "review_created", auto_leaf)
        record(
            "auto-keeps-and-reviews-unlearned-leftover",
            gc_result.returncode == 0
            and review.returncode == 0
            and _process_running(automatic["children"][0])
            and scope_of(automatic["children"][0]) == auto_leftover
            and "survivors=" in review.stdout
            and "exe:tail" in review.stdout
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
        from taema.config import policy as taema_policy
        from taema.daemon import service as taema_daemon
        from taema.governor import engine as taema_engine

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
    removed = remove_taema_packages()
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
        evidence = _m3_qmp_release_probe(server_pid, scope, saved, timeout=45)
        rec.step(
            "qmp-scope-eligible-immediately-after-disconnect",
            evidence["eligible"],
            json.dumps(
                {
                    "scope": daemon_scope(scope),
                    "candidates": evidence["eligible_candidates"],
                    "first_memory_reason": evidence["first_reason"],
                },
                sort_keys=True,
            ),
        )
        rec.step(
            "qmp-disconnect-allows-save-and-stop",
            evidence["hook_called"] and evidence["stopped"] and evidence["eligible"],
            json.dumps(
                {
                    "scope": scope,
                    "pid": server_pid,
                    "hook_marker": evidence["hook_called"],
                    "stopped": evidence["stopped"],
                    "eligible": evidence["eligible"],
                    "gc_calls": evidence["gc_calls"],
                    "stable_cpu_waits": evidence["stable_cpu_waits"],
                    "last_gc": evidence["last_gc"],
                },
                sort_keys=True,
            ),
        )
        if not (
            evidence["hook_called"]
            and evidence["stopped"]
            and evidence["eligible"]
        ):
            raise ScenarioError("QMP disconnect did not permit the fake save hook and VM stop")
        return tree
    finally:
        if client is not None:
            client.close()
        if tree is not None and _process_running(tree["children"][0]):
            kill_tree(tree, timeout=5)
        restored = _m0_restore(config_snapshot)
        ready, readiness = _m3_ensure_daemon_ready()
        rec.step(
            "qmp-probe-daemon-restored",
            restored.returncode == 0 and ready,
            json.dumps(
                {
                    "restore_rc": restored.returncode,
                    "restore_output": (restored.stdout + restored.stderr).strip()[-300:],
                    "readiness": readiness,
                },
                sort_keys=True,
            ),
        )


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
        for item in tracked:
            kill_tree(item, timeout=10)
            cache_dir = item.get("m3_cleanup_cache_dir")
            if isinstance(cache_dir, str):
                shutil.rmtree(cache_dir, ignore_errors=True)
        if config_snapshot is not None:
            restored = _m0_restore(config_snapshot)
            rec.step(
                "m3-config-restored",
                restored.returncode == 0,
                (restored.stdout + restored.stderr).strip()[:300],
            )
        ready, readiness = _m3_ensure_daemon_ready()
        rec.step("daemon-ready-before-m3-thaw", ready, readiness)
        if ready:
            thaw = _run(["/usr/bin/taema", "thaw", "--all"], timeout=30)
            rec.step(
                "m3-managed-freezes-thawed",
                thaw.returncode == 0,
                (thaw.stdout or thaw.stderr).strip()[:300],
            )
        else:
            rec.step(
                "m3-managed-freezes-thawed",
                False,
                "skipped because guest daemon did not become ready: %s" % readiness,
            )
    return all(step["ok"] for step in rec.steps)


def scenario_upgrade(rec, args, tree_holder):
    """Install the previous release, then upgrade back to the working tree."""
    stopped = run_privileged(["sv", "down", "/var/service/taema"])
    rec.step("stop-current-daemon", stopped.returncode == 0, stopped.stderr[-300:])
    removed = remove_taema_packages()
    rec.step("remove-current-package", removed.returncode == 0, removed.stderr[-500:])
    install_previous_release(rec, args)
    install_current_release(rec, args)
    return all(s["ok"] for s in rec.steps)


def _m3_config_path():
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(config_home, "taema", "taema.toml")


def _m3_config_snapshot(path):
    try:
        with open(path, "rb") as source:
            return source.read()
    except FileNotFoundError:
        return None


def _m3_write_config(path, contents):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as target:
        target.write(contents)


def _m3_restore_config(path, saved):
    if saved is None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as target:
            target.write(saved)


def _m3_guard_config(pressure_fixture=True):
    if pressure_fixture:
        guard_cooldown = 1
        psi_some = "1ms/2s"
        psi_full = "1ms/2s"
    else:
        # Match the daemon's production trigger sensitivity during the idle gate.
        guard_cooldown = 10
        psi_some = "150ms/2s"
        psi_full = "50ms/2s"
    return (
        'mode = "auto"\n\n'
        "[timers]\nadopt_interval = 15\ngc_interval = 3600\n"
        "idle_grace = 3600\nleftover_expire_days = 365\n\n"
        "[mem]\nenabled = true\nreclaim = true\n"
        'min_headroom = "128M"\nreclaim_minimum = "4M"\n'
        'reclaim_max = "32M"\nreclaim_cooldown = 0\nidle_reclaim_grace = 0\n\n'
        "[freeze]\nenabled = true\nafter = 0\nwake_on_connect = true\n"
        "cpu_idle_max = 0.5\nmax_frozen = 8\n\n"
        '[guard]\nenabled = true\navailable_floor = "auto"\ncooldown = %d\n'
        'psi_some = "%s"\npsi_full = "%s"\n\n'
        "[experimental]\nfreeze = false\nguard = true\n"
        % (guard_cooldown, psi_some, psi_full)
    )


def _m3_restart():
    result = run_privileged(["sv", "restart", "taema"], timeout=45)
    if result.returncode != 0:
        raise ScenarioError(
            "taema restart failed: %s" % (result.stdout + result.stderr)[-800:]
        )
    deadline = time.monotonic() + 45
    last = None
    while time.monotonic() < deadline:
        last = _run(["/usr/bin/taema", "status", "--json"], timeout=10)
        if last.returncode == 0:
            try:
                data = json.loads(last.stdout)
                if data.get("status", {}).get("daemon") == "running":
                    return data
            except (ValueError, AttributeError):
                pass
        time.sleep(0.25)
    detail = (last.stdout + last.stderr) if last else "no status response"
    raise ScenarioError("taema did not return to running state: %s" % detail[-800:])


def _m3_status():
    result = _run(["/usr/bin/taema", "status", "--json"], timeout=15)
    if result.returncode != 0:
        raise ScenarioError("taema status failed: %s" % (result.stdout + result.stderr))
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise ScenarioError("taema status returned invalid JSON: %s" % error)


def _m3_psi_pressure_snapshot(path):
    """Read the per-cgroup PSI counters and short-window averages."""
    metrics = {}
    try:
        with open(path, encoding="ascii") as source:
            for line in source:
                fields = line.split()
                if not fields or fields[0] not in ("some", "full"):
                    continue
                values = {}
                for field in fields[1:]:
                    if "=" not in field:
                        continue
                    key, value = field.split("=", 1)
                    if key == "avg10":
                        values[key] = float(value)
                    elif key == "total":
                        values[key] = int(value)
                if "avg10" in values and "total" in values:
                    metrics[fields[0]] = values
    except (OSError, ValueError) as error:
        raise ScenarioError("cannot read PSI pressure at %s: %s" % (path, error))
    if not all(name in metrics for name in ("some", "full")):
        raise ScenarioError("incomplete PSI pressure data at %s" % path)
    return metrics


def _m3_wait_for_footprint_quiet(
    status_reader=None,
    psi_reader=None,
    *,
    psi_path=None,
    timeout=180.0,
    quiet_seconds=10.0,
    poll_interval=1.0,
    quiet_avg10_percent=1.0,
):
    """Wait for post-pressure recovery before beginning the idle footprint window."""
    if timeout <= 0 or quiet_seconds <= 0 or poll_interval <= 0:
        raise ScenarioError("footprint quiet-wait durations must be positive")
    status_reader = _m3_status if status_reader is None else status_reader
    if psi_reader is None:
        if psi_path is None:
            psi_path = os.path.join(CGROOT, "user", str(os.getuid()), "memory.pressure")
        psi_reader = lambda: _m3_psi_pressure_snapshot(psi_path)

    start = time.monotonic()
    deadline = start + timeout
    stable_since = None
    previous_totals = None
    latest_guard_active = None
    latest_pressure = None
    while True:
        now = time.monotonic()
        status = status_reader()
        details = status.get("status", {}).get("details", {})
        guard = details.get("guard", {}) if isinstance(details, dict) else {}
        latest_guard_active = guard.get("active") if isinstance(guard, dict) else None
        if not isinstance(latest_guard_active, bool):
            raise ScenarioError(
                "daemon guard status is unavailable during footprint settling"
            )

        latest_pressure = psi_reader()
        totals = (
            latest_pressure["some"]["total"],
            latest_pressure["full"]["total"],
        )
        averages = (
            latest_pressure["some"]["avg10"],
            latest_pressure["full"]["avg10"],
        )
        quiet = (
            not latest_guard_active
            and max(averages) <= quiet_avg10_percent
            and totals == previous_totals
        )
        if quiet:
            if stable_since is None:
                stable_since = now
            stable_elapsed = now - stable_since
            if stable_elapsed >= quiet_seconds:
                return {
                    "waited_seconds": round(now - start, 2),
                    "stable_seconds": round(stable_elapsed, 2),
                    "some_total": totals[0],
                    "full_total": totals[1],
                    "some_avg10": averages[0],
                    "full_avg10": averages[1],
                }
        else:
            stable_since = None

        previous_totals = totals
        remaining = deadline - now
        if remaining <= 0:
            raise ScenarioError(
                "guard/PSI did not stay quiet for %.1fs within %.1fs "
                "(guard_active=%s pressure=%s)"
                % (quiet_seconds, timeout, latest_guard_active, latest_pressure)
            )
        time.sleep(min(poll_interval, remaining))


def _m3_memory():
    from taema.governor.guard import host_memory

    available, total = host_memory()
    if not isinstance(available, int) or not isinstance(total, int):
        raise ScenarioError("guest MemAvailable/MemTotal are unavailable")
    return available, total


def _m3_cgroup_stats(path):
    values = {}
    try:
        with open(os.path.join(path, "memory.current"), encoding="ascii") as source:
            values["current_bytes"] = int(source.read().strip())
        with open(os.path.join(path, "memory.stat"), encoding="ascii") as source:
            for line in source:
                fields = line.split()
                if len(fields) == 2 and fields[0] in (
                    "anon",
                    "file",
                    "shmem",
                    "inactive_file",
                    "workingset_refault_file",
                ):
                    values[fields[0] + "_bytes"] = int(fields[1])
    except (OSError, ValueError) as error:
        raise ScenarioError(
            "cannot read cgroup memory counters at %s: %s" % (path, error)
        )
    return values


def _m3_reclaimable_file_cache_bytes(stats):
    file_bytes = stats.get("file_bytes")
    inactive_file = stats.get("inactive_file_bytes")
    if file_bytes is None or inactive_file is None:
        return None
    shmem_bytes = stats.get("shmem_bytes", 0)
    return max(0, min(inactive_file, file_bytes - shmem_bytes))


def _m3_earlyoom_threshold_bytes(total_mib):
    mib = 1024 * 1024
    if total_mib <= 0:
        raise ValueError("earlyoom total memory must be positive")
    return (total_mib * mib * 5 + 99) // 100


def _m3_parse_earlyoom_memory_samples(output):
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    pattern = re.compile(r"mem avail:\s*(\d+)\s+of\s+(\d+)\s+MiB", re.IGNORECASE)
    samples = []
    for match in pattern.finditer(output):
        available_mib, total_mib = (int(value) for value in match.groups())
        if total_mib <= 0 or available_mib < 0:
            continue
        samples.append(
            {
                "available_mib": available_mib,
                "total_mib": total_mib,
                "threshold_bytes": _m3_earlyoom_threshold_bytes(total_mib),
            }
        )
    return samples


def _m3_post_guard_pressure_cap(allocated, available_bytes, earlyoom_threshold_bytes):
    mib = 1024 * 1024
    final_target = max(0, earlyoom_threshold_bytes - 16 * mib)
    cap = allocated + max(2 * mib, available_bytes - final_target)
    return final_target, cap


_M3_PRESSURE_RAMP_STEP_BYTES = 8 * 1024 * 1024
_M3_PRESSURE_RAMP_MAX_STEPS = 4
_M3_PRESSURE_RAMP_INTERVAL_SECONDS = 1.0


def _m3_pressure_ramp_next_cap(cap_bytes, increments_used):
    if increments_used >= _M3_PRESSURE_RAMP_MAX_STEPS:
        return cap_bytes, 0
    return cap_bytes + _M3_PRESSURE_RAMP_STEP_BYTES, _M3_PRESSURE_RAMP_STEP_BYTES


def _m3_create_cache_file(directory="/var/tmp"):
    """Reserve a unique candidate cache path on the guest's disk-backed temp area."""
    fd, path = tempfile.mkstemp(prefix="taema-m3-cache-", suffix=".bin", dir=directory)
    os.close(fd)
    return path


def _m3_enable_memory_controllers(base, leaf_parent):
    """Enable memory accounting down the disposable fixture's cgroup path."""
    base = os.path.abspath(base)
    leaf_parent = os.path.abspath(leaf_parent)
    try:
        common = os.path.commonpath((base, leaf_parent))
    except ValueError as error:
        raise ScenarioError("invalid memory controller path: %s" % error)
    if common != base:
        raise ScenarioError(
            "memory controller path %s is outside delegated base %s"
            % (leaf_parent, base)
        )

    parents = [base]
    relative = os.path.relpath(leaf_parent, base)
    if relative != ".":
        current = base
        for segment in relative.split(os.sep):
            current = os.path.join(current, segment)
            parents.append(current)

    for parent in parents:
        controllers_path = os.path.join(parent, "cgroup.controllers")
        subtree_path = os.path.join(parent, "cgroup.subtree_control")
        try:
            with open(controllers_path, encoding="ascii") as source:
                available = set(source.read().split())
            with open(subtree_path, encoding="ascii") as source:
                active = {item.lstrip("+") for item in source.read().split()}
        except OSError as error:
            raise ScenarioError(
                "cannot inspect memory controller at %s: %s" % (parent, error)
            )
        if "memory" not in available:
            raise ScenarioError("memory controller unavailable at %s" % parent)
        if "memory" in active:
            continue

        try:
            with open(subtree_path, "w", encoding="ascii") as target:
                target.write("+memory\n")
        except PermissionError:
            try:
                result = subprocess.run(
                    ["sudo", "-n", "tee", subtree_path],
                    input="+memory\n",
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ScenarioError(
                    "cannot enable memory controller at %s: %s" % (parent, error)
                )
            if result.returncode != 0:
                detail = (result.stderr or "").strip()
                raise ScenarioError(
                    "cannot enable memory controller at %s: %s"
                    % (parent, detail or "privileged write failed")
                )
        except OSError as error:
            raise ScenarioError(
                "cannot enable memory controller at %s: %s" % (parent, error)
            )

        try:
            with open(subtree_path, encoding="ascii") as source:
                active = {item.lstrip("+") for item in source.read().split()}
        except OSError as error:
            raise ScenarioError(
                "cannot verify memory controller at %s: %s" % (parent, error)
            )
        if "memory" not in active:
            raise ScenarioError("memory controller did not enable at %s" % parent)


def _m3_move(pid, path):
    proc_path = os.path.join(path, "cgroup.procs")
    try:
        with open(proc_path, "w", encoding="ascii") as target:
            target.write("%d\n" % pid)
    except PermissionError:
        result = subprocess.run(
            ["sudo", "-n", "tee", proc_path],
            input="%d\n" % pid,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            detail = (result.stderr or "").strip()
            raise ScenarioError(detail or "privileged cgroup move failed")


def _m3_set_oom_score_adj(pid, adjustment):
    path = os.path.join(PROCROOT, str(pid), "oom_score_adj")
    value = "%d\n" % adjustment
    try:
        with open(path, "w", encoding="ascii") as target:
            target.write(value)
    except PermissionError:
        try:
            result = subprocess.run(
                ["sudo", "-n", "tee", path],
                input=value,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ScenarioError(
                "cannot set oom_score_adj for pid %d: %s" % (pid, error)
            )
        if result.returncode != 0:
            detail = (result.stderr or "").strip()
            raise ScenarioError(
                "cannot set oom_score_adj for pid %d: %s"
                % (pid, detail or "privileged proc write failed")
            )
    except OSError as error:
        raise ScenarioError("cannot set oom_score_adj for pid %d: %s" % (pid, error))

    try:
        with open(path, encoding="ascii") as source:
            actual = int(source.read().strip())
    except (OSError, ValueError) as error:
        raise ScenarioError("cannot verify oom_score_adj for pid %d: %s" % (pid, error))
    if actual != adjustment:
        raise ScenarioError(
            "oom_score_adj for pid %d is %d, expected %d" % (pid, actual, adjustment)
        )
    return actual


def _m3_process_oom_metrics(pid):
    path = os.path.join(PROCROOT, str(pid))
    values = {}
    for name in ("oom_score", "oom_score_adj"):
        try:
            with open(os.path.join(path, name), encoding="ascii") as source:
                values[name] = int(source.read().strip())
        except (OSError, ValueError) as error:
            raise ScenarioError("cannot read %s for pid %d: %s" % (name, pid, error))
    return values


def _m3_process_oom_evidence(pid):
    return {"pid": pid, **_m3_process_oom_metrics(pid)}


def _m3_stop_process(proc, timeout=5):
    if proc is None or proc.poll() is not None:
        return True
    try:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False


def _m3_thaw_cgroups(
    candidate_path, pressure_path, pressure_proc=None, timeout=10, poll=0.05
):
    """Uncap and thaw disposable fixture cgroups before stopping their processes."""
    errors = []
    if pressure_path and os.path.isdir(pressure_path):
        try:
            with open(
                os.path.join(pressure_path, "memory.high"), "w", encoding="ascii"
            ) as target:
                target.write("max\n")
        except OSError as error:
            errors.append("could not uncap pressure cgroup: %s" % error)

    if pressure_proc is not None and pressure_proc.poll() is None:
        try:
            pressure_proc.send_signal(signal.SIGUSR2)
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append("could not resume pressure worker: %s" % error)

    paths = []
    for path in (candidate_path, pressure_path):
        if not path or not os.path.isdir(path):
            continue
        paths.append(path)
        try:
            with open(
                os.path.join(path, "cgroup.freeze"), "w", encoding="ascii"
            ) as target:
                target.write("0\n")
        except OSError as error:
            errors.append("could not thaw %s: %s" % (path, error))

    pending = set(paths)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for path in tuple(pending):
            try:
                with open(
                    os.path.join(path, "cgroup.events"), encoding="ascii"
                ) as source:
                    frozen = None
                    for line in source:
                        fields = line.split()
                        if len(fields) == 2 and fields[0] == "frozen":
                            frozen = fields[1]
                            break
            except OSError as error:
                errors.append("could not read thaw state for %s: %s" % (path, error))
                pending.remove(path)
                continue
            if frozen is None:
                errors.append("cgroup.events has no frozen state at %s" % path)
                pending.remove(path)
            elif frozen == "0":
                pending.remove(path)
        if pending:
            time.sleep(poll)

    for path in sorted(pending):
        errors.append("cgroup did not thaw before timeout: %s" % path)
    if errors:
        raise ScenarioError("; ".join(errors))


def _m3_events(path, offset):
    events = []
    try:
        with open(path, encoding="utf-8") as source:
            source.seek(offset)
            for line in source:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            return source.tell(), events
    except OSError:
        return offset, []


def _is_taema_daemon_argv(argv):
    """Recognize the internal daemon module and the public `taema daemon` command."""
    for index, arg in enumerate(argv[:-1]):
        if arg != "-m":
            continue
        module = argv[index + 1]
        if module == "taema.daemon_entrypoint":
            return True
        if module == "taema" and "daemon" in argv[index + 2 :]:
            return True
    return False


def _m3_daemon_pid():
    for entry in os.listdir(PROCROOT):
        if not entry.isdigit():
            continue
        root = os.path.join(PROCROOT, entry)
        try:
            if os.stat(root).st_uid != os.getuid():
                continue
            with open(os.path.join(root, "cmdline"), "rb") as source:
                argv = [
                    part.decode("utf-8", "replace")
                    for part in source.read().split(b"\0")
                    if part
                ]
            if _is_taema_daemon_argv(argv):
                return int(entry)
        except (OSError, ValueError):
            continue
    raise ScenarioError("could not find the per-user taema daemon process")


def _m3_daemon_sample(pid):
    with open(os.path.join(PROCROOT, str(pid), "status"), encoding="ascii") as source:
        status = source.read()
    rss = None
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1])
            break
    with open(os.path.join(PROCROOT, str(pid), "stat"), encoding="ascii") as source:
        fields = source.read().rsplit(")", 1)[1].split()
    if rss is None or len(fields) < 13:
        raise ScenarioError("daemon RSS/CPU counters unavailable for pid %d" % pid)
    ticks = int(fields[11]) + int(fields[12])
    pressure_path = os.path.join(CGROOT, "user", str(os.getuid()), "memory.pressure")
    psi_fds = 0
    for fd in glob.glob(os.path.join(PROCROOT, str(pid), "fd", "*")):
        try:
            target = os.readlink(fd)
            if os.path.normpath(target) == os.path.normpath(pressure_path):
                psi_fds += 1
        except OSError:
            pass
    return rss, ticks, psi_fds


def _m3_production_guard_configured(contents):
    """Require the production guard and both production PSI thresholds in the live config."""
    try:
        config = tomllib.loads(contents)
    except (TypeError, tomllib.TOMLDecodeError):
        return False
    guard = config.get("guard", {})
    experimental = config.get("experimental", {})
    memory = config.get("mem", {})
    return (
        config.get("mode") == "auto"
        and isinstance(memory, dict)
        and memory.get("enabled") is True
        and isinstance(guard, dict)
        and guard.get("enabled") is True
        and guard.get("psi_some") == "150ms/2s"
        and guard.get("psi_full") == "50ms/2s"
        and isinstance(experimental, dict)
        and experimental.get("guard") is True
    )


def _m3_footprint_guard_inputs(configured, psi_trigger_fds, status):
    """Confirm the daemon is running with production guard settings and both PSI fds."""
    daemon_status = status.get("status", {}) if isinstance(status, dict) else {}
    memory_status = status.get("memory", {}) if isinstance(status, dict) else {}
    return (
        _m3_production_guard_configured(configured)
        and isinstance(psi_trigger_fds, int)
        and not isinstance(psi_trigger_fds, bool)
        and psi_trigger_fds == 2
        and isinstance(daemon_status, dict)
        and daemon_status.get("daemon") == "running"
        and daemon_status.get("mode") == "auto"
        and not daemon_status.get("config_error")
        and isinstance(memory_status, dict)
        and memory_status.get("enabled") is True
    )


def _m3_unittest_passed(returncode, output, *, fail_on_skip=False):
    """Whether a focused unittest command passed, optionally requiring zero skips."""
    if returncode != 0:
        return False
    if fail_on_skip:
        for match in re.finditer(r"\(skipped=(\d+)\)", output or ""):
            if int(match.group(1)):
                return False
    return True


def _m3_memory_sample_bounds(path):
    with sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5) as db:
        row = db.execute("SELECT count(*), max(ts) FROM mem_samples").fetchone()
    return int(row[0] or 0), float(row[1] or 0)


def _m3_run_tests(rec, args, label, tests, extra_env=None, *, fail_on_skip=False):
    log_path = os.path.join(args.artifacts, label + ".log")
    env = dict(os.environ)
    installed = "/usr/lib/taema"
    if os.path.isdir(installed):
        env["PYTHONPATH"] = installed + os.pathsep + env.get("PYTHONPATH", "")
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "-v"] + list(tests),
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=150,
    )
    with open(log_path, "w", encoding="utf-8") as target:
        target.write(result.stdout or "")
    passed = _m3_unittest_passed(
        result.returncode, result.stdout or "", fail_on_skip=fail_on_skip
    )
    rec.step(
        label,
        passed,
        "rc=%d fail_on_skip=%s log=%s\n%s"
        % (result.returncode, fail_on_skip, log_path, (result.stdout or "")[-2500:]),
    )
    return passed


def _m3_pressure_probe(rec, args):
    installed = "/usr/lib/taema"
    if os.path.isdir(installed) and installed not in sys.path:
        sys.path.insert(0, installed)
    from taema.governor.guard import (
        available_floor_bytes,
        detect_oom_handlers,
        earlyoom_memory_percent,
    )

    config_path = _m3_config_path()
    saved_config = _m3_config_snapshot(config_path)
    artifact_dir = os.path.join(args.artifacts, "m3-pressure")
    os.makedirs(artifact_dir, exist_ok=True)
    state_log = os.path.join(args.state_dir, "decisions.log")
    oom_log_path = os.path.join(artifact_dir, "earlyoom.log")
    cache_path = None
    ready_path = os.path.join(artifact_dir, "candidate.ready")
    candidate_gate = os.path.join(artifact_dir, "candidate.go")
    pressure_gate = os.path.join(artifact_dir, "pressure.go")
    pressure_cap = os.path.join(artifact_dir, "pressure.cap")
    pressure_state = os.path.join(artifact_dir, "pressure.json")
    base = os.path.join(CGROOT, "user", str(os.getuid()))
    leftover_parent = os.path.join(base, "leftover")
    made_parent = not os.path.isdir(leftover_parent)
    candidate_path = pressure_path = None
    candidate_created = pressure_created = False
    candidate = pressure = earlyoom = None
    master = slave = None
    reader = None
    oom_chunks = []
    errors = []
    changed_config = False
    failure = None

    candidate_code = r"""import ctypes, os, signal, sys, time
+ready, gate, cache, anon_mb, file_mb = sys.argv[1:]
+try: ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"m3cache"), 0, 0, 0)
+except Exception: pass
+while not os.path.exists(gate): time.sleep(0.02)
+pages = []
+for _ in range(int(anon_mb)):
+    block = bytearray(1024 * 1024)
+    for at in range(0, len(block), 4096): block[at] = 1
+    pages.append(block)
+with open(cache, "wb", buffering=0) as target:
+    chunk = b"x" * (1024 * 1024)
+    for _ in range(int(file_mb)): target.write(chunk)
+    os.fsync(target.fileno())
+with open(ready, "w") as target: target.write(str(os.getpid()))
+signal.pause()
+"""
    pressure_code = r"""import ctypes, json, os, signal, sys, time
+gate, capfile, statefile = sys.argv[1:]
+try: ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"m3press"), 0, 0, 0)
+except Exception: pass
+paused = False
+stopping = False
+def pause(*_):
+    global paused
+    paused = True
+def resume(*_):
+    global paused
+    paused = False
+def stop(*_):
+    global stopping
+    stopping = True
+signal.signal(signal.SIGUSR1, pause)
+signal.signal(signal.SIGUSR2, resume)
+signal.signal(signal.SIGTERM, stop)
+while not os.path.exists(gate): time.sleep(0.02)
+blocks = []
+allocated = 0
+chunk_bytes = 2 * 1024 * 1024
+churns = 0
+while not stopping:
+    if paused:
+        time.sleep(0.05)
+        continue
+    try:
+        with open(capfile) as source: cap = int(source.read().strip())
+    except (OSError, ValueError):
+        cap = 0
+    block = bytearray(chunk_bytes)
+    for at in range(0, len(block), 4096): block[at] = 1
+    if allocated + chunk_bytes <= cap:
+        blocks.append(block)
+        allocated += len(block)
+    else:
+        del block
+        churns += 1
+    tmp = statefile + ".tmp"
+    with open(tmp, "w") as target: json.dump({"allocated_bytes": allocated, "churns": churns}, target)
+    os.replace(tmp, statefile)
+"""
    try:
        if not os.path.isfile("/usr/bin/earlyoom"):
            raise ScenarioError("earlyoom is not installed in the VM guest")
        if detect_oom_handlers().get("earlyoom"):
            raise ScenarioError(
                "an earlyoom handler already exists in the disposable guest"
            )
        _m3_write_config(config_path, _m3_guard_config())
        changed_config = True
        master, slave = pty.openpty()
        earlyoom = subprocess.Popen(
            ["/usr/bin/earlyoom", "-m", "5", "-s", "100", "-d", "-r", "1"],
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave)
        slave = None

        def drain_output():
            try:
                with open(oom_log_path, "w", encoding="utf-8") as log:
                    while True:
                        readable, _, _ = select.select([master], [], [], 0.2)
                        if not readable:
                            if earlyoom.poll() is not None:
                                break
                            continue
                        try:
                            data = os.read(master, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        chunk = data.decode("utf-8", "replace")
                        oom_chunks.append(chunk)
                        log.write(chunk)
                        log.flush()
            except OSError:
                pass

        reader = threading.Thread(target=drain_output, daemon=True)
        reader.start()
        time.sleep(0.4)
        if earlyoom.poll() is not None:
            raise ScenarioError("earlyoom exited at startup")
        # Restart only after earlyoom is visible so the daemon's startup handler
        # scan resolves the matching 9% automatic floor without a stale cache.
        _m3_restart()

        available, total = _m3_memory()
        handler = next(
            (
                item
                for item in detect_oom_handlers().get("earlyoom", ())
                if item.pid == earlyoom.pid
            ),
            None,
        )
        if handler is None:
            raise ScenarioError("daemon handler detector missed synthetic earlyoom")
        memory_percent = earlyoom_memory_percent(handler, total)
        guard_floor = available_floor_bytes(
            total,
            "auto",
            earlyoom_present=True,
            earlyoom_memory_percent=memory_percent,
        )
        oom_floor = math.ceil(total * 5 / 100)
        if memory_percent != 5.0 or guard_floor is None or guard_floor <= oom_floor:
            raise ScenarioError(
                "unexpected floors: earlyoom=%.2f%% guard=%s"
                % (memory_percent, guard_floor)
            )
        if available <= guard_floor:
            raise ScenarioError(
                "guest lacks healthy setup headroom: available=%d floor=%d"
                % (available, guard_floor)
            )
        mib = 1024 * 1024
        reclaim_bytes = max(8 * mib, min(32 * mib, guard_floor - oom_floor - 12 * mib))
        reclaim_mb = reclaim_bytes // mib
        anon_mb = max(32, min(64, total // (16 * mib)))
        file_mb = anon_mb + 128 + reclaim_mb

        if not os.path.isdir(leftover_parent):
            os.makedirs(leftover_parent)
        _m3_enable_memory_controllers(base, leftover_parent)
        token = str(os.getpid())
        candidate_scope = "leftover/m3_cache_" + token
        pressure_scope = "m3_pressure_" + token
        candidate_path = os.path.join(base, candidate_scope)
        pressure_path = os.path.join(base, pressure_scope)
        os.mkdir(candidate_path)
        candidate_created = True
        os.mkdir(pressure_path)
        pressure_created = True
        if not os.path.isfile(os.path.join(candidate_path, "cgroup.freeze")):
            raise ScenarioError("candidate cgroup has no freeze control")

        candidate_code = candidate_code.replace("\n+", "\n")
        pressure_code = pressure_code.replace("\n+", "\n")
        cache_path = _m3_create_cache_file()
        candidate = subprocess.Popen(
            [
                sys.executable,
                "-c",
                candidate_code,
                ready_path,
                candidate_gate,
                cache_path,
                str(anon_mb),
                str(file_mb),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _m3_move(candidate.pid, candidate_path)
        open(candidate_gate, "w").close()
        deadline = time.monotonic() + 45
        while not os.path.exists(ready_path) and time.monotonic() < deadline:
            if candidate.poll() is not None:
                raise ScenarioError("cache candidate exited during setup")
            time.sleep(0.1)
        if not os.path.exists(ready_path):
            raise ScenarioError("cache candidate setup timed out")

        adj_path = os.path.join(PROCROOT, str(candidate.pid), "oom_score_adj")
        deadline = time.monotonic() + 30
        oom_adj = None
        while time.monotonic() < deadline:
            try:
                with open(adj_path) as source:
                    oom_adj = int(source.read().strip())
            except (OSError, ValueError):
                break
            if oom_adj == 500:
                break
            time.sleep(0.25)
        if oom_adj != 500:
            raise ScenarioError("leftover oom_score_adj=%r, expected 500" % oom_adj)

        stats = _m3_cgroup_stats(candidate_path)
        if stats.get("anon_bytes", 0) < anon_mb * 900 * 1024:
            raise ScenarioError("candidate anonymous set too small: %s" % stats)
        expected_cache_bytes = file_mb * 900 * 1024
        if stats.get("file_bytes", 0) < expected_cache_bytes:
            raise ScenarioError("candidate page cache too small: %s" % stats)
        shmem_bytes = stats.get("shmem_bytes", 0)
        if shmem_bytes > 8 * mib:
            raise ScenarioError(
                "candidate cache is not disk-backed: shmem=%d stats=%s"
                % (shmem_bytes, stats)
            )
        reclaimable_file_cache_bytes = _m3_reclaimable_file_cache_bytes(stats)
        if (
            reclaimable_file_cache_bytes is None
            or reclaimable_file_cache_bytes < expected_cache_bytes
        ):
            raise ScenarioError(
                "candidate reclaimable file cache too small: reclaimable=%s "
                "expected=%d stats=%s"
                % (reclaimable_file_cache_bytes, expected_cache_bytes, stats)
            )
        pressure_baseline, _ = _m3_memory()
        if pressure_baseline <= guard_floor + 56 * mib:
            raise ScenarioError(
                "candidate fixture left insufficient pre-floor headroom: "
                "available=%d floor=%d" % (pressure_baseline, guard_floor)
            )
        # Keep global MemAvailable safely above the floor while a separate,
        # constrained scope creates sustained PSI stall pressure.
        pressure_budget = min(
            32 * mib,
            ((pressure_baseline - guard_floor - 48 * mib) // (2 * mib)) * (2 * mib),
        )
        if pressure_budget < 8 * mib:
            raise ScenarioError("insufficient headroom for bounded PSI pressure")
        rec.step(
            "pressure-fixture-ready",
            True,
            "candidate=%s pid=%d oom_score_adj=500 stats=%s "
            "reclaimable_file_cache=%d expected=%d earlyoom_pid=%d "
            "threshold=%d guard_floor=%d"
            % (
                candidate_scope,
                candidate.pid,
                stats,
                reclaimable_file_cache_bytes,
                expected_cache_bytes,
                earlyoom.pid,
                oom_floor,
                guard_floor,
            ),
        )

        pressure = subprocess.Popen(
            [
                sys.executable,
                "-c",
                pressure_code,
                pressure_gate,
                pressure_cap,
                pressure_state,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _m3_move(pressure.pid, pressure_path)
        pressure_oom_adj = _m3_set_oom_score_adj(pressure.pid, -1000)
        if pressure_oom_adj != -1000:
            raise ScenarioError(
                "pressure worker oom_score_adj=%d, expected -1000" % pressure_oom_adj
            )
        high_path = os.path.join(pressure_path, "memory.high")
        with open(high_path, "w", encoding="ascii") as target_file:
            target_file.write("2M\n")
        with open(high_path, encoding="ascii") as source:
            pressure_high = source.read().strip()
        if pressure_high != str(2 * mib):
            raise ScenarioError(
                "could not bound PSI pressure cgroup: %s" % pressure_high
            )
        with open(pressure_cap, "w") as target_file:
            target_file.write(str(pressure_budget))
        event_offset = os.path.getsize(state_log) if os.path.isfile(state_log) else 0
        open(pressure_gate, "w").close()

        current = pressure_baseline
        min_pressure_available = current
        guard_started = page_step = reclaim = freeze_step = None
        offset = event_offset
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and freeze_step is None:
            current, _ = _m3_memory()
            min_pressure_available = min(min_pressure_available, current)
            if current <= guard_floor:
                raise ScenarioError(
                    "MemAvailable reached the floor before guard actions: "
                    "available=%d floor=%d" % (current, guard_floor)
                )
            offset, events = _m3_events(state_log, offset)
            for event in events:
                if event.get("event") == "guard_started" and event.get("trigger") in (
                    "some",
                    "full",
                ):
                    guard_started = event
                if (
                    event.get("event") == "memory_reclaimed"
                    and event.get("scope") == candidate_scope
                    and int(event.get("file_reclaimed_bytes", 0) or 0) > 0
                ):
                    reclaim = event
                if event.get("event") == "guard_step":
                    if event.get(
                        "step"
                    ) == "page_cache" and candidate_scope in event.get("scopes", []):
                        page_step = event
                    if event.get("step") == "freeze" and candidate_scope in event.get(
                        "scopes", []
                    ):
                        freeze_step = event
            try:
                with open(pressure_state) as source:
                    pressure_state_data = json.load(source)
            except (OSError, ValueError):
                pressure_state_data = {}
            if not pressure_state_data and pressure.poll() is not None:
                raise ScenarioError("bounded PSI pressure worker exited early")
            time.sleep(0.1)
        try:
            with open(os.path.join(candidate_path, "cgroup.events")) as source:
                is_frozen = "frozen 1" in source.read().splitlines()
        except OSError:
            is_frozen = False
        guard_start_available = (
            guard_started.get("available_bytes")
            if isinstance(guard_started, dict)
            else None
        )
        guard_ok = bool(
            guard_started
            and isinstance(guard_start_available, int)
            and guard_start_available > guard_floor
            and min_pressure_available > guard_floor
            and page_step
            and reclaim
            and freeze_step
            and is_frozen
        )
        rec.step(
            "guard-reclaim-freeze-before-earlyoom",
            guard_ok,
            "threshold=%d guard_floor=%d guard_started_available=%s "
            "min_pressure_available=%d pressure_high=%s budget=%d "
            "reclaim=%s page_cache_step=%s freeze_step=%s frozen=%s"
            % (
                oom_floor,
                guard_floor,
                guard_start_available,
                min_pressure_available,
                pressure_high,
                pressure_budget,
                reclaim,
                page_step,
                freeze_step,
                is_frozen,
            ),
        )
        if not guard_ok:
            raise ScenarioError(
                "guard did not reclaim/freeze above floor: start=%s minimum=%d floor=%d"
                % (guard_start_available, min_pressure_available, guard_floor)
            )

        # Only after both guard actions are proven, remove the test cgroup's
        # soft cap and allow the bounded hog to cross earlyoom's threshold.
        with open(high_path, "w", encoding="ascii") as target_file:
            target_file.write("max\n")
        current, _ = _m3_memory()
        try:
            with open(pressure_state) as source:
                allocated = int(json.load(source).get("allocated_bytes", 0))
        except (OSError, ValueError):
            allocated = 0
        # earlyoom runs in the delegated user cgroup; use its live denominator,
        # which can differ from the host MemTotal used for the guard floor above.
        initial_samples = _m3_parse_earlyoom_memory_samples("".join(oom_chunks))
        if not initial_samples:
            raise ScenarioError(
                "earlyoom did not report memory availability before ramp"
            )
        latest_sample = initial_samples[-1]
        actual_earlyoom_threshold_bytes = latest_sample["threshold_bytes"]
        mib = 1024 * 1024
        final_target, pressure_cap_bytes = _m3_post_guard_pressure_cap(
            allocated,
            latest_sample["available_mib"] * mib,
            actual_earlyoom_threshold_bytes,
        )
        initial_pressure_target_bytes = final_target
        with open(pressure_cap, "w") as target_file:
            target_file.write(str(pressure_cap_bytes))
        preselection_oom_metrics = {
            "candidate": _m3_process_oom_evidence(candidate.pid),
            "pressure_worker": _m3_process_oom_evidence(pressure.pid),
        }
        if preselection_oom_metrics["candidate"]["oom_score_adj"] != 500:
            raise ScenarioError("candidate oom_score_adj changed before selection")
        if preselection_oom_metrics["pressure_worker"]["oom_score_adj"] != -1000:
            raise ScenarioError(
                "pressure worker oom_score_adj changed before selection"
            )
        pressure.send_signal(signal.SIGUSR2)

        ramp_started = time.monotonic()
        pressure_cap_history = [
            {
                "elapsed_seconds": 0.0,
                "cap_bytes": pressure_cap_bytes,
                "increment_bytes": 0,
                "reason": "actual-earlyoom-threshold",
                "earlyoom_available_mib": latest_sample["available_mib"],
                "earlyoom_total_mib": latest_sample["total_mib"],
                "earlyoom_threshold_bytes": actual_earlyoom_threshold_bytes,
                "target_bytes": initial_pressure_target_bytes,
            }
        ]
        pressure_increments = []
        earlyoom_available_samples = [dict(latest_sample, elapsed_seconds=0.0)]
        seen_sample_count = len(initial_samples)
        next_ramp_at = ramp_started + _M3_PRESSURE_RAMP_INTERVAL_SECONDS
        deadline = ramp_started + 30
        selected = None
        while time.monotonic() < deadline:
            output = "".join(oom_chunks)
            samples = _m3_parse_earlyoom_memory_samples(output)
            if len(samples) > seen_sample_count:
                sample_time = time.monotonic() - ramp_started
                for sample in samples[seen_sample_count:]:
                    actual_earlyoom_threshold_bytes = sample["threshold_bytes"]
                    final_target = max(0, actual_earlyoom_threshold_bytes - 16 * mib)
                    latest_sample = sample
                    earlyoom_available_samples.append(
                        dict(sample, elapsed_seconds=round(sample_time, 2))
                    )
                seen_sample_count = len(samples)
            match = re.search(r"sending SIGTERM to process\s+(\d+)", output, re.I)
            if match:
                selected = int(match.group(1))
                break
            if earlyoom.poll() is not None:
                break
            preselection_oom_metrics = {
                "candidate": _m3_process_oom_evidence(candidate.pid),
                "pressure_worker": _m3_process_oom_evidence(pressure.pid),
            }
            if preselection_oom_metrics["candidate"]["oom_score_adj"] != 500:
                raise ScenarioError("candidate oom_score_adj changed before selection")
            if preselection_oom_metrics["pressure_worker"]["oom_score_adj"] != -1000:
                raise ScenarioError(
                    "pressure worker oom_score_adj changed before selection"
                )
            try:
                with open(pressure_state) as source:
                    pressure_state_data = json.load(source)
            except (OSError, ValueError):
                pressure_state_data = {}
            if not pressure_state_data and pressure.poll() is not None:
                raise ScenarioError("bounded PSI pressure worker exited during ramp")

            now = time.monotonic()
            if (
                now >= next_ramp_at
                and len(pressure_increments) < _M3_PRESSURE_RAMP_MAX_STEPS
            ):
                pressure_cap_bytes, increment_bytes = _m3_pressure_ramp_next_cap(
                    pressure_cap_bytes, len(pressure_increments)
                )
                if increment_bytes:
                    with open(pressure_cap, "w") as target_file:
                        target_file.write(str(pressure_cap_bytes))
                    increment = {
                        "elapsed_seconds": round(now - ramp_started, 2),
                        "increment_bytes": increment_bytes,
                        "cap_bytes": pressure_cap_bytes,
                        "earlyoom_available_mib": latest_sample["available_mib"],
                        "earlyoom_total_mib": latest_sample["total_mib"],
                        "earlyoom_threshold_bytes": actual_earlyoom_threshold_bytes,
                        "target_bytes": final_target,
                    }
                    pressure_increments.append(increment)
                    pressure_cap_history.append(dict(increment))
                next_ramp_at = now + _M3_PRESSURE_RAMP_INTERVAL_SECONDS
            time.sleep(0.1)
        if earlyoom.poll() is None:
            earlyoom.terminate()
            try:
                earlyoom.wait(timeout=3)
            except subprocess.TimeoutExpired:
                earlyoom.kill()
                earlyoom.wait(timeout=3)
        if reader is not None:
            reader.join(timeout=3)
        final_samples = _m3_parse_earlyoom_memory_samples("".join(oom_chunks))
        if len(final_samples) > seen_sample_count:
            sample_time = time.monotonic() - ramp_started
            for sample in final_samples[seen_sample_count:]:
                actual_earlyoom_threshold_bytes = sample["threshold_bytes"]
                final_target = max(0, actual_earlyoom_threshold_bytes - 16 * mib)
                latest_sample = sample
                earlyoom_available_samples.append(
                    dict(sample, elapsed_seconds=round(sample_time, 2))
                )
            seen_sample_count = len(final_samples)
        selected_scope = ""
        selected_adj = None
        selected_leftover = False
        if selected is not None:
            try:
                selected_scope = scope_of(selected)
                selected_leftover = scope_matches(selected_scope, "leftover/")
                with open(
                    os.path.join(PROCROOT, str(selected), "oom_score_adj")
                ) as source:
                    selected_adj = int(source.read().strip())
            except (OSError, ScenarioError, ValueError):
                selected_scope = "exited after signal"
                selected_leftover = selected == candidate.pid
                selected_adj = 500 if selected_leftover else None
        selected_ok = selected is not None and selected_leftover and selected_adj == 500
        rec.step(
            "earlyoom-selects-leftover-500",
            selected_ok,
            "pid=%s scope=%s oom_score_adj=%s threshold=%d total_mib=%d "
            "available_mib=%d cap=%d increments=%d prior_log=%s"
            % (
                selected,
                selected_scope,
                selected_adj,
                actual_earlyoom_threshold_bytes,
                latest_sample["total_mib"],
                latest_sample["available_mib"],
                pressure_cap_bytes,
                len(pressure_increments),
                oom_log_path,
            ),
        )
        with open(
            os.path.join(args.artifacts, "m3-pressure-evidence.json"), "w"
        ) as target:
            json.dump(
                {
                    "earlyoom_pid": earlyoom.pid,
                    "earlyoom_threshold_bytes": actual_earlyoom_threshold_bytes,
                    "earlyoom_total_mib": latest_sample["total_mib"],
                    "earlyoom_available_mib": latest_sample["available_mib"],
                    "earlyoom_available_samples": earlyoom_available_samples,
                    "guard_oom_floor_bytes": oom_floor,
                    "guard_floor_bytes": guard_floor,
                    "guard_started_available_bytes": guard_start_available,
                    "minimum_pre_floor_available_bytes": min_pressure_available,
                    "pressure_available_bytes": current,
                    "pressure_cgroup_high": pressure_high,
                    "pressure_budget_bytes": pressure_budget,
                    "post_guard_pressure_target_bytes": final_target,
                    "post_guard_pressure_initial_target_bytes": initial_pressure_target_bytes,
                    "post_guard_pressure_initial_cap_bytes": pressure_cap_history[0][
                        "cap_bytes"
                    ],
                    "post_guard_pressure_cap_bytes": pressure_cap_bytes,
                    "post_guard_pressure_cap_history": pressure_cap_history,
                    "post_guard_pressure_increments": pressure_increments,
                    "candidate_scope": candidate_scope,
                    "candidate_pid": candidate.pid,
                    "candidate_oom_metrics_before_selection": (
                        preselection_oom_metrics["candidate"]
                        if preselection_oom_metrics is not None
                        else None
                    ),
                    "candidate_stats": stats,
                    "candidate_reclaimable_file_cache_bytes": reclaimable_file_cache_bytes,
                    "pressure_worker_pid": pressure.pid,
                    "pressure_worker_oom_metrics_before_selection": (
                        preselection_oom_metrics["pressure_worker"]
                        if preselection_oom_metrics is not None
                        else None
                    ),
                    "reclaim_event": reclaim,
                    "page_cache_step": page_step,
                    "freeze_step": freeze_step,
                    "selected_pid": selected,
                    "selected_scope": selected_scope,
                    "selected_oom_score_adj": selected_adj,
                    "earlyoom_selected_prioritized_leftover": selected_ok,
                    "earlyoom_log": oom_log_path,
                },
                target,
                indent=2,
                sort_keys=True,
            )
        rec.step(
            "pressure-evidence-artifact",
            True,
            "m3-pressure-evidence.json; " + oom_log_path,
        )
        if not selected_ok:
            raise ScenarioError(
                "earlyoom did not select the prioritized leftover after %d bounded "
                "pressure increments; latest=%s"
                % (len(pressure_increments), latest_sample)
            )
    except Exception as error:
        failure = error
    finally:
        try:
            _m3_thaw_cgroups(
                candidate_path if candidate_created else None,
                pressure_path if pressure_created else None,
                pressure_proc=pressure,
            )
        except ScenarioError as error:
            errors.append("could not release fixture cgroups: %s" % error)
        for proc in (earlyoom, pressure, candidate):
            if not _m3_stop_process(proc, timeout=3):
                errors.append(
                    "process %s survived SIGKILL" % getattr(proc, "pid", None)
                )
        if reader is not None:
            reader.join(timeout=3)
        for path, created in (
            (pressure_path, pressure_created),
            (candidate_path, candidate_created),
        ):
            if not created:
                continue
            if path and os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError as error:
                    errors.append("could not remove %s: %s" % (path, error))
        if made_parent and os.path.isdir(leftover_parent):
            try:
                os.rmdir(leftover_parent)
            except OSError as error:
                errors.append("could not remove leftover parent: %s" % error)
        for path in (
            cache_path,
            ready_path,
            candidate_gate,
            pressure_gate,
            pressure_cap,
            pressure_state,
        ):
            if path is None:
                continue
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError as error:
                errors.append("could not remove %s: %s" % (path, error))
        if changed_config:
            try:
                _m3_restore_config(config_path, saved_config)
                _m3_restart()
            except Exception as error:
                errors.append("could not restore config and daemon: %s" % error)
        for fd in (master, slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        rec.step(
            "pressure-fixture-cleanup",
            not errors,
            "; ".join(errors) or "thawed, stopped, removed and restored configuration",
        )
    if failure is not None:
        raise ScenarioError("pressure probe failed: %s" % failure)
    if errors:
        raise ScenarioError("pressure cleanup failed: %s" % "; ".join(errors))
    return True


def _m3_footprint_probe(rec, args):
    config_path = _m3_config_path()
    saved_config = _m3_config_snapshot(config_path)
    changed = False
    cleanup_error = ""
    try:
        _m3_write_config(config_path, _m3_guard_config(pressure_fixture=False))
        changed = True
        before = _m3_restart()
        status = before.get("status", {})
        memory = before.get("memory", {})
        if (
            status.get("daemon") != "running"
            or status.get("mode") != "auto"
            or status.get("config_error")
            or memory.get("enabled") is not True
        ):
            raise ScenarioError("guard/memory daemon not ready: %s" % before)
        try:
            quiet = _m3_wait_for_footprint_quiet()
        except ScenarioError as error:
            rec.step("footprint-idle-stabilization", False, str(error))
            raise
        rec.step(
            "footprint-idle-stabilization",
            True,
            "waited=%.2fs stable=%.2fs some_total=%d full_total=%d "
            "some_avg10=%.3f%% full_avg10=%.3f%%"
            % (
                quiet["waited_seconds"],
                quiet["stable_seconds"],
                quiet["some_total"],
                quiet["full_total"],
                quiet["some_avg10"],
                quiet["full_avg10"],
            ),
        )
        daemon_pid = _m3_daemon_pid()
        db_path = os.path.join(args.state_dir, "state.db")
        db_count_before, db_latest_before = _m3_memory_sample_bounds(db_path)
        rss, ticks, psi_fds = _m3_daemon_sample(daemon_pid)
        initial_ticks = ticks
        available, total = _m3_memory()
        fallback = available >= 0 and total > 0
        with open(config_path, encoding="utf-8") as source:
            configured = source.read()
        if not _m3_footprint_guard_inputs(configured, psi_fds, before):
            raise ScenarioError(
                "production guard trigger inputs unavailable: psi_trigger_fds=%d floor=%s"
                % (psi_fds, fallback)
            )

        hz = os.sysconf("SC_CLK_TCK")
        start = time.monotonic()
        prior_time = start
        prior_ticks = ticks
        max_rss = rss
        max_interval_cpu = 0.0
        psi_samples = int(psi_fds == 2)
        guard_samples = int(_m3_footprint_guard_inputs(configured, psi_fds, before))
        floor_samples = int(fallback)
        sample_count = 0
        csv_path = os.path.join(args.artifacts, "m3-daemon-footprint.csv")
        with open(csv_path, "w", encoding="utf-8") as output:
            output.write(
                "elapsed_s,rss_kib,cpu_interval_pct,psi_trigger_fds,floor_sampler\n"
            )
            output.write("0,%d,0,%d,%d\n" % (rss, psi_fds, fallback))
            output.flush()
            while time.monotonic() - start < 610:
                time.sleep(min(1.0, max(0.0, 610 - (time.monotonic() - start))))
                now = time.monotonic()
                rss, ticks, psi_fds = _m3_daemon_sample(daemon_pid)
                interval = max(0.001, now - prior_time)
                interval_cpu = 100.0 * max(0, ticks - prior_ticks) / (hz * interval)
                max_rss = max(max_rss, rss)
                max_interval_cpu = max(max_interval_cpu, interval_cpu)
                available, total = _m3_memory()
                fallback = available >= 0 and total > 0
                with open(config_path, encoding="utf-8") as source:
                    configured = source.read()
                sample_guard_active = _m3_footprint_guard_inputs(
                    configured, psi_fds, before
                )
                psi_samples += int(psi_fds == 2)
                guard_samples += int(sample_guard_active)
                floor_samples += int(fallback)
                output.write(
                    "%.3f,%d,%.5f,%d,%d\n"
                    % (now - start, rss, interval_cpu, psi_fds, fallback)
                )
                output.flush()
                prior_time = now
                prior_ticks = ticks
                sample_count += 1
        elapsed = time.monotonic() - start
        avg_cpu = 100.0 * max(0, ticks - initial_ticks) / (hz * elapsed)
        after = _m3_status()
        final_status = after.get("status", {})
        final_memory = after.get("memory", {})
        with open(config_path, encoding="utf-8") as source:
            final_configured = source.read()
        final_rss, _final_ticks, final_psi_fds = _m3_daemon_sample(daemon_pid)
        max_rss = max(max_rss, final_rss)
        db_count_after, db_latest_after = _m3_memory_sample_bounds(db_path)
        triggers_active = (
            final_status.get("daemon") == "running"
            and final_status.get("mode") == "auto"
            and not final_status.get("config_error")
            and final_memory.get("enabled") is True
            and guard_samples == sample_count + 1
            and _m3_footprint_guard_inputs(final_configured, final_psi_fds, after)
        )
        passed = (
            elapsed >= 600
            and max_rss <= 30 * 1024
            and avg_cpu <= 0.2
            and triggers_active
            and db_latest_after > db_latest_before
        )
        rec.step(
            "daemon-10-minute-footprint-sampling",
            passed,
            "pid=%d elapsed=%.2fs rss_peak_kib=%d cpu_avg_pct=%.5f "
            "cpu_max_1s_pct=%.5f observations=%d psi_fd_samples=%d "
            "guard_samples=%d final_psi_fds=%d floor_samples=%d "
            "db_samples=%d->%d latest=%.3f->%.3f triggers=%s csv=%s"
            % (
                daemon_pid,
                elapsed,
                max_rss,
                avg_cpu,
                max_interval_cpu,
                sample_count + 1,
                psi_samples,
                guard_samples,
                final_psi_fds,
                floor_samples,
                db_count_before,
                db_count_after,
                db_latest_before,
                db_latest_after,
                triggers_active,
                csv_path,
            ),
        )
        return passed
    finally:
        if changed:
            try:
                _m3_restore_config(config_path, saved_config)
                _m3_restart()
            except Exception as error:
                cleanup_error = str(error)
        rec.step(
            "footprint-config-cleanup",
            not cleanup_error,
            cleanup_error or "original user config restored and daemon restarted",
        )


def remove_taema_packages():
    """Remove taema and any installed subpackage that depends on it.

    The eventd scenario installs the optional taema-eventd subpackage;
    xbps refuses to remove taema while it is installed, so remove it
    first. Removing a package that is not installed fails harmlessly.
    """
    run_privileged(["xbps-remove", "-y", "taema-eventd"])
    return run_privileged(["xbps-remove", "-y", "taema"])


def scenario_remove(rec, args, tree_holder):
    """Remove the package and verify the guest is cleaned up."""
    rm = remove_taema_packages()
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

    # runsvdir stops the service asynchronously; give the daemon a
    # bounded window to exit before declaring it left over.
    leftovers = []
    stop_deadline = time.monotonic() + 30
    while True:
        leftovers = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit() or int(entry) == os.getpid():
                continue
            try:
                with open(os.path.join("/proc", entry, "cmdline"), "rb") as f:
                    argv = [
                        part.decode("utf-8", "replace")
                        for part in f.read().split(b"\0")
                        if part
                    ]
            except OSError:
                continue
            if _is_taema_daemon_argv(argv):
                leftovers.append((entry, " ".join(argv)[:120]))
        if not leftovers or time.monotonic() >= stop_deadline:
            break
        time.sleep(0.5)
    rec.step("daemon-stopped", not leftovers, "running=%s" % leftovers)
    return all(s["ok"] for s in rec.steps)


# ---- disposable graphical session -------------------------------------------
#
# A scripted Wayland stack for desktop-path tests: weston on the headless
# backend (pixman software rendering, no seat or GPU) as the outer root,
# niri nested inside it as the compositor under test, a scripted
# org.freedesktop.Notifications server that records notifications and can
# close them or invoke actions on cue, test windows opened/closed/focused
# through niri's IPC, and grim screenshots diffed with the stdlib PNG reader
# below. Later desktop scenarios reuse start/stop_graphical_session; only
# scenario_graphical asserts the stack.

GRAPHICAL_TOOLS = (
    "weston",
    "niri",
    "foot",
    "grim",
    "notify-send",
    "dbus-daemon",
)


def weston_ini(width, height):
    """Deterministic kiosk-free config: solid background, no panel clock."""
    return (
        "[core]\n"
        "backend=headless\n"
        "[shell]\n"
        "panel-location=none\n"
        "background-color=0xff1a1a1a\n"
        "[output]\n"
        "name=headless\n"
        "mode=%dx%d\n" % (width, height)
    )


def wait_for_path(path, procs, timeout=60, poll=0.1):
    """Wait for a socket file; refuse when a watched process dies first."""
    deadline = time.monotonic() + timeout
    while True:
        if os.path.exists(path):
            return True
        dead = [p for p in procs if p.poll() is not None]
        if dead:
            raise ScenarioError(
                "%s never appeared; process exited rc=%s" % (path, dead[0].poll())
            )
        if time.monotonic() >= deadline:
            raise ScenarioError("%s never appeared within %ss" % (path, timeout))
        time.sleep(poll)


def _socket_entries(runtime_dir):
    """Socket filenames currently present in the runtime directory."""
    found = set()
    for entry in os.listdir(runtime_dir):
        try:
            mode = os.stat(os.path.join(runtime_dir, entry)).st_mode
        except OSError:
            continue
        if stat.S_ISSOCK(mode):
            found.add(entry)
    return found


def _wait_for_sockets(runtime_dir, before, procs, display, timeout=60):
    """Wait until niri's wayland and IPC sockets appear; classify them."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        dead = [p for p in procs if p.poll() is not None]
        if dead:
            raise ScenarioError(
                "compositor exited rc=%s during startup" % dead[0].poll()
            )
        new = _socket_entries(runtime_dir) - before - {display}
        wayland = sorted(name for name in new if name.startswith("wayland-"))
        ipc = sorted(name for name in new if not name.startswith("wayland-"))
        if wayland and ipc:
            return wayland[0], [os.path.join(runtime_dir, name) for name in ipc]
        time.sleep(0.1)
    raise ScenarioError("niri sockets never appeared within %ss" % timeout)


def _niri_probe(env, timeout=10):
    """True when `niri msg` answers over env's NIRI_SOCKET."""
    try:
        reply = subprocess.run(
            ["niri", "msg", "--json", "version"],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return reply.returncode == 0


def start_graphical_session(
    workdir, display="taema-test", width=800, height=600, timeout=60
):
    """Start dbus-daemon, weston, the scripted notify server, and niri."""
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime_dir or not os.path.isdir(runtime_dir):
        raise ScenarioError("XDG_RUNTIME_DIR is not a directory: %r" % runtime_dir)
    os.makedirs(workdir, exist_ok=True)
    ini_path = os.path.join(workdir, "weston.ini")
    with open(ini_path, "w") as f:
        f.write(weston_ini(width, height))
    weston_log = open(os.path.join(workdir, "weston.log"), "w")
    bus_log = open(os.path.join(workdir, "dbus.log"), "w")
    bus = subprocess.Popen(
        ["dbus-daemon", "--session", "--print-address=1", "--nofork"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=bus_log,
        text=True,
        start_new_session=True,
    )
    try:
        address = bus.stdout.readline().strip()
    except OSError as e:
        bus.kill()
        raise ScenarioError("dbus-daemon produced no address: %s" % e)
    if not address or bus.poll() is not None:
        raise ScenarioError("dbus-daemon failed during startup")
    base_env = dict(
        os.environ,
        XDG_RUNTIME_DIR=runtime_dir,
        WAYLAND_DISPLAY=display,
        DBUS_SESSION_BUS_ADDRESS=address,
        LIBGL_ALWAYS_SOFTWARE="1",
    )
    weston = subprocess.Popen(
        [
            "weston",
            "--backend=headless",
            "--socket=" + display,
            "--config=" + ini_path,
        ],
        env=base_env,
        stdin=subprocess.DEVNULL,
        stdout=weston_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    socket_path = os.path.join(runtime_dir, display)
    try:
        wait_for_path(socket_path, [weston], timeout=timeout)
    except ScenarioError:
        weston.terminate()
        raise
    notify_log_path = os.path.join(workdir, "notify.jsonl")
    notify_control_path = os.path.join(workdir, "notify.control")
    notify_log = open(os.path.join(workdir, "notify-server.log"), "w")
    server_script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "notify_server.py"
    )
    notify = subprocess.Popen(
        ["python3", server_script, notify_log_path, notify_control_path],
        env=base_env,
        stdin=subprocess.DEVNULL,
        stdout=notify_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        wait_for_path(notify_log_path, [notify], timeout=timeout)
    except ScenarioError:
        stop_graphical_session(
            {
                "notify": notify,
                "weston": weston,
                "bus": bus,
                "logs": [weston_log, notify_log, bus_log, bus.stdout],
            }
        )
        raise
    niri_config = os.path.join(workdir, "niri-config.kdl")
    with open(niri_config, "w") as handle:
        handle.write("// taema graphical test session\n")
    before = _socket_entries(runtime_dir)
    niri_log = open(os.path.join(workdir, "niri.log"), "w")
    niri = subprocess.Popen(
        ["niri", "--config", niri_config],
        env=base_env,
        stdin=subprocess.DEVNULL,
        stdout=niri_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        niri_display, ipc_candidates = _wait_for_sockets(
            runtime_dir, before, [niri], display, timeout=timeout
        )
        niri_socket = None
        for candidate in ipc_candidates:
            if _niri_probe(dict(base_env, NIRI_SOCKET=candidate)):
                niri_socket = candidate
                break
        if niri_socket is None:
            raise ScenarioError("no niri IPC socket answered `niri msg`")
    except ScenarioError:
        stop_graphical_session(
            {
                "notify": notify,
                "niri": niri,
                "weston": weston,
                "bus": bus,
                "logs": [weston_log, notify_log, niri_log, bus_log, bus.stdout],
            }
        )
        raise
    niri_env = dict(base_env, WAYLAND_DISPLAY=niri_display, NIRI_SOCKET=niri_socket)
    return {
        "weston": weston,
        "niri": niri,
        "notify": notify,
        "bus": bus,
        "display": display,
        "niri_display": niri_display,
        "runtime_dir": runtime_dir,
        "socket": socket_path,
        "env": base_env,
        "niri_env": niri_env,
        "notify_log": notify_log_path,
        "notify_control": notify_control_path,
        "logs": [weston_log, notify_log, niri_log, bus_log, bus.stdout],
    }


def stop_graphical_session(session, timeout=10):
    """Terminate the session processes; tolerate the already-dead."""
    for key in ("notify", "niri", "mako", "weston", "bus"):
        proc = session.get(key)
        if proc is None or proc.poll() is not None:
            continue
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    for handle in session.get("logs", []):
        try:
            handle.close()
        except OSError:
            pass


def notify_send(env, summary, body="", timeout=15):
    """Deliver one notification through the session bus; return CompletedProcess."""
    argv = ["notify-send", summary] + ([body] if body else [])
    return subprocess.run(
        argv, env=env, capture_output=True, text=True, timeout=timeout
    )


def notify_records(session):
    """Parsed notification-server records so far (oldest first)."""
    records = []
    try:
        with open(session["notify_log"], encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    records.append(json.loads(line))
    except OSError:
        pass
    return records


def wait_notify_record(session, event, timeout=15, **match):
    """Wait for a server record of `event` whose fields match; return it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in notify_records(session):
            if record.get("event") != event:
                continue
            if all(record.get(key) == value for key, value in match.items()):
                return record
        time.sleep(0.1)
    raise ScenarioError("no %s record matching %s within %ss" % (event, match, timeout))


def notify_cue(session, line):
    """Append one command line to the notify server's control file."""
    with open(session["notify_control"], "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


_WINDOW_CLIENTS = (
    ("foot", ["foot"]),
    ("weston-terminal", ["weston-terminal"]),
    ("weston-simple-shm", ["weston-simple-shm"]),
)


def open_test_window(env):
    """Open one test window on env's compositor; return the Popen."""
    for _name, argv in _WINDOW_CLIENTS:
        if shutil.which(argv[0]) is not None:
            return subprocess.Popen(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
    raise ScenarioError("no test-window client available")


def niri_windows(env, timeout=15):
    """The compositor's window list, parsed from `niri msg --json windows`."""
    reply = subprocess.run(
        ["niri", "msg", "--json", "windows"],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if reply.returncode != 0:
        raise ScenarioError("niri msg windows failed: %s" % reply.stderr[:200])
    try:
        windows = json.loads(reply.stdout or "[]")
    except ValueError as e:
        raise ScenarioError("niri msg windows gave bad JSON: %s" % e)
    return windows if isinstance(windows, list) else []


def wait_window_count(env, count, timeout=30):
    """Wait until the window list has exactly `count` entries; return it."""
    deadline = time.monotonic() + timeout
    windows = []
    while time.monotonic() < deadline:
        windows = niri_windows(env)
        if len(windows) == count:
            return windows
        time.sleep(0.2)
    raise ScenarioError(
        "window count never reached %d (last saw %d)" % (count, len(windows))
    )


def niri_focus_window(env, window_id, timeout=15):
    """Focus one window through niri's IPC action interface."""
    reply = subprocess.run(
        ["niri", "msg", "action", "focus-window", "--id", str(window_id)],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if reply.returncode != 0:
        raise ScenarioError("focus-window failed: %s" % reply.stderr[:200])


def take_screenshot(env, path, timeout=30):
    """Capture one output with grim; raise ScenarioError when it fails."""
    reply = subprocess.run(
        ["grim", path], env=env, capture_output=True, text=True, timeout=timeout
    )
    if reply.returncode != 0 or not os.path.isfile(path):
        raise ScenarioError(
            "grim failed rc=%s: %s"
            % (reply.returncode, (reply.stderr or reply.stdout)[:200])
        )
    return reply


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def scenario_graphical(rec, args, tree_holder):
    """Nested niri session: windows, scripted notifications, screenshot."""
    del tree_holder
    missing = [tool for tool in GRAPHICAL_TOOLS if shutil.which(tool) is None]
    rec.step(
        "graphical-tools",
        not missing,
        "missing: %s" % ",".join(missing) if missing else "all present",
    )
    if missing:
        return False
    with tempfile.TemporaryDirectory(prefix="taema-graphical-") as workdir:
        session = None
        clients = []
        try:
            session = start_graphical_session(workdir)
            rec.step(
                "session-up",
                True,
                "weston=%s niri=%s" % (session["display"], session["niri_display"]),
            )
            niri_env = session["niri_env"]
            baseline = wait_window_count(niri_env, 0)
            rec.step("window-list-baseline", baseline == [], "no windows yet")

            first = open_test_window(niri_env)
            clients.append(first)
            opened = wait_window_count(niri_env, 1)
            first_id = opened[0].get("id")
            rec.step("window-open", first_id is not None, "id=%s" % first_id)

            second = open_test_window(niri_env)
            clients.append(second)
            wait_window_count(niri_env, 2)
            rec.step("window-open-second", True, "two windows listed")

            niri_focus_window(niri_env, first_id)
            deadline = time.monotonic() + 15
            focused_id = None
            while time.monotonic() < deadline:
                for window in niri_windows(niri_env):
                    if window.get("is_focused"):
                        focused_id = window.get("id")
                if focused_id == first_id:
                    break
                time.sleep(0.2)
            rec.step(
                "window-focus",
                focused_id == first_id,
                "focused=%s want=%s" % (focused_id, first_id),
            )

            first.terminate()
            remaining = wait_window_count(niri_env, 1)
            rec.step(
                "window-close",
                len(remaining) == 1 and remaining[0].get("id") != first_id,
                "remaining=%s" % [w.get("id") for w in remaining],
            )

            wait_notify_record(session, "ready")
            client = subprocess.Popen(
                [
                    "notify-send",
                    "--wait",
                    "--action=default=Open",
                    "taema-graphical",
                    "session is up",
                ],
                env=session["env"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            clients.append(client)
            seen = wait_notify_record(session, "notify", summary="taema-graphical")
            rec.step(
                "notify-recorded",
                seen.get("summary") == "taema-graphical",
                "id=%s" % seen.get("id"),
            )
            notify_cue(session, "invoke %d default" % seen["id"])
            out, _err = client.communicate(timeout=15)
            rec.step(
                "notify-action-invoked",
                out.strip() == "default",
                "client heard action %r" % out.strip(),
            )

            sent = notify_send(session["env"], "taema-close-cue")
            closed_seen = wait_notify_record(
                session, "notify", summary="taema-close-cue"
            )
            notify_cue(session, "close %d" % closed_seen["id"])
            wait_notify_record(session, "closed", id=closed_seen["id"])
            rec.step(
                "notify-close-on-cue",
                sent.returncode == 0,
                "closed id=%s on cue" % closed_seen["id"],
            )

            shot = os.path.join(args.artifacts, "graphical.png")
            take_screenshot(session["niri_env"], shot)
            shutil.copy2(
                session["notify_log"],
                os.path.join(args.artifacts, "graphical-notify.jsonl"),
            )
            img = read_png(shot)
            distinct = len(set(img["pixels"]))
            rec.step(
                "screenshot",
                img["width"] > 0 and img["height"] > 0 and distinct > 1,
                "%dx%d distinct=%d" % (img["width"], img["height"], distinct),
            )
        except ScenarioError as e:
            rec.step("graphical", False, str(e))
            return False
        finally:
            for client in clients:
                if client.poll() is None:
                    client.terminate()
            if session is not None:
                stop_graphical_session(session)
    return all(s["ok"] for s in rec.steps)


def read_png(path):
    """Decode 8-bit RGB/RGBA PNGs to {"width","height","pixels"} (RGB bytes)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ScenarioError("cannot read %s: %s" % (path, e))
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ScenarioError("%s is not a PNG" % path)
    pos, width, height, color = 8, None, None, None
    raw = b""
    try:
        while pos + 8 <= len(data):
            (length,) = struct.unpack(">I", data[pos : pos + 4])
            ctype = data[pos + 4 : pos + 8]
            payload = data[pos + 8 : pos + 8 + length]
            if len(payload) != length or pos + 12 + length > len(data):
                raise ScenarioError("%s is truncated" % path)
            if ctype == b"IHDR":
                width, height, depth, color, comp, filt, inter = struct.unpack(
                    ">IIBBBBB", payload
                )
                if depth != 8 or color not in (2, 6) or comp != 0 or filt != 0:
                    raise ScenarioError(
                        "%s: need 8-bit RGB/RGBA, got depth=%s color=%s"
                        % (path, depth, color)
                    )
                if inter != 0:
                    raise ScenarioError("%s is interlaced" % path)
            elif ctype == b"IDAT":
                raw += payload
            elif ctype == b"IEND":
                break
            pos += 12 + length
    except struct.error as e:
        raise ScenarioError("%s has a bad chunk: %s" % (path, e))
    if width is None:
        raise ScenarioError("%s has no IHDR" % path)
    try:
        pixels = zlib.decompress(raw)
    except zlib.error as e:
        raise ScenarioError("%s has bad image data: %s" % (path, e))
    channels = 3 if color == 2 else 4
    stride = width * channels
    want = height * (stride + 1)
    if len(pixels) != want:
        raise ScenarioError(
            "%s: want %d image bytes, got %d" % (path, want, len(pixels))
        )
    out = bytearray()
    prior = bytearray(stride)
    for row in range(height):
        line = pixels[row * (stride + 1) : (row + 1) * (stride + 1)]
        kind, filt = line[0], line[1:]
        if kind > 4:
            raise ScenarioError("%s: bad filter %d" % (path, kind))
        recon = bytearray(stride)
        for i in range(stride):
            a = recon[i - channels] if i >= channels else 0
            b = prior[i]
            c = prior[i - channels] if i >= channels else 0
            if kind == 1:
                pred = a
            elif kind == 2:
                pred = b
            elif kind == 3:
                pred = (a + b) // 2
            elif kind == 4:
                pred = _paeth(a, b, c)
            else:
                pred = 0
            recon[i] = (filt[i] + pred) % 256
        if channels == 4:
            out += b"".join(bytes(recon[i : i + 3]) for i in range(0, stride, 4))
        else:
            out += recon
        prior = recon
    return {"width": width, "height": height, "pixels": bytes(out)}


def image_diff_fraction(first, second):
    """Fraction of differing bytes between two read_png images."""
    if (
        first["width"] != second["width"]
        or first["height"] != second["height"]
        or len(first["pixels"]) != len(second["pixels"])
    ):
        raise ScenarioError(
            "screenshot size mismatch: %dx%d vs %dx%d"
            % (first["width"], first["height"], second["width"], second["height"])
        )
    total = len(first["pixels"])
    if total == 0:
        return 0.0
    differing = sum(1 for a, b in zip(first["pixels"], second["pixels"]) if a != b)
    return differing / total


def _raw_daemon_status(timeout=10):
    """Ask the daemon over its socket directly, bypassing config file layers."""
    import socket as socket_mod

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    path = os.path.join(runtime_dir, "taema.sock")
    request = json.dumps({"v": 2, "id": 1, "cmd": "status", "args": {}}) + "\n"
    sock = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        sock.sendall(request.encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()
    reply = json.loads(buf.decode() or "{}")
    if isinstance(reply, dict) and reply.get("ok") is True:
        return reply.get("result") or {}
    return {}


def scenario_m4(rec, args, tree_holder):
    """M4 release gate: mode switch, invalid config, completions, status p50."""
    del tree_holder

    status, attempts = wait_for_auto_status(timeout=60)
    rec.step(
        "daemon-ready",
        status.returncode == 0 and '"mode": "auto"' in status.stdout,
        "attempts=%d socket={%s} %s"
        % (attempts, runtime_socket_detail(), (status.stdout or status.stderr)[:300]),
    )

    started = time.monotonic()
    switched = _run(["taema", "mode", "adopt"], timeout=30)
    elapsed = time.monotonic() - started
    rec.step(
        "mode-switch-no-sudo",
        switched.returncode == 0,
        "rc=%d %.3fs %s"
        % (switched.returncode, elapsed, (switched.stdout + switched.stderr)[:200]),
    )
    rec.step("mode-switch-under-1s", elapsed < 1.0, "%.3fs" % elapsed)

    status = _run(["taema", "status", "--json"], timeout=30)
    try:
        mode = json.loads(status.stdout).get("status", {}).get("mode", "")
    except ValueError:
        mode = ""
    rec.step("status-shows-adopt", mode == "adopt", "mode=%r" % mode)

    drop_dir = os.path.join(os.path.expanduser("~"), ".config", "taema", "taema.d")
    os.makedirs(drop_dir, exist_ok=True)
    bad_path = os.path.join(drop_dir, "99-m4-bad.toml")
    with open(bad_path, "w") as handle:
        handle.write('mode = "adopt"\nbroken = [oops\n')
    try:
        reloaded = _run(["taema", "reload"], timeout=30)
        output = reloaded.stdout + reloaded.stderr
        rec.step(
            "invalid-config-reports-file-line",
            reloaded.returncode != 0 and "99-m4-bad.toml" in output and ":2" in output,
            "rc=%d %s" % (reloaded.returncode, output[:300]),
        )
        try:
            kept_mode = _raw_daemon_status().get("mode", "")
        except Exception as error:
            kept_mode = "socket error: %s" % error
        rec.step(
            "invalid-config-keeps-previous", kept_mode == "adopt", "mode=%r" % kept_mode
        )
    finally:
        try:
            os.remove(bad_path)
        except OSError:
            pass
    healed = _run(["taema", "reload"], timeout=30)
    rec.step(
        "reload-after-fix",
        healed.returncode == 0,
        (healed.stdout + healed.stderr)[:200],
    )

    for path in (
        "/usr/share/bash-completion/completions/taema",
        "/usr/share/zsh/site-functions/_taema",
        "/usr/share/fish/vendor_completions.d/taema.fish",
    ):
        rec.step(
            "completion-installed-" + os.path.basename(path),
            os.path.isfile(path),
            path,
        )
    bash_load = _run(
        [
            "bash",
            "--norc",
            "-c",
            "source /usr/share/bash-completion/completions/taema && complete -p taema",
        ],
        timeout=30,
    )
    rec.step(
        "completion-loads-bash",
        bash_load.returncode == 0,
        bash_load.stdout.strip()[:200],
    )

    have_zsh = _run(["sh", "-c", "command -v zsh"], timeout=30).returncode == 0
    have_fish = _run(["sh", "-c", "command -v fish"], timeout=30).returncode == 0
    if not (have_zsh and have_fish):
        installed = run_privileged(
            ["xbps-install", "-Sy", "zsh", "fish-shell"], timeout=300
        )
        rec.step(
            "shells-install",
            installed.returncode == 0,
            (installed.stdout + installed.stderr)[-300:],
        )
        have_zsh = _run(["sh", "-c", "command -v zsh"], timeout=30).returncode == 0
        have_fish = _run(["sh", "-c", "command -v fish"], timeout=30).returncode == 0
    if have_zsh:
        zsh_load = _run(
            [
                "zsh",
                "-f",
                "-c",
                "autoload -Uz compinit && compinit -i && source /usr/share/zsh/site-functions/_taema && (( $+functions[_taema_completion] ))",
            ],
            timeout=30,
        )
        rec.step(
            "completion-loads-zsh",
            zsh_load.returncode == 0,
            (zsh_load.stdout + zsh_load.stderr)[:200],
        )
    else:
        rec.step("completion-loads-zsh", False, "zsh not installed")
    if have_fish:
        fish_load = _run(
            [
                "fish",
                "--no-config",
                "-c",
                "source /usr/share/fish/vendor_completions.d/taema.fish; complete -c taema",
            ],
            timeout=30,
        )
        rec.step(
            "completion-loads-fish",
            fish_load.returncode == 0,
            (fish_load.stdout + fish_load.stderr)[:200],
        )
    else:
        rec.step("completion-loads-fish", False, "fish not installed")

    latencies = []
    for _ in range(100):
        begun = time.monotonic()
        probe = _run(["taema", "status"], timeout=30)
        latencies.append((time.monotonic() - begun) * 1000.0)
        if probe.returncode != 0:
            break
    latencies.sort()
    p50 = latencies[len(latencies) // 2] if latencies else float("inf")
    rec.step(
        "status-p50-under-50ms",
        len(latencies) == 100 and p50 < 50.0,
        "n=%d p50=%.1fms min=%.1f max=%.1f"
        % (
            len(latencies),
            p50,
            latencies[0] if latencies else -1,
            latencies[-1] if latencies else -1,
        ),
    )
    return all(step["ok"] for step in rec.steps)


# ---- M5 release acceptance: desktop and session integration -------------------
#
# Issue #67 gate for the 0.7.0 tag. Runs the windowed M5 checks inside the
# disposable graphical session from start_graphical_session with the session
# agent up: last-window review within 3 s with Stop applied, on_last_window
# quit plus reopen-cancel, wrapped-desktop launch provenance, agent loss and
# re-registration, a 50-close notification storm under max_per_hour with a
# widget-feed screenshot, and the installed agent man page plus autostart
# snippet. Default batching and grace delays are verified in a separate run
# first so the fast drop-in below never masks them.


_M5_DROPIN_NAME = "99-m5-fast.toml"
_M5_NOTIFY_CAP = 6


def _m5_config_home():
    """The guest test user's config home (honours XDG_CONFIG_HOME)."""
    home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return home


def _m5_dropin_path():
    return os.path.join(_m5_config_home(), "taema", "taema.d", _M5_DROPIN_NAME)


def _m5_fast_config_text(grace=0, interval=1):
    """Test-only delays: no batching, wrap enabled, fast adopt.

    Bullet 1 (#67) runs with batching and grace disabled and a 1 s
    windowless sweep so the last-window question lands within 3 s of
    the close. Bullet 2 needs a real grace, so it rewrites this dropin
    with grace 3 and a 10 s sweep (stop lands inside 48 s; reopen at
    ~2 s with the ~5 s agent feed still cancels it).
    """
    return (
        "# taema-vm-m5: fast delays for the M5 gate; removed on teardown.\n"
        "[notify]\n"
        "batch_seconds = 0\n"
        "\n"
        "[agent]\n"
        "windowless_grace = %d\n" % grace + "\n"
        "[timers]\n"
        "adopt_interval = 2\n"
        "windowless_interval = %d\n" % interval + "\n"
        "[experimental]\n"
        "launch_wrap = true\n"
    )


def _m5_snapshot():
    paths = [
        _m5_dropin_path(),
        os.path.join(_m5_config_home(), "taema", "units", "m5quit.toml"),
    ]
    snapshot = {}
    for path in paths:
        try:
            with open(path, "rb") as handle:
                snapshot[path] = handle.read()
        except FileNotFoundError:
            snapshot[path] = None
    return snapshot


def _m5_write_fast(grace=0, interval=1):
    dropin = _m5_dropin_path()
    os.makedirs(os.path.dirname(dropin), exist_ok=True)
    with open(dropin, "w") as handle:
        handle.write(_m5_fast_config_text(grace, interval))
    reloaded = _run(["taema", "reload"], timeout=30)
    if reloaded.returncode != 0:
        raise ScenarioError(
            "m5 fast config reload failed: %s%s" % (reloaded.stdout, reloaded.stderr)
        )


def _m5_restore(snapshot):
    for path, contents in snapshot.items():
        if contents is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(contents)
    return run_privileged(["sv", "restart", "taema"], timeout=45)


def _m5_cli_json(argv, timeout=30):
    """Run a read-only CLI command; return parsed JSON or None."""
    reply = _run(argv, timeout=timeout)
    if reply.returncode != 0:
        return None
    try:
        return json.loads(reply.stdout or "")
    except ValueError:
        return None


def _m5_review_ids(timeout=30):
    data = _m5_cli_json(["taema", "review", "--json"], timeout=timeout)
    if isinstance(data, dict):
        data = data.get("reviews")
    if not isinstance(data, list):
        return None
    ids = []
    for item in data:
        if isinstance(item, dict) and item.get("id") is not None:
            ids.append(item["id"])
    return ids


def _m5_popen_launch(niri_env, artifacts, tag, app, cmd, logs):
    """Start `taema launch` with stderr captured to the artifacts directory."""
    log_path = os.path.join(artifacts, "m5-launch-%s.log" % tag)
    log = open(log_path, "w")
    logs.append(log)
    proc = subprocess.Popen(
        ["taema", "launch", "--app", app, "--"] + list(cmd),
        env=niri_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=log,
        start_new_session=True,
    )
    return proc, log_path


def _m5_popen_agent(niri_env, artifacts, tag, launch_logs):
    """Start `taema agent` with output captured to the artifacts directory."""
    log_path = os.path.join(artifacts, "m5-agent-%s.log" % tag)
    log = open(log_path, "w")
    launch_logs.append(log)
    proc = subprocess.Popen(
        ["taema", "agent"],
        env=niri_env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return proc, log_path


def _m5_wait_launch_scope(proc, log_path, prefixes, timeout=60):
    """Wait until the launched pid sits in a matching scope.

    Fail fast with the launch log when the child dies first instead of
    waiting out the timeout on a pid that will never arrive.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            try:
                with open(log_path, encoding="utf-8", errors="replace") as handle:
                    tail = handle.read()[-2000:]
            except OSError:
                tail = "<no launch log>"
            tail = tail.strip().splitlines()
            raise ScenarioError(
                "launch exited rc=%s before entering %s: %s"
                % (
                    proc.returncode,
                    list(prefixes),
                    "; ".join(tail[-5:]) if tail else "<silent>",
                )
            )
        try:
            rel = scope_of(proc.pid)
            if any(scope_matches(rel, p) for p in prefixes):
                return rel
        except ScenarioError:
            pass
        time.sleep(0.5)
    raise ScenarioError(
        "pid %d not in any scope matching %s within %ss"
        % (proc.pid, list(prefixes), timeout)
    )


def _m5_close_window(niri_env, window_id):
    """Close one window through the compositor; fall back to client SIGTERM."""
    reply = subprocess.run(
        ["niri", "msg", "action", "focus-window", "--id", str(window_id)],
        env=niri_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if reply.returncode == 0:
        closed = subprocess.run(
            ["niri", "msg", "action", "close-window"],
            env=niri_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if closed.returncode == 0:
            return "compositor"
    return "terminate"


def scenario_m5(rec, args, tree_holder):
    """M5 gate (#67): windowed lifecycle, launch, agent, notify cap, docs."""
    del tree_holder
    missing = [tool for tool in GRAPHICAL_TOOLS if shutil.which(tool) is None]
    rec.step(
        "graphical-tools",
        not missing,
        "missing: %s" % ",".join(missing) if missing else "all present",
    )
    if missing:
        return False
    status, _attempts = wait_for_auto_status(timeout=60)
    rec.step(
        "daemon-ready",
        status.returncode == 0,
        (status.stdout + status.stderr)[:200],
    )
    if status.returncode != 0:
        return False
    log_path = os.path.join(args.state_dir, "decisions.log")
    snapshot = _m5_snapshot()
    session = None
    agent = None
    launched = []
    launch_logs = []
    try:
        # Default delays first: with stock batching (60 s) and grace (30 s) a
        # fresh close must produce no review within 5 s and keep its scope.
        session = start_graphical_session(args.artifacts)
        rec.step("session-up", True, "niri=%s" % session["niri_display"])
        niri_env = session["niri_env"]
        before = _m5_review_ids() or []
        default_app = "m5default"
        # One launch carries both halves: the shell detaches a sleeper with
        # setsid (new session, no controlling terminal, so the pty hangup on
        # window close cannot reach it) and waits, while foot itself owns the
        # window. A second launch would reserve a *different* scope, so the
        # survivor must be born inside the first one.
        default_root, default_log = _m5_popen_launch(
            niri_env,
            args.artifacts,
            "default",
            default_app,
            ["foot", "sh", "-c", "setsid sleep 300 & wait"],
            launch_logs,
        )
        launched.append(default_root)
        default_scope = _m5_wait_launch_scope(
            default_root, default_log, ("app-" + default_app,), timeout=60
        )
        default_windows = wait_window_count(niri_env, 1)
        default_id = default_windows[0].get("id")
        _m5_close_window(niri_env, default_id)
        try:
            wait_window_count(niri_env, 0, timeout=15)
            closed_ok = True
        except ScenarioError:
            closed_ok = False
        rec.step("default-close", closed_ok, "window went away")
        time.sleep(5)
        delayed = _m5_review_ids()
        rec.step(
            "default-batch-delays-review",
            delayed is not None and len(delayed) == len(before),
            "reviews before=%d after=%d (batch holds)"
            % (len(before), len(delayed or [])),
        )
        try:
            default_kept = scope_members(default_scope) != []
            default_kept_note = "scope %s kept inside 30 s grace" % default_scope
        except ScenarioError as error:
            default_kept, default_kept_note = False, str(error)
        rec.step("default-grace-holds-scope", default_kept, default_kept_note)
        if default_root.poll() is None:
            default_root.terminate()

        # Ticket #67 bullet 1 runs with batching and grace disabled.
        _m5_write_fast(0, 1)
        rec.step(
            "fast-delays",
            True,
            "batch 0 s, grace disabled, sweep 1 s, adopt 2 s",
        )

        agent, agent_log = _m5_popen_agent(niri_env, args.artifacts, "1", launch_logs)
        try:
            wait_for_audit_event(log_path, "agent_up", None, timeout=30)
            rec.step("agent-registered", True, "agent_up in decisions.log")
        except ScenarioError as error:
            detail = str(error)
            if agent.poll() is not None:
                detail += " (agent exited rc=%s; see %s)" % (
                    agent.returncode,
                    os.path.basename(agent_log),
                )
            rec.step("agent-registered", False, detail)
            return False

        # Bullet 1: last-window close with a surviving child reviews fast.
        # Detection reads the daemon's audit event, not `taema review`:
        # the CLI sees the store file, which the daemon flushes on its
        # own schedule, while the audit event fires in the same call
        # that queues the review and its notification job.
        # The cursor precedes the launch: with grace disabled the
        # question can be queued on the first windowless observation,
        # which may land just before the close when the agent's window
        # feed has not reported the fresh window yet.
        close_app = "m5close"
        try:
            audit_offset = os.stat(log_path).st_size
        except OSError:
            audit_offset = 0
        foot, foot_log = _m5_popen_launch(
            niri_env,
            args.artifacts,
            "close",
            close_app,
            # tail (not sleep): the survivor needs an attributable,
            # answerable identity, and sleep is a trivial command that
            # the identity policy marks invalid.
            ["foot", "sh", "-c", "setsid tail -f /dev/null & wait"],
            launch_logs,
        )
        launched.append(foot)
        close_scope = _m5_wait_launch_scope(
            foot, foot_log, ("app-" + close_app,), timeout=60
        )
        windows = wait_window_count(niri_env, 1)
        window_id = windows[0].get("id")
        rec.step("close-window-open", window_id is not None, "id=%s" % window_id)
        closed_at = time.monotonic()
        _m5_close_window(niri_env, window_id)
        if foot.poll() is None:
            try:
                foot.wait(timeout=10)
            except subprocess.TimeoutExpired:
                foot.terminate()
        try:
            wait_window_count(niri_env, 0, timeout=15)
            rec.step("close-last-window", True, "window went away")
        except ScenarioError as error:
            rec.step("close-last-window", False, str(error))
        try:
            # close_scope is a full relative path (user/1001/app-m5close)
            # while the audit event carries the leaf (app-m5close).
            close_leaf = close_scope.rsplit("/", 1)[-1]
            created = wait_for_audit_event_after(
                log_path,
                audit_offset,
                "review_created",
                predicate=lambda event: event.get("scope") == close_leaf,
                timeout=30,
            )
            review_id = created.get("id")
            elapsed = time.monotonic() - closed_at
            rec.step(
                "review-within-3s",
                review_id is not None and elapsed < 3.0,
                "review %s after %.1fs" % (review_id, elapsed),
            )
        except ScenarioError as error:
            rec.step("review-within-3s", False, str(error))
            return False
        answered = _run(["taema", "answer", str(review_id), "stop"], timeout=30)
        rec.step(
            "stop-applies",
            answered.returncode == 0,
            (answered.stdout + answered.stderr)[:200],
        )
        helper_gone = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                helper_gone = scope_members(close_scope) == []
            except ScenarioError:
                helper_gone = True
            if helper_gone:
                break
            time.sleep(0.25)
        rec.step("stop-reaps-survivor", helper_gone, "tail helper exited")
        rec.step(
            "stop-removes-scope",
            wait_for_scope_gone(close_scope, timeout=20),
            close_scope,
        )

        # Bullet 2: on_last_window=quit stops after grace; reopen cancels.
        # Bullet 2 needs a real grace, so rewrite the dropin: grace 3 s
        # with a 10 s sweep (stop lands inside 48 s; a reopen at ~2 s,
        # visible to the daemon inside ~7 s via the agent feed, cancels it).
        _m5_write_fast(3, 10)
        unit_path = os.path.join(_m5_config_home(), "taema", "units", "m5quit.toml")
        os.makedirs(os.path.dirname(unit_path), exist_ok=True)
        with open(unit_path, "w") as handle:
            handle.write(
                '[unit]\nname = "m5quit"\nkind = "app"\n\n'
                '[match]\ncomm = "foot"\n\n'
                '[desktop]\non_last_window = "quit"\n'
            )
        reloaded = _run(["taema", "reload"], timeout=30)
        rec.step("quit-unit-reloads", reloaded.returncode == 0, "m5quit unit")
        quit_app = "m5quit"
        # The quit target needs a surviving child: a bare foot exits with
        # its window, leaving an empty scope with nothing to stop.
        quit_foot, quit_log = _m5_popen_launch(
            niri_env,
            args.artifacts,
            "quit",
            quit_app,
            ["foot", "sh", "-c", "setsid tail -f /dev/null & wait"],
            launch_logs,
        )
        launched.append(quit_foot)
        quit_scope = _m5_wait_launch_scope(
            quit_foot, quit_log, ("app-" + quit_app,), timeout=60
        )
        quit_windows = wait_window_count(niri_env, 1)
        _m5_close_window(niri_env, quit_windows[0].get("id"))
        rec.step(
            "quit-after-grace",
            wait_for_scope_gone(quit_scope, timeout=48),
            "scope stopped past 3 s grace",
        )
        reopen_app = "m5quit2"
        first, first_log = _m5_popen_launch(
            niri_env, args.artifacts, "reopen1", reopen_app, ["foot"], launch_logs
        )
        launched.append(first)
        reopen_scope = _m5_wait_launch_scope(
            first, first_log, ("app-" + reopen_app,), timeout=60
        )
        first_windows = wait_window_count(niri_env, 1)
        _m5_close_window(niri_env, first_windows[0].get("id"))
        time.sleep(1)
        second, _second_log = _m5_popen_launch(
            niri_env, args.artifacts, "reopen2", reopen_app, ["foot"], launch_logs
        )
        launched.append(second)
        try:
            wait_window_count(niri_env, 1, timeout=30)
            reopened = True
        except ScenarioError as error:
            reopened, reopen_note = False, str(error)
        time.sleep(8)
        try:
            members = scope_members(reopen_scope) if reopened else []
        except ScenarioError as error:
            members, reopen_note = [], str(error)
        rec.step(
            "reopen-cancels-stop",
            bool(reopened) and second.poll() is None and members != [],
            "scope %s survived reopen inside grace" % reopen_scope
            if reopened
            else reopen_note,
        )
        for proc in (quit_foot, first, second):
            if proc.poll() is None:
                proc.terminate()

        # Bullet 3: a wrapped desktop entry launches in its scope with proof.
        # wrap only consults system entries, so install the fixture entry
        # to /usr/local/share/applications (this VM is disposable).
        system_entry = "/usr/local/share/applications/m5wrap.desktop"
        staged = os.path.join(args.artifacts, "m5wrap.desktop")
        with open(staged, "w") as handle:
            handle.write(
                "[Desktop Entry]\nType=Application\nName=M5Wrap\n"
                # tail (not sleep): the launch record needs an attributable,
                # answerable owner identity, and sleep is a trivial command
                # the identity policy marks invalid.
                "Exec=tail -f /dev/null\nNoDisplay=true\n"
            )
        made_dir = run_privileged(
            ["mkdir", "-p", "/usr/local/share/applications"], timeout=30
        )
        installed = run_privileged(["cp", staged, system_entry], timeout=30)
        rec.step(
            "desktop-entry-installed",
            made_dir.returncode == 0
            and installed.returncode == 0
            and os.path.isfile(system_entry),
            (installed.stdout + installed.stderr)[:200],
        )
        apps_dir = os.path.join(
            os.path.expanduser("~"), ".local", "share", "applications"
        )
        wrapped = _run(["taema", "desktop", "wrap", "m5wrap.desktop"], timeout=30)
        rec.step(
            "desktop-wrap",
            wrapped.returncode == 0,
            (wrapped.stdout + wrapped.stderr)[:200],
        )
        listed = _run(["taema", "desktop", "list"], timeout=30)
        rec.step(
            "desktop-list",
            listed.returncode == 0 and "m5wrap" in (listed.stdout or ""),
            (listed.stdout or "")[:200],
        )
        override = os.path.join(apps_dir, "m5wrap.desktop")
        exec_argv = None
        try:
            with open(override, encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("Exec="):
                        exec_argv = shlex.split(line[len("Exec=") :].strip())
                        break
        except OSError as error:
            exec_argv = None
            rec.step("desktop-exec", False, "unreadable override: %s" % error)
        if exec_argv:
            rec.step("desktop-exec", True, " ".join(exec_argv)[:120])
            wrap_proc = subprocess.Popen(
                exec_argv,
                env=niri_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            launched.append(wrap_proc)
            try:
                wrap_scope = wait_for_scope(wrap_proc.pid, ("app-",), timeout=60)
                why = _run(["taema", "why", str(wrap_proc.pid)], timeout=30)
                why_text = (why.stdout or "") + (why.stderr or "")
                rec.step(
                    "why-launched-by",
                    why.returncode == 0 and "launched_by=launch" in why_text,
                    "%s %s" % (wrap_scope, why_text[:160]),
                )
                rec.step(
                    "why-desktop-id",
                    why.returncode == 0 and "m5wrap" in why_text,
                    "%s %s" % (wrap_scope, why_text[:160]),
                )
            except ScenarioError as error:
                rec.step("why-launched-by", False, str(error))
                rec.step("why-desktop-id", False, "no scope: %s" % error)

        # Bullet 4: killing the agent degrades cleanly; restart re-registers.
        if agent is not None and agent.poll() is None:
            agent.terminate()
            try:
                agent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent.kill()
        time.sleep(2)
        degraded = _run(["taema", "status"], timeout=30)
        degraded_text = (degraded.stdout or "") + (degraded.stderr or "")
        rec.step(
            "agent-loss-degrades",
            degraded.returncode == 0 and "Traceback" not in degraded_text,
            degraded_text[:200],
        )
        agent, agent_log = _m5_popen_agent(niri_env, args.artifacts, "2", launch_logs)
        try:
            wait_for_audit_event(log_path, "agent_up", None, timeout=30)
            rec.step("agent-reregisters", True, "agent_up within 30 s")
        except ScenarioError as error:
            detail = str(error)
            if agent.poll() is not None:
                detail += " (agent exited rc=%s; see %s)" % (
                    agent.returncode,
                    os.path.basename(agent_log),
                )
            rec.step("agent-reregisters", False, detail)

        # Bullet 5: a scripted storm of 50 closes stays within the hourly cap.
        storm_before = len(notify_records(session))
        storm_ok = True
        for index in range(50):
            tree = spawn_gui_tree(
                os.path.join(args.artifacts, "m5-storm-%02d" % index), children=1
            )
            try:
                wait_for_scope(tree["root"], ("app-",), timeout=30)
            except ScenarioError as error:
                rec.step("storm-%02d-adopted" % index, False, str(error))
                storm_ok = False
                break
            close_root(tree["root"], timeout=15)
            for pid in tree["children"]:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        if storm_ok:
            rec.step("storm-50-closes", True, "50 roots closed")
        storm_after = len(notify_records(session))
        rec.step(
            "storm-within-cap",
            (storm_after - storm_before) <= _M5_NOTIFY_CAP,
            "notifications +%d (cap %d/hr)"
            % (storm_after - storm_before, _M5_NOTIFY_CAP),
        )
        shot = os.path.join(args.artifacts, "m5.png")
        take_screenshot(niri_env, shot)
        try:
            img = read_png(shot)
            rec.step(
                "screenshot",
                img["width"] > 0 and img["height"] > 0 and len(set(img["pixels"])) > 1,
                "%dx%d" % (img["width"], img["height"]),
            )
        except (OSError, ValueError) as error:
            rec.step("screenshot", False, "unreadable PNG: %s" % error)
        widget = "/usr/share/examples/taema/widgets/TaemaBar.qml"
        feed = _run(["taema", "bar", "--format", "json"], timeout=30)
        rec.step(
            "widget-feed-live",
            os.path.isfile(widget) and feed.returncode == 0,
            "widget installed=%s bar rc=%d" % (os.path.isfile(widget), feed.returncode),
        )

        # Bullet 6: the agent man page and autostart snippet are installed.
        rec.step(
            "agent-man-page",
            os.path.isfile("/usr/share/man/man1/taema-agent.1"),
            "taema-agent(1)",
        )
        rec.step(
            "niri-autostart",
            os.path.isfile("/usr/share/examples/taema/autostart/niri-taema-agent.kdl"),
            "niri-taema-agent.kdl",
        )
        version = _run(["taema", "--version"], timeout=30)
        rec.step(
            "version-%s" % args.current_version,
            version.returncode == 0
            and bool(args.current_version)
            and args.current_version in (version.stdout or ""),
            (version.stdout or "").strip()[:80],
        )
        try:
            shutil.copy2(
                session["notify_log"],
                os.path.join(args.artifacts, "m5-notify.jsonl"),
            )
        except OSError:
            pass
    except ScenarioError as error:
        rec.step("m5", False, str(error))
        return False
    finally:
        for proc in launched:
            try:
                if proc.poll() is None:
                    proc.terminate()
            except OSError:
                pass
        for handle in launch_logs:
            try:
                handle.close()
            except OSError:
                pass
        if agent is not None and agent.poll() is None:
            agent.terminate()
            try:
                agent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent.kill()
        if session is not None:
            stop_graphical_session(session)
        _m5_restore(snapshot)
    return all(step["ok"] for step in rec.steps)


def _eventd_db_instance(state_dir, app):
    path = os.path.join(state_dir, "state.db")
    with sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5) as db:
        return db.execute(
            "SELECT pid, start, born, exited FROM instances WHERE app = ? "
            "ORDER BY coalesce(born, 0) DESC, id DESC LIMIT 1",
            (app,),
        ).fetchone()


def _eventd_user_config_set(value):
    """Set [experimental] eventd in the user config; return an undo closure."""
    path = os.path.join(os.path.expanduser("~"), ".config", "taema", "taema.toml")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    original = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            original = handle.read()

    def render(text):
        lines = text.splitlines() if text else []
        out = []
        in_exp = False
        exp_seen = False
        done = False
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if in_exp and not done:
                    out.append("eventd = %s" % value)
                    done = True
                in_exp = stripped[1:-1].strip() == "experimental"
                exp_seen = exp_seen or in_exp
            elif in_exp and re.match(r"eventd\s*=", stripped):
                if not done:
                    out.append("eventd = %s" % value)
                    done = True
                continue
            out.append(line)
        if not done:
            if not exp_seen:
                out.append("[experimental]")
            out.append("eventd = %s" % value)
        return "\n".join(out) + "\n"

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(original))

    def undo():
        if original is None:
            try:
                os.unlink(path)
            except OSError:
                pass
        else:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(original)

    return undo


def _eventd_stage_conf(tmpdir, conf, enable):
    """Install or remove the TAEMA_EVENTD service conf override as root."""
    original = None
    if os.path.exists(conf):
        with open(conf, encoding="utf-8") as handle:
            original = handle.read()
    if enable:
        kept = [
            line
            for line in (original or "").splitlines()
            if not line.strip().startswith("TAEMA_EVENTD")
        ]
        body = "\n".join(kept)
        if body and not body.endswith("\n"):
            body += "\n"
        body += "TAEMA_EVENTD=1\n"
        staged = os.path.join(tmpdir, "taema-eventd-conf")
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write(body)
        installed = run_privileged(
            ["install", "-m", "644", "-o", "root", "-g", "root", staged, conf]
        )
        if installed.returncode != 0:
            raise ScenarioError("conf install: %s" % installed.stderr.strip()[:200])
    elif original is None:
        run_privileged(["rm", "-f", conf])
    else:
        staged = os.path.join(tmpdir, "taema-eventd-conf")
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write(original)
        installed = run_privileged(
            ["install", "-m", "644", "-o", "root", "-g", "root", staged, conf]
        )
        if installed.returncode != 0:
            raise ScenarioError("conf restore: %s" % installed.stderr.strip()[:200])
    return original


def _eventd_spawn_probe(sleep, tag):
    """Copy sleep to a unique path and run it for 0.3 s; return (path, pid, life).

    The basename stays under 15 characters: the ledger identity prefers the
    kernel comm, which truncates there, so the queried app key must match.
    """
    del tag
    dest = "/tmp/evdb%07d" % (int(time.time_ns() // 1000) % 10000000)
    shutil.copy(sleep, dest)
    os.chmod(dest, 0o755)
    start = time.monotonic()
    proc = subprocess.Popen([dest, "0.3"])
    pid = proc.pid
    proc.wait(timeout=30)
    return dest, pid, time.monotonic() - start


def _eventd_wait_row(state_dir, app, pid, timeout=150):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = _eventd_db_instance(state_dir, app)
        except sqlite3.OperationalError:
            last = None
        if (
            last is not None
            and last[0] == pid
            and last[2] is not None
            and last[3] is not None
        ):
            return last
        time.sleep(2)
    return last


def scenario_eventd(rec, args, tree_holder):
    """M6 gate (#74): a sub-second process is recorded with eventd enabled.

    Phase A runs with the stock config (forwarder off): the daemon must stay
    healthy, proving behaviour is unchanged with eventd disabled. Phase B
    enables the forwarder and the collector, restarts the service, and
    requires a 0.3 s probe to land in the instance ledger with a sub-second
    born-to-exit span. Everything is restored afterwards.
    """
    del tree_holder
    uid = os.getuid()
    sock = "/run/taema/events/%d.sock" % uid
    conf = "/etc/sv/taema/conf"
    tmpdir = tempfile.mkdtemp(prefix="taema-eventd-")
    probes = []
    undo_config = None

    def cleanup_probes():
        for path in probes:
            try:
                os.unlink(path)
            except OSError:
                pass
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except OSError:
            pass

    try:
        status, _attempts = wait_for_auto_status(timeout=60)
        rec.step(
            "daemon-ready",
            status.returncode == 0,
            (status.stdout + status.stderr)[:200],
        )
        if status.returncode != 0:
            return False

        sleep = next(
            (p for p in ("/bin/sleep", "/usr/bin/sleep") if os.path.isfile(p)),
            "",
        )
        rec.step("sleep-present", bool(sleep), sleep or "no sleep binary")
        if not sleep:
            return False

        # Phase A: stock config, forwarder off.
        rec.step("forwarder-off-by-default", not os.path.exists(sock), sock)
        dest_a, _pid_a, life_a = _eventd_spawn_probe(sleep, "evdprobe-a")
        probes.append(dest_a)
        healthy_a = _run(["/usr/bin/taema", "status"], timeout=30)
        rec.step(
            "disabled-healthy",
            healthy_a.returncode == 0,
            "probe_life=%.2fs rc=%d" % (life_a, healthy_a.returncode),
        )

        # Phase B: enable forwarder and collector, restart the service.
        # The forwarder ships in the optional taema-eventd subpackage,
        # which provisioning deliberately leaves out (off by default).
        installed = run_privileged(
            [
                "xbps-install",
                "-y",
                "-i",
                "--repository=/tmp/taema-vm/repo",
                "taema-eventd",
            ]
        )
        rec.step(
            "forwarder-installed",
            installed.returncode == 0,
            (installed.stdout + installed.stderr).strip()[:200],
        )
        if installed.returncode != 0:
            return False
        undo_config = _eventd_user_config_set("true")
        _eventd_stage_conf(tmpdir, conf, True)
        restarted = run_privileged(["sv", "restart", "/var/service/taema"])
        rec.step(
            "service-restart",
            restarted.returncode == 0,
            (restarted.stdout + restarted.stderr).strip()[:200],
        )
        status_b, _ = wait_for_auto_status(timeout=90)
        rec.step(
            "daemon-ready-eventd",
            status_b.returncode == 0,
            (status_b.stdout + status_b.stderr)[:200],
        )
        if status_b.returncode != 0:
            return False

        # One throwaway ensures the forwarder created our listener.
        dest_w, _, _ = _eventd_spawn_probe(sleep, "evdprobe-warm")
        probes.append(dest_w)
        sock_found = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if os.path.exists(sock):
                sock_found = True
                break
            time.sleep(1)
        detail = sock
        if sock_found:
            try:
                st = os.stat(sock)
                detail = "%s mode=%04o uid=%d" % (
                    sock,
                    st.st_mode & 0o777,
                    st.st_uid,
                )
                sock_found = (st.st_mode & 0o777) == 0o600 and st.st_uid == uid
            except OSError as error:
                detail = str(error)
                sock_found = False
        rec.step("socket-created-0600", sock_found, detail)
        if not sock_found:
            return False

        dest_b, pid_b, life_b = _eventd_spawn_probe(sleep, "evdprobe-b")
        probes.append(dest_b)
        app_b = "exe:%s" % os.path.basename(dest_b)
        row = _eventd_wait_row(args.state_dir, app_b, pid_b, timeout=150)
        if row is None:
            rec.step("subsecond-recorded", False, "no ledger row for %s" % app_b)
            return False
        span = row[3] - row[2]
        rec.step(
            "subsecond-recorded",
            row[0] == pid_b and span < 1.0,
            "app=%s pid=%d life=%.2fs span=%.3fs" % (app_b, row[0], life_b, span),
        )
        return all(step["ok"] for step in rec.steps)
    except ScenarioError as error:
        rec.step("fatal", False, str(error))
        return False
    finally:
        try:
            _eventd_stage_conf(tmpdir, conf, False)
        except ScenarioError as error:
            rec.step("conf-restore", False, str(error))
        if undo_config is not None:
            undo_config()
        removed = run_privileged(["xbps-remove", "-y", "taema-eventd"])
        rec.step(
            "forwarder-removed",
            removed.returncode == 0,
            (removed.stdout + removed.stderr).strip()[:200],
        )
        run_privileged(["sv", "restart", "/var/service/taema"])
        status_c, _ = wait_for_auto_status(timeout=90)
        rec.step(
            "restored-healthy",
            status_c.returncode == 0,
            (status_c.stdout + status_c.stderr)[:200],
        )
        cleanup_probes()


SCENARIOS = {
    "smoke": scenario_smoke,
    "eventd": scenario_eventd,
    "m0": scenario_m0,
    "setup": scenario_setup,
    "m1": scenario_m1,
    "m2": scenario_m2,
    "m3": scenario_m3,
    "m4": scenario_m4,
    "m5": scenario_m5,
    "upgrade": scenario_upgrade,
    "remove": scenario_remove,
    "graphical": scenario_graphical,
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
