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
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from unittest import mock

CGROOT = os.environ.get("TAEMA_CGROOT", "/sys/fs/cgroup")
PROCROOT = os.environ.get("TAEMA_PROCROOT", "/proc")

#: The fake application root: forks out of the SSH session, spawns children,
#: records the tree, and idles. The final process is deliberately not a
#: session leader; its session-leader parent stays alive long enough for the
#: lineage scanner to see the parent relationship and classify it separately.
APP_ROOT = """\
import json, os, signal, subprocess, sys, time

def main():
    n = int(sys.argv[1])
    workdir = sys.argv[2]
    child_argv = json.loads(sys.argv[3]) if len(sys.argv) > 3 else ["/bin/sleep", "3600"]

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
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        signal.pause()

main()
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


def spawn_gui_tree(workdir, children=2, timeout=10, child_argv=None):
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
    if child_argv is not None:
        argv.append(json.dumps([str(arg) for arg in child_argv]))
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


def scenario_upgrade(rec, args, tree_holder):
    """Install the previous release, then upgrade back to the working tree."""
    prevdir = os.path.dirname(args.previous)
    index = run_privileged(["xbps-rindex", "-f", "-a", args.previous])
    rec.step(
        "index-previous", index.returncode == 0, (index.stdout + index.stderr)[-600:]
    )
    down = run_privileged(
        ["xbps-install", "-y", "-i", "--repository", prevdir, "taema"]
    )
    rec.step(
        "install-previous", down.returncode == 0, (down.stdout + down.stderr)[-600:]
    )

    ver = _run(["/usr/bin/taema", "--version"])
    rec.step(
        "previous-version",
        args.previous_version in (ver.stdout + ver.stderr),
        (ver.stdout + ver.stderr).strip()[:200],
    )

    up = run_privileged(
        ["xbps-install", "-y", "-i", "--repository", args.package_dir, "taema"]
    )
    rec.step("install-current", up.returncode == 0, (up.stdout + up.stderr)[-600:])

    ver = _run(["/usr/bin/taema", "--version"])
    rec.step(
        "current-version",
        args.current_version in (ver.stdout + ver.stderr),
        (ver.stdout + ver.stderr).strip()[:200],
    )

    svc = run_privileged(["sv", "status", "/var/service/taema"])
    rec.step("service-up", svc.returncode == 0, (svc.stdout + svc.stderr).strip()[:300])

    status = _run(["/usr/bin/taema", "status"], timeout=30)
    rec.step(
        "daemon-status", status.returncode == 0, (status.stdout or status.stderr)[:300]
    )
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
        "--package-dir", help="local repository with the current package (upgrade)"
    )
    common.add_argument("--previous", help="path to the previous release .xbps")
    common.add_argument("--previous-version", help="expected previous version")
    common.add_argument("--current-version", help="expected current version")
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
