"""Session agent: relay desktop-session facts to the daemon.

The agent has no authority: it holds a per-session lock, joins the protected
agent leaf, registers its capabilities, and beats every 30 seconds. The daemon
marks it down after 3 missed beats and refuses stale facts. The agent exits
when the session's compositor socket goes away.
"""

import os
import time

BEAT_S = 30
MAX_MISSED = 3
BACKOFF_CAP_S = 30
POLL_S = 5


def backoff(attempt):
    """Exponential reconnect delay in seconds, capped at 30."""
    return min(BACKOFF_CAP_S, 2 ** max(0, attempt))


def session_key():
    """The session this agent serves; one agent per session."""
    return os.environ.get("XDG_SESSION_ID") or "default"


def lock_path(state_dir, session):
    return os.path.join(state_dir, "agent-%s.lock" % session)


def hold_lock(path):
    """Take the session lock; None when another agent holds it."""
    import fcntl

    handle = open(path, "w")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def release_lock(handle):
    if handle is not None:
        handle.close()


def compositor_socket():
    """The session's compositor socket, or None outside a graphical session."""
    display = os.environ.get("WAYLAND_DISPLAY")
    if display:
        if os.path.isabs(display):
            return display
        runtime = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
        return os.path.join(runtime, display)
    return os.environ.get("NIRI_SOCKET")


def compositor_live(path):
    return bool(path) and os.path.exists(path)


def detect_capabilities():
    """Honest capability list from sockets the agent can actually see."""
    capabilities = ["heartbeat"]
    display = os.environ.get("WAYLAND_DISPLAY")
    if display and compositor_live(compositor_socket()):
        capabilities.append("wayland")
    niri = os.environ.get("NIRI_SOCKET")
    if niri and os.path.exists(niri):
        capabilities.append("niri")
    return capabilities


def ensure_leaf(pid, ask):
    """Join the protected agent leaf, asking the daemon to attach when needed."""
    from .core import cgroup
    from .config import policy

    try:
        dest = cgroup.mkleaf(policy.AGENT_LEAF)
        cgroup.move(pid, dest)
        return True
    except OSError:
        pass
    reply = ask({"cmd": "attach", "scope": policy.AGENT_LEAF, "pids": [pid]})
    return isinstance(reply, dict) and reply.get("ok") is True


class Agent:
    """One session's relay: register once, then beat until told to stop."""

    def __init__(self, cfg, session=None, backend=None):
        from . import notify as notify_mod
        from .notifier import JobHandler

        self.cfg = cfg
        self.session = session or session_key()
        self.pid = os.getpid()
        self.compositor = compositor_socket()
        if backend is None:
            try:
                backend = notify_mod.select_backend(
                    (cfg.get("notify", {}) or {}).get("backend", "auto")
                )
            except notify_mod.NotifyError:
                backend = notify_mod.NullNotifier()
        self.backend = backend
        self.handler = JobHandler(cfg, backend)
        self.cursor = 0
        self.capabilities = detect_capabilities()
        if backend.name != "null":
            self.capabilities.append("notify")
            if "actions" in backend.capabilities():
                self.capabilities.append("notify-actions")

    def _ask(self, message):
        from .cli.commands import ask

        return ask(self.cfg, message)

    def connect(self):
        """Register with the daemon; True on acceptance."""
        reply = self._ask(
            {
                "cmd": "register_agent",
                "session": self.session,
                "pid": self.pid,
                "capabilities": self.capabilities,
                "compositor": self.compositor or "",
            }
        )
        return isinstance(reply, dict) and reply.get("ok") is True

    def beat(self, facts=None):
        """One heartbeat; True when the daemon accepted it."""
        message = {"cmd": "agent_beat", "session": self.session, "pid": self.pid}
        if facts is not None:
            message["facts"] = facts
        reply = self._ask(message)
        return isinstance(reply, dict) and reply.get("ok") is True

    def poll_once(self):
        """Fetch notification jobs, show them, and report outcomes."""
        reply = self._ask(
            {
                "cmd": "notify_poll",
                "session": self.session,
                "pid": self.pid,
                "since_seq": self.cursor,
            }
        )
        if not isinstance(reply, dict) or reply.get("error"):
            return
        jobs = reply.get("jobs", [])
        if not isinstance(jobs, list):
            return
        self.handler.handle(
            [job for job in jobs if isinstance(job, dict)],
            reply.get("profile", "auto"),
            reply.get("mutes", []),
            self._report,
            keepalive=self._keepalive,
        )
        for job in jobs:
            seq = job.get("seq") if isinstance(job, dict) else None
            if isinstance(seq, int) and seq > self.cursor:
                self.cursor = seq

    def _report(self, payload):
        return self._ask(
            {
                "cmd": "notify_result",
                "session": self.session,
                "pid": self.pid,
                **payload,
            }
        )

    def _keepalive(self):
        """Beat between review wait slices; False abandons the wait."""
        if not compositor_live(self.compositor):
            return False
        return bool(self.beat())

    def run(self, sleep=time.sleep, max_beats=None, clock=time.monotonic):
        """Beat until the compositor goes away; back off while disconnected.

        Connected beats are followed by 5-second notification polls until
        the next beat is due; disconnected beats keep the plain backoff.
        """
        attempt = 0
        beats = 0
        while True:
            if not compositor_live(self.compositor):
                return "compositor-gone"
            if self.beat():
                attempt = 0
                beats += 1
                if max_beats is not None and beats >= max_beats:
                    return "stopped"
                reason = self._sleep_connected(sleep, clock)
                if reason is not None:
                    return reason
            else:
                delay = backoff(attempt)
                attempt += 1
                sleep(delay)
                beats += 1
                if max_beats is not None and beats >= max_beats:
                    return "stopped"

    def _sleep_connected(self, sleep, clock):
        """Poll every few seconds until the next beat; None when due."""
        deadline = clock() + BEAT_S
        while True:
            if not compositor_live(self.compositor):
                return "compositor-gone"
            self.poll_once()
            remaining = deadline - clock()
            if remaining <= 0:
                return None
            sleep(min(POLL_S, remaining))
