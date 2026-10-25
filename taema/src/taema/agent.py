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

    def __init__(self, cfg, session=None):
        self.cfg = cfg
        self.session = session or session_key()
        self.pid = os.getpid()
        self.compositor = compositor_socket()
        self.capabilities = detect_capabilities()

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

    def run(self, sleep=time.sleep, max_beats=None):
        """Beat until the compositor goes away; back off while disconnected."""
        attempt = 0
        while True:
            if not compositor_live(self.compositor):
                return "compositor-gone"
            if self.beat():
                attempt = 0
                delay = BEAT_S
            else:
                delay = backoff(attempt)
                attempt += 1
            sleep(delay)
            if max_beats is not None:
                max_beats -= 1
                if max_beats <= 0:
                    return "stopped"
