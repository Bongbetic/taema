taema-agent(1)

# NAME

taema agent - relay this session's desktop facts to the tæma daemon

# SYNOPSIS

*taema agent*

# DESCRIPTION

The session agent runs once per graphical session and relays desktop facts
to the per-user daemon, which keeps every decision. The agent itself decides
nothing: it streams window open, change, close, and focus facts from the
compositor, reports notification actions and launch requests, and polls the
daemon's notification queue through the configured backend.

Only one agent runs per session, held under a lock. On start it joins the
protected *agent* leaf (asking the daemon to attach it only when a direct move
fails), registers its capabilities, and beats every 30 seconds with
exponential reconnect backoff capped at 30 seconds. The daemon accepts
*register_agent* and *agent_beat* only from the same uid, marks agents down
after 3 missed beats with *agent_up* and *agent_down* audit events, and refuses
stale facts so it decides on process data only. The agent exits when the
compositor socket goes away. The agent leaf is never adopted, frozen,
deprioritized, reclaimed, undone, stopped, or removed.

Without an agent, or without an action-capable notification server, reviews
wait for the shell hint and *taema review*. Killing the agent degrades the
daemon to process-only mode without errors, and a restarted agent re-registers
within 30 seconds.

# SESSION SETUP

The agent needs a Wayland compositor socket. For niri, start it from the
compositor configuration:

	spawn-at-startup "taema" "agent"

An example snippet ships under
_/usr/share/examples/taema/autostart/niri-taema-agent.kdl_, with an XDG
autostart entry _taema-agent.desktop_ alongside it.

# FILES

_/usr/share/examples/taema/autostart/niri-taema-agent.kdl_
	Example niri *spawn-at-startup* entry.

_/usr/share/examples/taema/autostart/taema-agent.desktop_
	XDG autostart entry for desktop environments that honour it.

# SEE ALSO

*taema*(1), *taema.toml*(5)
