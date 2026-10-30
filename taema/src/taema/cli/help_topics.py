"""Topic help for `taema help TOPIC` (issue #83).

Each topic is plain text: a short paragraph plus the commands that matter.
Kept stdlib-only and import-light so `--help` stays fast.
"""

TOPICS = {
    "modes": """MODES
Tæma runs in one lifecycle mode, weakest first: observe, adopt, enforce, auto.
Observe learns and explains but stops nothing. Adopt scopes apps and asks
before stopping leftovers. Enforce stops with learned authority. Auto also
adopts windowless helpers. Switch live: taema mode MODE. See: status, hold.
""",
    "learning": """LEARNING
Tæma learns owner-to-leftover pairs, survivor signatures, and app identities.
Reviews ask once; answers persist. Inspect: taema learn show, taema why TARGET.
Teach: taema teach OWNER LEFTOVER stop|keep|standalone. Export: taema learn
export --redact. Unlearn: taema forget. See: review, answer, undo.
""",
    "veto": """VETO
A veto keeps a target alive: scope, app, pid, pair, or signature. Create:
taema do-not-kill TARGET [--for 2h] [--reason TEXT]. List via taema status.
Remove: taema forget --veto TARGET. Vetoes beat learning, dependencies, and
holds. An audited override needs --force-veto on kill.
""",
    "ladder": """LADDER
Stop ladder, weakest first: skip protected, share what outsiders use, freeze
idle leftovers, SIGTERM then wait, SIGKILL what remains, GC empty scopes.
Dry-run any step: taema kill --dry-run, taema gc --dry-run, taema unit test.
Explain a decision: taema why TARGET. Undo: taema undo.
""",
    "memory": """MEMORY
Memory accounting is per-scope: current, peak, reclaimable, PSI pressure.
Commands: taema memory, taema memory top, taema memory pressure,
taema memory budget, taema memory reclaim SCOPE, taema memory watch.
Configure in [mem]: enabled, budget, fraction, floor, reclaim gates,
oom_policy. Units set [mem] class and background.
""",
    "units": """UNITS
Units match apps and scopes: [unit] name/kind, [match] exe/comm/cmdline,
[kill] graceful/keep/hook, [gc], [mem], [window], [[children]]. Author:
taema unit new|draft, check: taema unit lint|test|dry-run, manage:
taema unit list|enable|disable|install. Files: /etc/taema/units,
~/.config/taema/units. See: taema.unit(5).
""",
    "agent": """AGENT
The session agent relays desktop facts (windows, focus, launches,
notification actions) to the daemon. Run per graphical session:
taema agent. Without it the daemon decides on process data only. Check:
taema doctor, taema status. See: taema-agent(1).
""",
    "profiles": """PROFILES
Profiles switch config as a set: default, focus, battery, game, quiet,
server, or auto selection. Select: taema profile NAME, back to auto:
taema profile auto. Inspect: taema config show, taema status. Override in
[profile] and taema.toml(5).
""",
    "privacy": """PRIVACY
Tæma stores state under ~/.local/state/taema, mode 0600. Titles, argv, cwd,
and environment values are never required: taema learn export --redact
strips them, and taema bug-report ships only the redacted bundle. Config
layers in taema.toml(5); drop-ins cannot unprotect [protected] entries.
""",
    "safety": """SAFETY
Tæma touches only your own processes, never session infrastructure
(compositor, audio, D-Bus) or protected comms. Stops move shared members
aside instead of killing them. Check first: taema doctor, taema doctor
--fix. Every destructive command has --dry-run; undo reverses the last
automatic action.
""",
}

ORDER = (
    "modes",
    "learning",
    "veto",
    "ladder",
    "memory",
    "units",
    "agent",
    "profiles",
    "privacy",
    "safety",
)


def names():
    return list(ORDER)


def text(topic):
    key = (topic or "").lower()
    return TOPICS.get(key)


def listing():
    lines = ["Topics:"]
    for name in ORDER:
        first = TOPICS[name].splitlines()[1] if len(TOPICS[name].splitlines()) > 1 else ""
        lines.append("  %-10s %s" % (name, first[:72]))
    lines.append("Run `taema help TOPIC` for details.")
    return "\n".join(lines) + "\n"
