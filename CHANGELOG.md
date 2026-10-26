# Unreleased

## Behaviour changes

### M4 release gate: 0.6.0 readiness

`taema status` answers in 43 ms p50 over 100 runs (gate: under 50 ms):
bare status probes the default daemon socket before loading config,
the daemon does no file I/O on the request path, and the status reply
carries a `mem_enabled` flag so the fast path honours `mem.enabled`.
Every read command's `--json` output validates against its schema.
`taema(1)` and `taema.toml(5)` ship and install to man1/man5, and shell
completions install and load for bash, zsh, and fish. A new `m4` VM
scenario gates releases: mode switch without sudo in under a second,
invalid config keeps the previous config and reports `file:line`.

### Status bar feed and quickshell widget

`taema bar --format waybar|i3bar|json|plain [--follow]` writes one
line per state change from subscriptions without polling:
`tæma ⟲2 ❄1 ↓3 9.3G` with a tooltip and a class of ok, review,
pressure, hold, or error. Status now also reports deprioritized scope
count and bytes freed today. `widgets/taema-bar/` holds a quickshell
widget consuming the json stream: mode, profile, reviews, frozen
count, freed today, and pressure, with a popup for answering reviews,
hold/snooze, profile switching, starting the agent, and opening the
dashboard, all through the existing CLI.

### Desktop entry wrapping

`taema desktop wrap NAME.desktop` writes a user-level override whose
Exec runs the original command under `taema launch`, recording the
source hash in the override marker; `unwrap NAME|--all` and `list`
reverse and inspect. System entries are only read, never edited.
`doctor` warns when a package update changes a source behind its
wrapper (rewrap to fix). Wrapping is gated behind
`[experimental] launch_wrap`.

### Launch-time scoping

`taema launch [--app NAME] [--unit UNIT] [--bind] -- CMD…` reserves an
app scope through `launch_prepare`, moves itself into it, registers the
instance, and execs the command, so containment and provenance begin
before the app's first instruction. A reservation expires if the pid
doesn't arrive within 5 seconds and the empty leaf is removed. Launches
route through the session agent when one is up (no sudo; the daemon
attaches) and otherwise use the validated helper `move`. `why` shows
`launched_by=launch` and the requested app name as the desktop id.

### Windowless lifecycle

App scopes that lose their last window are tracked, and once they stay
windowless past `agent.windowless_grace` (30 seconds) the daemon stops
them under the same pair authority as GC, every 30 seconds. Only windows
reset the clock — undo never does — and opted-out units, frozen scopes,
and anything the ladder refuses are left alone. Without a feeding window
backend nothing is tracked or stopped: windowlessness is unprovable and
fail-closed. GC stops and session end now carry the unit's
`requires_window` flag (default true) and the scope's live window state,
so the ladder keeps scopes that still have windows.

### Niri window feed

The session agent streams window state from niri over `$NIRI_SOCKET`
(snapshot plus event stream, capped at 50 events per second) and forwards
open, change, close, and focus facts to the daemon, which validates window
pids and re-checks start times against reuse. Window titles stay out unless
`agent.store_titles` is set. Each mapped pid resolves to its scope and app
instance, and the window's app id becomes the instance's desktop id and
display name. The focused scope is foreground — never frozen, reclaimed no
further than page cache — windowed scopes are interactive and exempt from
deprioritization, and focus boost applies only in the focus profile. Any
scope with an open window refuses freezing, and opening or focusing a
window in a frozen scope thaws it at once. `ls`, `top`, `tree`, and the
dashboard show window state.

### Actionable review notifications

Each new answerable review produces one desktop notification with actions
and wait — "Stop when it closes", "Keep", "Never", and "Details" — through
the default notify-send backend. The notification carries the review's
nonce; the agent reports the click with `notify_result` and the daemon
answers through exactly the `taema answer` path, with the same rate limits,
audit trail, and expiry. Clicking after expiry or on an answered review
shows a short "question expired" toast with Details. Review waits slice at
60 seconds with heartbeat keepalives so long waits never mark the agent
down. Without an agent or an action-capable server, reviews wait for the
shell hint and `taema review` as before.

### Notification policy, toasts, and countdowns

The agent polls a per-session notification queue (`notify_poll`) and shows
jobs through the configured backend subject to policy: closes batch over 60
seconds and cap at 6 per hour, closes under 200 MB are skipped unless their
pattern repeats 3 times, quiet hours (22:00–08:00), the game and quiet
profiles, and `taema mute APP`/`unmute` suppress per-app noise. Automatic
stops and freezes queue undo toasts ("Freed 812 MB · Undo"); a toast undo
also records a full regret. Learned stops that were not explicitly answered
wait out a 30-second countdown with Keep and Stop now while an
action-capable agent is up — Keep records keep evidence with a 7-day
suspension, a veto cancels the countdown, and silence stops when the
deadline fires. Guard runs that reclaim memory, error notices (at most once
a day per kind, including store recovery), and an optional daily digest
round out the set. Text stays plain unless the server advertises markup.

### Notification backends

One `Notifier` contract (`taema.notify`) with three backends and no new
mandatory dependencies: `notify-send` stays the default (actions via
`--action=NAME=Text` with `--wait`), an opt-in jeepney D-Bus backend sends,
closes, and listens for action/close signals while accepting signals only
from the bus name that owns the notification service, and a `gdbus` backend
sends one-way toasts when libnotify is missing. `notify.backend = auto`
prefers notify-send, falls back to gdbus, and degrades to a null backend
that keeps CLI reviews working; `doctor` reports the active backend and the
server's capabilities.

### Disposable graphical test session

The VM harness gains a `graphical` scenario: a disposable headless session
(private dbus-daemon, `weston --backend=headless` with a deterministic
weston.ini, mako) under a test-owned `XDG_RUNTIME_DIR`. The scenario asserts
the Wayland socket appears, sends a `notify-send` notification, captures the
headless output with `grim` into the artifacts directory, and verifies the
PNG with a stdlib-only reader plus a capture-diff helper (`read_png`,
`image_diff_fraction`). Guest images install `weston mako grim libnotify
mesa-dri`.

### Rust root helper with differential parity

The privileged `taema-attach` helper is rewritten in Rust (`rust/attach`,
only libc/serde/serde_json/toml per ADR-3, vendored for offline builds) with
an identical command line and validation. A differential corpus
(`tests/test_attach_parity.py`, ~90 cases plus a refusal catalog) sends the
same requests to both helpers and compares exit codes, output, and produced
files byte for byte; the only intentional differences are inputs where Python
crashes with a traceback, which Rust refuses cleanly with the same exit code.
The install ships a `taema-attach` wrapper preferring the Rust binary with
the Python helper as fallback (same sudoers rule, unchanged service), and CI
gates the workspace on fmt, clippy, tests, audit, and deny. `WITHOUT_RUST=1`
skips the Rust build, the corpus, and the Rust install.

### Session agent lifecycle

`taema agent` runs once per session under a lock, joins the protected `agent`
leaf (asking the daemon to attach it only when a direct move fails),
registers its capabilities, and beats every 30 seconds with exponential
reconnect backoff capped at 30 seconds. The daemon accepts `register_agent`
and `agent_beat` only from the same uid, marks agents down after 3 missed
beats with `agent_up`/`agent_down` audit events, and refuses stale facts so
it decides on process data only. The agent exits when the compositor socket
goes away. The agent leaf is never adopted, frozen, thawed, deprioritized,
reclaimed, undone, stopped, or removed. `status` and `doctor` show agent
state, and example niri and XDG autostart entries ship under
`examples/autostart/`.

### Terminal dashboard

`taema dash` shows scopes, learned pairs and signatures, memory and budget,
open reviews, and recent events in one curses screen refreshed every 2 seconds
over the daemon subscription stream. Movement, why, stop (with a confirmation
showing veto, edge, and memory facts), veto, undo, review answers, filters,
and governor keys (reclaim, freeze/thaw, profile, GC dry run) all dispatch
through the same CLI paths, so refusals match the CLI exactly. `dash --once`
prints a deterministic snapshot, `dash --json` prints the view model, and
without curses `dash` falls back to `watch --plain`.

### Live process top and scope tree

`taema top` shows live CPU/MEM/RSS/threads per scope-grouped process with
one-shot piped output and `--json` (`taema.top.v1`) plus a looping terminal
mode (`--count`, `--interval`, keypress to quit). `taema tree` prints a
scope-grouped process tree with zombie reaper annotations. Both clip to
terminal width unless `--wide`.

### Unit authoring tools

`taema unit draft NAME --from PID` generates a unit file from a running
process. `taema unit lint` and `taema unit dry-run` validate units and show
matches without consequences. The `unit_test` socket command evaluates match
logic remotely. New and changed units reload without a restart.

### Automatic profile switching

`[profile.auto]` rules switch profiles on battery power, running processes,
and time windows while `profile.active` is `auto`. A manual `taema profile`
choice wins until `taema profile auto`. Selections reuse the config-reload
path, log `profile_changed`, and show in status.

### History, reports, and recent actions

`taema history APP|SCOPE [--since]` shows a decision-id timeline of launches,
closes, reviews, freezes, reclaims, stops, and regrets. `taema recent` lists
the last 50 automatic actions with freed bytes and restore possibility.
`taema report --day|--week|--month [--json]` aggregates freed memory by
reclaim and stop, stops, undos, regrets, leftover makers, frozen time,
guard events, and review outcomes from indexed queries and daily rollups.

### Backup, learning transfer, and reset

`taema backup` writes a tarball with an online database copy, user config,
drop-ins, and user units; `taema restore-backup` restores it after
confirmation. `taema learn export` defaults to the versioned `learn-v1`
format with `--redact`, and `taema learn import` merges or replaces answers
after showing a diff. Imported answers start probationary and never allow
SIGKILL. `taema reset --learning|--vetoes|--history|--all` always backs up
first.

### Legacy module paths removed

The one-release compatibility shims are gone. Import the new package paths:
`taema.model.authorization`, `taema.core.cgroup`, `taema.governor.engine`,
`taema.core.process`, `taema.store.knowledge`, `taema.core.lineage`,
`taema.config.policy`, `taema.cli.commands`, and `taema.daemon.service`.
The `taema.cli` and `taema.daemon` packages no longer re-export implementation
names.

# 0.5.0

## Resource governor

### Memory budget and pressure response

Per-scope memory accounting now supports class reservations, conservative soft limits,
bounded page-cache and anonymous reclaim, and pressure-triggered reclaim and freezing.
The pressure guard coordinates its available-memory floor with earlyoom and preserves leftovers
as preferred external OOM victims. Memory documentation and `taema doctor` now cover the
kernel controls required for these features.

The disposable VM harness adds the `m3` release scenario for bounded low-memory pressure,
HTTP wake-on-connect, QMP/save-hook safety, and the ten-minute idle footprint gate.

# 0.4.0

## Behaviour changes

### SQLite state and provenance learning

Learning state now lives in a transactional SQLite database, with concurrent read-only CLI
access, retained decision provenance, and an anonymized replay fixture. Upgrading from 0.3.0
imports valid pair decisions, quarantines invalid legacy owners for review, and keeps a
private backup of the original JSON state; migration does not stop processes. Survivor
signatures carry explicit answers across identical relaunched survivor sets, while changed
sets require a separate review. Automatic-stop outcomes, regret, and undo update durable
pair and signature decisions.

The package includes the SQLite schema and migration guides plus the `taema-learning(7)`
manual page.

### inspect and reset learned state

`taema learn show`, `apps`, `pairs`, and `signatures` display learned decisions, evidence, and
outcomes in human-readable or JSON form. `taema forget --all APP` clears that app's learned
records while preserving its vetoes. Versioned v2 `forget` feedback now accepts the optional
boolean `all` field to request this full reset.

### undo retained automatic actions and opt-in restore

`taema undo [ID]` now reverses retained containment, priority, freeze, and stop actions. Stop undo
adds keep evidence and a veto, clears pending stop state, and suspends automatic authority for the
regret window. With `[learn].remember_argv = true`, a stopped root's argv and cwd can be relaunched
once in a fresh scope; the relaunch receives only the documented environment allowlist and no
inherited stdin. The option remains off by default.

# 0.3.0

## Behaviour changes

### vetoes cover every target and action

`taema do-not-kill` can protect process instances, scopes, pairs, signatures, app identities,
owners, units, cgroup subtrees, and executable paths, with explicit precedence, reasons, and
expiry. Vetoes also block actions while the daemon is down; `taema stop --force-veto` remains the
single confirmed and audited override.

### adopt now contains and asks

In `adopt`, a GUI app's surviving processes now move into a dedicated `leftover/` scope
when its root exits, and tæma queues a review so you can decide what should happen next.
An unanswered review keeps the leftover. `taema run --bind` honors the explicit owner
binding by stopping its scope when the command exits, with the same safety and veto checks
as other stops. In `auto`, unlearned leftovers are kept for review, while eligible idle
runtime scopes whose configured runtime directory disappeared can be collected after the
usual safety checks. `observe` continues to report would-actions without moving or stopping
processes.

### configuration reloads live

Configuration now layers system and user TOML drop-ins in lexical order, with protected
entries remaining union-only. `taema config` edits only its managed `50-cli.toml` drop-in,
validates changes before reload, and preserves the last good daemon configuration after an
invalid edit. The daemon also reloads on SIGHUP and config or unit file changes.

### runtime modes and manual profiles

`taema mode` changes lifecycle policy in the managed drop-in and reports changed authorization
capabilities. `taema profile` applies built-in or user-defined overlays without changing
learned feedback; status reports the active profile and reason, and mode/profile changes are
recorded in the audit log.
