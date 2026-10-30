taema(1)

# NAME

taema - dependency-aware, self-managing cgroup v2 process scopes

# SYNOPSIS

*taema* [_GLOBAL_] _COMMAND_ [_ARGS_]

# DESCRIPTION

Tæma adopts processes into cgroup scopes, learns which leftovers are safe to
stop, and stops them under pair authority. A per-user daemon (*taema daemon*)
owns lifecycle passes; the CLI reads state and sends requests over a Unix
socket.

Lifecycle modes, weakest first: *observe*, *adopt*, *enforce*, *auto*.
*taema mode MODE* switches the running daemon without sudo.

# COMMANDS

## Scopes and launching

*taema run [--bind] [--owner PID] [--join] NAME CMD...*
	Run CMD inside scope-NAME, stopping the scope when the owner exits.

*taema launch [--app NAME] [--unit UNIT] [--bind] -- CMD...*
	Reserve an app scope, attach, register provenance, and exec CMD.

*taema kill NAME*
	Stop a scope; shared members are moved aside, not killed.

*taema ls*
	List scopes.

*taema top*
	Live process table sorted by CPU, memory, then PID.

*taema tree*
	Process trees grouped under scope headers.

## Inspecting and teaching

*taema status*
	Show daemon and policy status.

*taema explain [TARGET]*
	Explain a process, scope, app, pair, or latest decision. *why* is an alias.

*taema review [--interactive]*
	List pending reviews or answer them interactively.

*taema answer ID CHOICE*
	Answer a review with stop, keep, standalone, or never.

*taema teach OWNER SURVIVOR CHOICE*
	Record an explicit pair answer without waiting for a review.

*taema learn show|apps|pairs|signatures*
	Inspect learned state.

*taema help TOPIC*
	Show a topic: modes, learning, veto, ladder, memory, units, agent,
	profiles, privacy, safety.

*taema history TARGET*
	Show the timeline of one app or scope.

*taema recent*
	List the latest automatic actions.

*taema report --day|--week|--month*
	Summarize cleanup activity.

*taema events [--since SEQ] [--follow]*
	Query or follow the event log.

*taema dash*
	Curses dashboard; --once prints one snapshot.

*taema prompt*
	Print the cached prompt summary without contacting the daemon.

*taema bar --format waybar|i3bar|json|plain [--follow]*
	Stream bar state, one line per state change.

## Acting and overruling

*taema keep TARGET*
	Keep an executable or owner/survivor pair.

*taema do-not-kill TARGET*
	Veto a target or the latest automatic stop.

*taema forget TARGET*
	Forget an executable or veto.

*taema undo [ID]*
	Reverse a retained automatic action.

*taema restore ID*
	Relaunch a stopped root by decision id.

*taema mute APP*
	Mute an app's notifications.

*taema hold [TARGET]*
	Pause actions without changing mode.

*taema resume [TARGET]*
	Resume actions.

*taema snooze DURATION|until TIME*
	Hold all actions for a duration or until a local time.

*taema freeze SCOPE*
	Manually freeze a safe leftover scope.

*taema thaw [SCOPE|--all]*
	Thaw managed scopes.

*taema gc [--dry-run] [--memory]*
	Show or collect idle scopes.

*taema adopt*
	Adopt eligible processes into scopes.

## Configuration and units

*taema mode MODE*
	Switch lifecycle mode without restarting the daemon.

*taema profile NAME*
	Select a configuration profile or return to automatic selection.

*taema config*
	Show or edit layered configuration.

*taema reload*
	Reload configuration and units in the daemon.

*taema unit new|draft|test|dry-run|lint*
	Unit authoring tools.

## Desktop and session

*taema desktop wrap|unwrap|list*
	Wrap launcher entries with taema launch.

*taema agent*
	Relay this session's desktop facts to the daemon.

*taema watch*
	Print live changes as plain lines.

## Maintenance

*taema doctor*
	Check system support and report setup problems.

*taema bug-report [--to FILE]*
	Write a sanitized support bundle: versions, doctor JSON, redacted config,
	unit names, self-metrics, and the last 500 events.

*taema backup [--to FILE]*
	Write a tarball with the database, user config, and user units.

*taema restore-backup FILE*
	Restore state, config, and units from a backup tarball.

*taema reset --learning|--vetoes|--history|--all*
	Clear state after a backup.

*taema memory [top|pressure|budget|watch|reclaim]*
	Host and per-scope memory accounting.

*taema daemon*
	Run the per-user daemon.

# OPTIONS

Global options accepted before or after the command:
*--json*, *--jsonl*, *--plain*, *--wide*, *--no-color*, *--quiet*, *--yes*,
*--socket* _PATH_, *--config* _PATH_, *--verbose_.
Read commands emit schema-tagged JSON with *--json*.

# FILES

_/etc/taema/taema.toml_
	System configuration.

_~/.config/taema/taema.toml_
	User configuration; drop-ins live in _taema.d_.

_/etc/taema/units, ~/.config/taema/units_
	Unit files.

_~/.config/taema/taema.toml_
	User configuration file.

# EXAMPLES

*taema run editor code .*
	Start the editor inside scope-editor.

*taema launch --app firefox -- firefox*
	Start firefox inside its own reserved app scope.

*taema why scope-firefox*
	Explain what tæma would do to the scope and why.

# SEE ALSO

*taema.toml*(5), *taema.unit*(5), *taema-learning*(7)
