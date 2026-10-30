taema.unit(5)

# NAME

taema.unit - tæma unit file format

# DESCRIPTION

Units match apps and scopes and say how to stop them. Files live in
_/etc/taema/units_ (system) and _~/.config/taema/units_ (user); later
directories win unless a user tombstone masks the name
(*taema unit disable*). Lint with *taema unit lint*, dry-run matches with
*taema unit dry-run*, test the ladder with *taema unit test*.

# UNIT

*[unit] name*
	Unit name. App units match processes; scope units match explicit scopes.

*[unit] kind*
	*"app"* or *"scope"*.

*[unit] stop_when_unneeded*
	Stop the scope when nothing uses it (GC). Detached servers that should
	survive logout combine this with *[kill] survive_logout*.

*[unit] group_by_qmp, group_by_env*
	Optional grouping keys for VM-backed apps.

# MATCH

*[match] exe, comm, cmdline_contains*
	How to recognize the app. App units need at least one. Prefer *exe*;
	a bare *comm* that matches every process of that name is rejected as
	over-broad unless *cmdline_contains* narrows it.

*[match] env_exclude*
	Table of environment values that disqualify a match.

# KILL

*[kill] graceful*
	Seconds to wait after SIGTERM before SIGKILL. Default follows the daemon.

*[kill] keep*
	List of exe basenames moved to shared/ instead of killed, even without a
	detected edge (for example shared adb servers).

*[kill] hook*
	Path to an executable stop hook.

*[kill] never_stop, survive_logout*
	Never stop this unit; survive logout (requires *stop_when_unneeded*).

# GC

*[gc] keep_while_children*
	Keep the scope while it has children (for tmux-like servers).

# MEM

*[mem] class, background*
	Memory class (*app*, *vm*) and whether the workload is background work
	for reclaim priority. *taema unit lint* warns when *[mem] max* sits below
	the app's observed peak.

# WINDOW

*[window] backend, requires_window*
	Compositor backend and whether the app needs a window to stay alive.

*[desktop] app_id, on_last_window*
	Desktop identity and what happens on the last window close:
	*ask*, *quit*, or *keep*.

# CHILDREN

*[[children]] name, ancestor_comm|comm, binds_to*
	Carve sub-scopes out of an adopted tree. Each child binds to its own root
	process: when that process exits, the child scope stops. Names become
	_name_-_pid_ leaves (for example *session-4242*).

# SOURCE

*[source] learned*
	True when the learner wrote the file. Masks and packs never touch it.

# EXAMPLE

	[unit]
	name = "app-herdr"
	kind = "app"
	stop_when_unneeded = true

	[match]
	comm = "herdr"
	cmdline_contains = "server"

	[kill]
	survive_logout = true
	graceful = 10

	[gc]
	keep_while_children = true

# SEE ALSO

*taema*(1), *taema.toml*(5), *taema-learning*(7)
