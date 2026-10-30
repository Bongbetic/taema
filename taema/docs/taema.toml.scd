taema.toml(5)

# NAME

taema.toml - tæma configuration file

# DESCRIPTION

Tæma reads layered TOML configuration: built-in defaults, then
_/etc/taema/taema.toml_, _/etc/taema/taema.d/\*.toml_,
_~/.config/taema/taema.toml_, _~/.config/taema/taema.d/\*.toml_.
Later layers override earlier ones; drop-ins sort by filename.
*[protected]* entries always union, so a user file cannot remove a system
entry. *TAEMA_CONFIG* replaces the file layers with one file. An invalid edit
keeps the previous config and reports _file:line_.

# TOP LEVEL

*mode*
	Lifecycle mode: observe, adopt, enforce, or auto. Default observe.

# PATHS

*[paths]*
	socket, socket_fallback, state_dir, helper. Defaults live under
	_~/.local/state/taema_.

# TIMERS

*[timers]*
	adopt_interval, gc_interval, idle_grace, leftover_expire_days.

# PROTECTED

*[protected]*
	comm (list), cgroup_prefix (list), env_prefix (table). Matching processes
	are never stopped.

# LEARNER

*[learner]*
	deny_owners extends the built-in owner-deny classes.

*[learn]*
	enabled, burn-in and probation windows, ask budgets, review_ttl_days,
	identity_denylist, remember_argv, allow_self_authority (default false).

# MEMORY

*[mem]*
	enabled, manage (soft), budget, fraction, floor, reclaim and pressure
	gates, swap_reclaim, zswap, oom_policy.

# VETO, UI, REVIEW

*[veto]*
	enabled, default_expiry, block_reclaim.

*[ui]*
	color, dashboard_refresh, events_tail.

*[review]*
	queue, prompt, prompt_interval.

# AGENT

*[agent]*
	enabled, window_backend (auto), windowless_grace seconds (30),
	max_events_per_s (50), store_titles (false).

# NOTIFY

*[notify]*
	enabled, backend (auto), batch_seconds, max_per_hour, min_mem,
	quiet_hours, ttl, undo_toast_seconds, countdown_seconds, digest.

# FREEZE, QOS, GUARD

*[freeze]*
	enabled, adopt, after, wake_on_connect, max_frozen, cpu_idle_max.

*[qos]*
	enabled, leftover/idle weights, focus_boost, leftover_pids_max.

*[guard]*
	enabled, available_floor, psi_some, psi_full, cooldown,
	freeze_in_adopt, oom adjustments.

# STORE

*[store]*
	path, retention_days, sample_interval, max_events, daily_export.

# EXPERIMENTAL

*[experimental]*
	freeze, guard, window_close, launch_wrap, eventd feature flags.

# PROFILE

*[profile]*
	active (auto or a name), runtime_mode, per-profile overrides
	(default, focus, battery, game, quiet, server).

# UNITS

Units live in _/etc/taema/units_ and _~/.config/taema/units_:
[unit] name, kind, stop_when_unneeded; [match] exe, comm,
cmdline_contains; [kill] survive_logout, graceful; [gc]
keep_while_children; [window] backend, requires_window; [[children]]
carves.

# EXAMPLE

	mode = "adopt"
	[timers]
	gc_interval = 60
	[notify]
	max_per_hour = 6

# SEE ALSO

*taema*(1), *taema.unit*(5), *taema-learning*(7)
