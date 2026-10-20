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
