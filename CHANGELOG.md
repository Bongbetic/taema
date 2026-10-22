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
