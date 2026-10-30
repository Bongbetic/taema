# Upgrading to tæma 1.0.0

1.0.0 completes the v2 spec (issue #1). Upgrades from 0.2.1 and from every
0.3–0.8 release are automatic: install the new package, and the per-user
daemon migrates its state on first start. Migration stops no processes, and
managed scopes stay in place while package files are replaced.

```sh
sudo xbps-install -Su taema
```

## From 0.2.1 (legacy JSON state)

The 0.2.x daemon stores learning in `knowledge.json`. On first 1.0.0 start
the daemon:

- Copies the JSON file to a private `knowledge.json.backup-*` file, kept for
  30 days. The original file stays untouched and is never written again.
- Imports valid pairs, standalone answers, question counts, and metadata
  into SQLite `state.db` in one transaction.
- Treats legacy identities as low-confidence. Pairs whose owner identity
  fails validation cannot authorize any action; an explicit stop or keep
  answer on such a pair is cleared and reopened as a review for
  re-confirmation.
- Imports up to the 10,000 most recent lines of the legacy audit log,
  best effort.

Inspect the result with `taema learn pairs`; find re-confirmation reviews
with `taema review` or `taema learn show --legacy`. Full detail:
`/usr/share/doc/taema/legacy-state-migration.md`.

## From 0.3.0–0.8.0 (SQLite state)

The SQLite schema migrates in place on daemon start. Imported and native
records keep their decisions. No manual export is needed.

## Behaviour changes since 0.2.1

- **adopt contains and asks.** In `adopt`, survivors of a closed GUI app
  move into a `leftover/` scope and queue a review instead of being left
  unscoped. Unanswered reviews keep the leftover.
- **Unlearned idle leftovers are never stopped.** Inactivity alone grants
  no authority in any mode. `auto` collects eligible idle shared/unit
  scopes; unlearned leftovers are reviewed, not stopped.
- **`taema run --bind` works in `adopt`.** The explicit owner binding stops
  its scope when the command exits, under the usual safety and veto checks.
- **Vetoes are broader and work offline.** `taema do-not-kill` covers
  processes, scopes, pairs, signatures, apps, owners, units, subtrees, and
  executables. Pending vetoes block CLI stops while the daemon is down;
  `taema stop --force-veto` is the single confirmed, audited override.
- **Reversible actions come first.** Idle leftovers are deprioritized,
  frozen (with wake-on-connect), and reclaimed before any authorized stop.
  `taema undo` thaws and restores.
- **Memory is governed.** Per-scope memory, swap, and pressure accounting;
  conservative soft shares by default; hard caps only by explicit opt-in.
- **State moved to SQLite.** `knowledge.json` is read once, then
  `state.db` is authoritative. State and config export, import, backup,
  and reset live under `taema backup`, `taema learn export/import`, and
  `taema reset`.
- **IPC and CLI output are versioned.** JSON/JSONL output validates against
  shipped schemas (`taema.*.v1` records). Old commands, hooks, and units
  keep working.

Per-release detail is in `CHANGELOG.md` (0.3.0 through 1.0.0).

## Downgrading

Before downgrading to 0.2.x, export the learned state in the legacy format:

```sh
sv down taema
taema learn export --format v2 --output "$HOME/taema-knowledge-v2.json"
```

Then follow the rollback procedure in
`/usr/share/doc/taema/legacy-state-migration.md`. Downgrading to a 0.3–0.8
release needs no export; those releases read the same SQLite state family,
but decisions recorded only by newer releases may be ignored. Keep a
`taema backup` archive before any downgrade.

## Removing

```sh
sudo xbps-remove taema
```

Removal deletes the package, its binaries, and the `/var/service/taema`
link, and leaves no daemon process running. Your state directory
(`~/.local/state/taema`) is kept; delete it manually to erase learned state.
