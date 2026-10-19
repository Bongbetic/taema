# Upgrade and downgrade state

When the daemon first starts with `state.db` and an existing 0.2 `knowledge.json`, it
copies the JSON file to a private `knowledge.json.backup-*` file and imports learning,
reviews, vetoes, metadata, and recent audit events in one SQLite transaction. The backup
is kept for 30 days. The original JSON remains untouched and is no longer written. A
restarted or upgraded daemon recognizes the committed import marker and will not import it
again. Existing SQLite records stay authoritative when a migration merges into a database
that already has state.

Legacy app records begin with low confidence. Pairs whose owner identity fails validation
remain stored as `legacy-invalid`; they cannot ask, keep, or stop. Any explicit stop or keep
answer on such a pair is cleared from decision evidence and moved into an open review so it
can be confirmed later. Import indexes up to the latest 10,000 valid lines from
`decisions.log.1` and `decisions.log`; the text log itself remains unchanged.

## Downgrade to 0.2

Export the SQLite state in the format understood by 0.2:

```sh
set -e
sv down taema
taema learn export --format v2 --output "$HOME/taema-knowledge-v2.json"
```

The command writes the file atomically with mode `0600`. Keep the SQLite database and its
sidecars together as a rollback copy. For the default state directory:

```sh
sv down taema
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/taema"
backup_dir="$state_dir/sqlite-before-downgrade-$(date +%Y%m%d%H%M%S)"
install -m 600 "$HOME/taema-knowledge-v2.json" "$state_dir/knowledge.json.tmp"
mv "$state_dir/knowledge.json.tmp" "$state_dir/knowledge.json"
mkdir -m 700 "$backup_dir"
for file in state.db state.db-wal state.db-shm; do
  [ ! -e "$state_dir/$file" ] || mv "$state_dir/$file" "$backup_dir/"
done
```

Then install the 0.2 package. Moving the SQLite files aside lets a later 0.3 upgrade import
the JSON state that 0.2 may have changed. Keep the rollback directory until that upgrade
has been verified. If the service uses a custom state directory, use that path instead.

## Maintainer fixture

`tools/anonymize_state.py` reads `knowledge.json` and the audit log without modifying them.
It replaces app, scope, process, and record identifiers and writes only the decision fields
needed by migration tests. It removes command arguments, working directories, paths, and
project names. Refresh the committed fixture on the reference machine with:

```sh
python3 tools/anonymize_state.py --output-dir tests/fixtures/legacy-v2
```

The fixture parity test checks that every valid pair keeps its decision across import.
