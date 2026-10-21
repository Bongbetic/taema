# SQLite state schema

The current `state.db` schema version is **9**, recorded in `PRAGMA user_version`.
`taema/store/db.py` applies each numbered migration in its own write transaction and
advances `user_version` only after that migration succeeds. Migrations are forward-only
and additive; this document records the storage contract needed by read-only clients.

## Signature outcome fields

Schema 8 adds two nullable columns to `signatures`:

| Column | SQLite type | Meaning |
|---|---|---|
| `last_outcome` | `TEXT` | Latest recorded learning outcome: `answered`, `stop_ok`, `respawn`, or `regret`. |
| `last_outcome_at` | `REAL` | Unix epoch time in seconds when that event was recorded. |

The decision is derived from the outcome and existing `ex_last` value:

| `last_outcome` | Decision | Meaning |
|---|---|---|
| `answered` | `ex_last` (`stop` or `keep`) | The latest explicit answer. |
| `stop_ok` | `stop` | An automatic stop completed without a respawn during its watch window. |
| `respawn` | `keep` | A stopped survivor returned during the watch window. |
| `regret` | `keep` | Tæma detects the same pair revived within the configured regret window, adds keep evidence, and suspends automatic authority for that interval. |

Explicit answers, successful automatic stops, respawns, and regrets accepted by
`Store.regret()` update both columns. `veto` and `probation` counters do not replace the latest
decision outcome. A later recorded event replaces an earlier one, so its timestamp determines
which result the learn views report.

Pair outcomes are stored in the pair payload's `last_auto_outcome` object with `decision`,
`outcome`, and `at` fields. The object retains its historical name and also records regrets.
Both pair and signature timestamps use the event-recording time, not the time the stop was
first requested.

## Migration and older rows

Migration 8 runs `ALTER TABLE` to append nullable `last_outcome` and `last_outcome_at` columns
to `signatures`; it does not infer event order from counters or rewrite existing rows. A
schema-7 signature therefore keeps both fields `NULL` until a new answer, stop result, respawn,
or regret is recorded.

For such a legacy signature, learn summaries fall back to `ex_last` as an `answered` outcome
with no timestamp. If there is no valid `ex_last`, the summary reports no last outcome. Older
automatic counters cannot be ordered against explicit answers because their event timestamps
were not stored. Pair payloads created before `last_auto_outcome` use their retained answer,
pending-stop timestamp, and `last_keep` / `last_auto_stop` timestamps for a best-effort result;
the original event order cannot be recovered when those timestamps are absent or ambiguous.

## Memory samples

Schema 9 adds the nullable `peak INTEGER` column to `mem_samples`. It stores each scope's
observed peak alongside the current, anonymous, file, swap, zswap, and PSI sample values.
Migration 9 appends the column with `ALTER TABLE`; existing rows retain `NULL` peak values
and are not rewritten. Older schema-8 databases are upgraded on the next writable startup.
Read-only consumers that encounter a schema-8 database can continue reading the existing
columns and treat peak as unavailable.
