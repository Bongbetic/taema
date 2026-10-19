# ADR-0001: SQLite for state storage

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §8; `taema-v2.md` §11.3
- Related decisions: D14 (privacy defaults shape what is stored), D17 (Python floor keeps `sqlite3` in the stdlib)

## Context

In 0.2.1 the daemon persists learning in `knowledge.json` — a whole-file rewrite on every
save — plus `decisions.log` (JSON lines) and `feedback.jsonl`. That design worked for a
small store, but the v2 product line needs indexed queries and retention for `why`,
`history`, `report`, and dashboard views; concurrent readers (CLI, dashboard, widget, and
agent) must read while the daemon writes; state must survive crashes atomically; and the
daemon must stay Python-stdlib-only so no new runtime dependency enters the package. The
store will also hold vetoes, reviews, decisions, memory samples, and OOM values with
per-table caps (for example 50,000 instances and 200,000 events over 90 days), none of
which a single JSON blob models well.

## Options considered

| Option | Assessment |
|---|---|
| JSON v3 (revision 1 approach: schema bump on the existing whole-file store) | Rejected: no queries or retention, every save rewrites the whole file, and reader/writer races need ad-hoc locking. |
| **SQLite via the stdlib `sqlite3` module** | **Accepted:** queries and retention come built in, readers can open read-only URIs while the daemon writes, commits are atomic, it ships in the stdlib, and the future Rust components can read the same file. |
| LMDB, RocksDB, or another non-stdlib store | Rejected: adds a runtime dependency the package does not want, and none of them gives SQL for reporting queries. |

## Decision

- The store is `state.db` in the state directory (default `~/.local/state/taema/`), opened
  in WAL mode with `synchronous=NORMAL`, `busy_timeout=2000`, and `foreign_keys=ON`; the
  schema version lives in `PRAGMA user_version` (schema 3).
- There is exactly one writer, the daemon, committing one transaction per pass and
  immediately after answers, vetoes, and undo. Readers (CLI, dashboard, agent, bar) open
  `file:…?mode=ro` URIs.
- `decisions.log` stays outside the database as the append-only, greppable, rotated audit
  trail; the `events` table is a queryable index with retention on top of it.
- Legacy `knowledge.json` state is migrated atomically and idempotently with a 30-day
  backup; migration stops no processes.

## Consequences

- Queries, retention, and concurrent readers arrive without locks, and crash safety comes
  from atomic commits instead of temp-file renames.
- Schema migrations become a permanent responsibility: they are forward-only scripts keyed
  to `PRAGMA user_version`.
- Corruption handling is required: `quick_check` at startup, quarantine the damaged file,
  and rebuild from the newest of three rotated daily exports, then the legacy backup.
- WAL growth must be bounded with a passive checkpoint taken at idle, and writes must
  never block beyond the configured busy timeout.
- The Rust components and read-only clients inherit a single shared storage contract, but
  the schema must be documented and versioned alongside the IPC schemas.
