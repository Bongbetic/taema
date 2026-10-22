# Application identity resolution

Every process gets one `AppIdentity`. Its `key` is the authority-bearing value used by pairs,
vetoes, stop plans, and answers; `display` is presentation only. A display-name change never
reuses authority, and a changed executable inode creates a new executable identity.

The resolver checks stronger, class-specific evidence before generic executable fallback:

1. A matching app unit uses its configured unit name under the `unit:` key namespace.
2. An interpreter with a script uses the canonical interpreter, script label, and a 12-character
   SHA-256 hash of the resolved script location. The interpreter binary's inode is not used for
   script identities, so equal script basenames in separate projects stay separate. A
   module/class includes its working location in the hash. A scriptless interpreter can use a
   distinct validated process title.
3. A recognized runtime uses a runtime class and a hash of its cgroup identity or Unix socket
   evidence instead of the runtime executable's shared inode. Runtime CLI probing is not part of
   resolution.
4. An ordinary application executable uses `exe:<basename>:<device>:<inode>`. The basename is
   its display name; the device and inode distinguish upgrades and parallel installations.
5. If stronger evidence is unavailable, `comm` is accepted only after generic threads, numeric
   names, shells, trivial commands, and scriptless interpreters are rejected.

Rejected fallbacks receive an `invalid:` key. They can still describe a process or leftover, but
they cannot own a learned pair or receive an answer. When ownership cannot be resolved, the daemon
queues a `provenance-candidate` review with valid ancestry candidates. Candidate listing is
informational: it does not bind an answer or grant authority.

`StateDB` persists identities in `apps` and pid/start records in `instances`. The existing bounds
are 2,000 LRU identities and 50,000 instances over 90 days; answered, standalone, and actively
vetoed identities are retained. Instances record their exit time when they disappear from a pass;
re-observing the same pid/start key after daemon restart updates that row and clears its exit time.
`last_seen` keeps a long-running process's instance row in retention while it is observed; its
`born` time remains the process birth time. The `parents` table counts the retained pid/start
instances that support each app-to-parent edge.
Each instance stores its evidence set so repeated passes do not inflate those counts, and pruning
removes its contribution before deleting the instance. Current evidence includes co-birth, shared
cgroup, shared job, and matching runtime; the schema also reserves window and launch evidence.

`taema why` follows the latest retained parent edge and shows counts for each evidence type.
Confidence is the selected parent's share of all retained evidence counts for that app; it is a
relative support measure, not a calibrated probability. `launched_by` records `adopt`, `unit`, or
`run` when those sources can be derived from the app unit or managed cgroup. Display hints such as
`launch_name` are never copied into this source field.

Only identity keys, basenames, display labels, unit/runtime tags, and provenance fields are stored
here. Script paths are hashed; argv and cwd are not persisted. Schema v4 adds the per-instance
evidence set with an empty default, `last_seen`, and an index on parent evidence recency; v3 app and
instance rows remain intact and acquire evidence as they are observed again. Pruning may leave the
instance cap temporarily exceeded when every remaining row protects an explicit answer or active
veto.

The v4 migration is additive and transactional. To downgrade after taking a consistent SQLite
backup and stopping the daemon, remove the v4-only evidence, then restore the v3 schema marker:

```sql
BEGIN IMMEDIATE;
DELETE FROM parents;
DROP INDEX IF EXISTS parents_last;
ALTER TABLE instances DROP COLUMN parent_evidence;
ALTER TABLE instances DROP COLUMN last_seen;
PRAGMA user_version = 3;
COMMIT;
```

This preserves app and pid/start records; it intentionally discards accumulated parent counts so a
later v4 upgrade cannot count them twice.

## Desktop and launch hook

Later desktop-agent and `taema launch` work can provide names without adding a second key path.
`IdentityHints` accepts `desktop_id` and `launch_name`; `Lineage` accepts a provider with the
signature `provider(pid: int, start: int) -> IdentityHints | None` through its
`identity_hints` constructor argument. The resolver uses the name for display and decorates the
evidence key with its source, while keeping executable/script/runtime evidence in the key. A unit
continues to use its configured unit name. This hook lets the agent and launch command supply
recognizable names while preserving inode- and project-bound authority.

The daemon also gives `Lineage` an `identity_sink(records)` callback, backed by
`Store.record_identities`. It receives the identities and instance records discovered or changed
in one observe pass, so SQLite writes remain bounded to one transaction per pass.
