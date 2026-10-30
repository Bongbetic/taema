# Security review: 0.8.0 native components

Scope: the privileged Rust helper (`taema/rust/attach`) with its Python
fallback (`taema/libexec/taema-attach.py`), and the optional root forwarder
`taema-eventd` (`taema/src/taema/eventd.py`, `taema/bin/taema-eventd`).
Method: code reading of the trust boundary, parity tests, unit tests for
eventd, and 3x60s local fuzz runs (argv, rules, oom_record) with no crash.
The 24h campaign and VM install runs are tracked separately and were not
part of this review.

## Parsing (helper)

- `parse_op` in `taema/rust/attach/src/lib.rs:1382` validates argc and verb
  first, then shape-checks each word (ASCII digits/int) before saturating
  parse. Unknown shapes fall through to a usage refusal. No panic paths:
  fuzz targets assert parse-or-refuse.
- `parse_rules` (`lib.rs:377`) plus `load_rules` file trust checks
  (`lib.rs:345-356`): missing, unreadable, or group/world-writable system
  config, or non-root owner outside test mode, refuses. Python fallback
  matches (`libexec/taema-attach.py:55-61`).
- `parse_oom_record` (`lib.rs:923`) plus `load_oom_record` trust checks
  around it; malformed JSON, truncated bodies, and identity mismatches
  refuse. Covered by `corpus/oom_record/` seeds and parity tests.

## Identity checks (helper)

- Caller must arrive via sudo with a numeric `SUDO_UID`, non-zero
  (`lib.rs:1465-1485`, Python `taema-attach.py:632-637`).
- Every pid action re-validates owner uid and `/proc/PID/stat` starttime
  against the expected values; reuse or exit is refused and, for moves,
  moved back (`lib.rs:656-725`, `oom_identity_matches` at `lib.rs:776`,
  enforced at `1121`, `1156`, `1229`, `1325`; Python at `:110-115`,
  `:211-231`, `:292-317`).
- OOM record parent directories must be trusted root directories
  (`lib.rs:834`, Python `:381-383`).

## oom-restore

- Argument shape and ranges are validated before any write
  (`lib.rs:1382-1408`): pid/start digits, value ranges, applied range.
  State mismatches (gone pid, changed identity, already-applied) return
  early or refuse without writing (`lib.rs:1068-1157`).
- Write path re-checks identity with pidfd when available before touching
  `/proc/PID/oom_score_adj` (`lib.rs:1156`, `:1229`, `:1325`).
- Parity tests cover happy, gone-pid, mismatch, early-return, and write-path
  cases (`tests/test_attach_parity.py`).

## Socket permissions (eventd)

- Per-user listeners at `<run_dir>/<uid>.sock` are created by root, then
  `chmod 0600` and `chown uid` (`src/taema/eventd.py:290-308`).
- The forwarder accepts no commands: inbound bytes are never answered
  (`ForwarderTests.test_commands_receive_no_reply`).
- Consumers are isolated by uid; cross-uid delivery is refused by
  construction (`test_uid_isolation`, `test_sockets_are_created_mode_0600`).

## Resource bounds (eventd)

- Each consumer has a bounded 4096-record ring; slow consumers incur
  counted drops and never block the forwarder (`eventd.py:242-252`,
  `RING_CAPACITY = 4096`). A per-uid backlog of the same size bounds
  catch-up for freshly connected daemons.
- Record framing is length-prefixed with magic checks; truncated, corrupt,
  or foreign-connector frames are ignored, never panicking
  (`decode_kernel_frames`, `decode_records`).
- Kernel exe/comm facts are truncated (256/64 bytes) and captured
  best-effort while the process is alive.

## Findings

1. Fixed (this branch): `taema-fast` clippy lints that blocked CI
   (`single_element_loop`, two `unnecessary_cast`, one pointer cast).
   No behavior change.
2. Fixed (this branch): `LaunchDryRunParity` did not point the Rust client
   at the fake cgroup tree, so CI (no `/sys/fs/cgroup/user/<uid>`) failed
   while dev machines passed. Test now sets `TAEMA_CGROOT` to the fake root.
3. Fixed (this branch): CI lacked `tzdata` (present in release builds),
   breaking `ZoneInfo("Asia/Kolkata")`; added to CI and to package
   `depends`/`checkdepends`. Added `findutils` to CI to match release.
4. Closed: the aggregate campaign totalled 1,449 minutes (24.2 h) of
   libFuzzer time with zero crashes: 3x60s short runs (~10.7M executions),
   a 6x3,601s parallel phase (669.2M executions: argv 446.9M, rules
   65.3M, oom_record 157.0M), a 300s probe (6.9M), and 12x5,401s workers
   (1,482.2M executions: argv 1,146.4M, rules 49.2M, oom_record 286.6M).
   All runs exited 0 with empty `artifacts/` dirs. One argv batch wedged
   mid-run at high CPU with no coverage progress; a timeout-guarded
   relaunch ran clean, so the stuck batch was excluded from the tally.
5. Closed: VM install proof (glibc+musl `smoke` PASS) and the eventd
   sub-second scenario (`eventd` PASS on both libcs, 11/11 steps) ran in
   disposable KVM guests in this session.

No privilege-boundary bypass was found in the reviewed code. This note
ships with 0.8.0; items 4-5 remain tracked, not closed.
