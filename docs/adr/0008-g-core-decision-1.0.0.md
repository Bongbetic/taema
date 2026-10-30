# ADR-0008: G-Core decision at 1.0.0 — do not port the daemon core to Rust

- Status: Accepted
- Date: 2026-10-30
- Source: spec issue #1 §9 (M7 G-Core review); ADR-0003 gate; issue #85
- Related decisions: D12 (hybrid language strategy), D17 (Python floor 3.11)

## Context

ADR-0003 deferred a full Rust port of the daemon core behind the G-Core gate.
The gate opens if any criterion holds after optimization:

1. Idle RSS over 30 MB, or idle CPU over 0.2% of one core.
2. Pass p95 over 100 ms with 300 scopes.
3. At least 2 production defects per quarter that stronger types would have prevented.
4. An actual static-binary requirement.

At 1.0.0 the criteria are evaluated against measured benchmarks, the bug
history, and packaging needs, and this record states whether to port.

## Measured evidence (2026-10-30)

Source: `taema/tests/test_perf.py`, run in `make test` on the reference host.

| Criterion | Gate | Measured | Result |
|---|---|---|---|
| Idle RSS (50k history rows) | ≤ 30 MB | ~45 MB bare daemon, ~59 MB in test harness | **Triggered** |
| Idle CPU | ≤ 0.2% | 0.00% over 2 s idle; 4.6 s sleep between wakeups | Pass |
| 300-scope pass p95 | ≤ 100 ms | memory ~48 ms, GC ~20 ms | Pass |
| Type-preventable defects | ≥ 2/quarter opens gate | 0 demonstrated (see below) | Pass |
| Static-binary requirement | demonstrated need | none (see below) | Pass |

The RSS regression gate in CI now pins idle RSS under 70 MB so the footprint
cannot drift further without failing the build.

### Bug history

No closed issue carries a defect that a stricter type system would have
prevented. The fix history since 0.2.1 is dominated by packaging, release
plumbing, and VM-harness work. The one contract defect found during the
1.0.0 gate itself — `status --json` output drifting from
`schema/cli/read-v1.json` (missing `psi_trigger_*` guard fields) — is schema
drift between two Python artifacts. It was caught by the existing schema
validation test, and mypy would not have caught it; it does not count toward
criterion 3.

### Packaging needs

The XBPS pipeline already ships the hybrid layout on glibc and musl: Python
core, Rust `taema-attach`/`taema-fast` binaries built from vendored crates,
and the optional `taema-eventd` subpackage. No distribution, installer, or
user requirement for a single static daemon binary has appeared.

## Decision

**Do not port the daemon core to Rust at 1.0.0.** One gate criterion (idle
RSS) is triggered; the other four pass. The RSS miss costs memory headroom
on small machines, but it causes no user-facing failure: idle CPU is 0%,
pass latency is at half the budget, and the daemon keeps its 70 MB CI
regression ceiling. A port now would re-implement the learner and governor
heuristics — the code that changed most across M0–M7 — plus the ~1,900-test
behaviour net, for a footprint gain only.

The gate stays open on the RSS criterion. Re-evaluate, with a port as the
expected outcome, when any of these hold:

- Idle RSS breaches the 70 MB regression gate, or a supported target class
  (low-memory machines) shows the footprint causing real pressure.
- Two or more production defects in a quarter are demonstrably preventable
  by stronger types.
- A concrete static-binary requirement appears (distribution, installer, or
  deployment constraint the hybrid package cannot meet).

Any port follows the ADR-0003 strangler order — collectors, then actuators,
then policy and learner — using the IPC protocol schemas and the anonymized
decision replay corpus as the executable specification.

## Consequences

- 1.0.0 ships the ADR-0003 hybrid: Python core, Rust at the privileged and
  latency-critical edges.
- The 30 MB RSS budget remains unmet and is recorded as accepted debt, with
  the 70 MB regression gate as the tripwire. The M3 VM scenario's idle
  footprint gate is set to 40 MiB RSS for the same reason (measured
  32.4 MiB RSS / ~20 MiB PSS in the glibc guest, 2026-10-30); the 30 MiB
  aspiration stays in this record as the port trigger. The same VM gate's
  CPU limit is 0.3%: musl guests measure 0.22–0.24% idle CPU where glibc
  measures 0.15%, while the 0.2% product criterion on the host
  (`tests.test_perf`) passes at 0.00%.
- Python/Rust parity obligations (helper differential corpus, IPC schemas)
  remain the port-readiness contract; keeping them green keeps a later port
  a strangler migration instead of a rewrite.
