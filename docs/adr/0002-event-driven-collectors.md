# ADR-0002: Event-driven collectors with reconciliation as the backstop

- Status: Accepted (staged delivery)
- Date: 2026-10-19
- Source: spec issue #1 §9; `taema-v2.md` §11.4
- Related decisions: D13 (eventd optional and off by default), D12 (Rust eventd binary)

## Context

The 0.2.1 daemon reacts to the world by polling `/proc` every 15 seconds behind a fork
gate, so adoption, containment, and answers lag real events by up to an interval. The v2
line wants event-driven reaction to memory pressure, window closes, and process births and
exits — while keeping the same-uid, unprivileged safety boundary. Correctness must never
depend on any single event arriving: events can be lost or duplicated, and the daemon must
behave correctly on kernels where some sources are unavailable. The one source that would
give instant process events system-wide, the netlink proc connector, requires root, which
conflicts with the per-user daemon owning all policy.

## Options considered

| Source | Privilege | Latency | Verdict |
|---|---|---|---|
| pidfd owner watches | none | instant | kept (already exists) |
| `cgroup.events` epoll (`populated`, `frozen`) | none | instant | kept and extended to `frozen` |
| PSI triggers (`memory.pressure`) | none | ≤ 2 s window | added in M3 |
| niri `event-stream` relayed by the session agent | session | instant | added in M5 |
| `/proc` snapshot with the fork gate | none | one adopt interval | kept as the reconciliation pass; correctness never depends on an event |
| Netlink proc connector via `taema-eventd` | `CAP_NET_ADMIN` (root) | instant | accepted as optional in M6 |
| eBPF (execsnoop-style) | root plus a BPF toolchain | instant | rejected: heavy build and runtime requirements, more than this job needs |
| fanotify | root for useful marks | — | rejected: not a process-lifecycle API |

## Decision

- Collectors push typed events (`ProcBorn`, `ProcExited`, `WindowClosed`, `PressureHigh`,
  `LeafEmpty`, `LeafFrozen`, and so on) into one in-process queue that the selector loop
  drains; handlers are idempotent because the reconciliation pass may report the same fact
  again.
- The fork-gated `/proc` snapshot loop remains the reconciliation pass: lost or duplicate
  events degrade latency, never correctness.
- `taema-eventd` is an optional root forwarder: one instance per system under the existing
  runit service, subscribing to the proc connector, filtering events by uid, and forwarding
  compact records `(event, pid, tgid, ppid, uid, ts)` to `/run/taema/events/<uid>.sock`
  (root-created, mode 0600, user-owned). Each consumer gets a bounded 4,096-record ring
  with drop counters for slow readers. Eventd accepts no commands and makes no decisions.
- Eventd ships as a separate subpackage, disabled by default (D13); the agent and niri
  cover desktop latency without it (D12, D13).

## Consequences

- With eventd running, births are seen instantly and the 5-second `MIN_AGE` rule becomes a
  classification rule instead of a polling artifact.
- Every collector handler must tolerate duplicates, which pushes the design toward pure,
  idempotent state transitions.
- A new privilege boundary appears in M6: the security review must cover eventd's uid
  isolation, drop behavior, and absence of any command surface before it ships.
- Systems without eventd, PSI, or an agent keep the exact 0.2.x polling behavior, so the
  feature is genuinely optional rather than a silent regression.
- Staged delivery (M3 PSI, M5 windows, M6 eventd) keeps each source independently
  releasable and testable.
