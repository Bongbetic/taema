# ADR-0003: Hybrid language strategy with the G-Core gate for a full port

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §9; `taema-v2.md` §11.5
- Related decisions: D12 (Rust helper, fast clients, and eventd now; core port only through G-Core), D17 (Python floor stays 3.11)

## Context

The 0.2.1 stack is Python ≥ 3.11 with a standard-library-only constraint, and its 331
tests are the regression net for every behavioral change. Several forces push back against
staying pure Python: the privileged `taema-attach` helper runs an interpreter under
`sudo -n`, which is a large attack surface for a tiny job; latency-critical clients (shell
hook, prompt, launch, bar) pay ~95 ms interpreter start-up; and the daemon footprint sits
near 25 MB RSS. At the same time, the learner and governor heuristics are still moving, so
a full rewrite now would re-port tests and code that have not settled, delaying user value
by months. Whatever is chosen, a later full port must remain possible without a big-bang
rewrite.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A. Python only, typed and modernized | Fastest iteration on moving heuristics; reuses all 331 tests; no new toolchain | ~25 MB RSS daemon; ~95 ms client start; an interpreter under sudo; weaker guarantees for privileged code | Rejected as the *only* language, but kept as the core |
| **B. Hybrid: Python core plus Rust at the edges** | Memory-safe privileged code; sub-5 ms clients; a tiny eventd; iteration speed kept where logic changes most | Two toolchains and slower CI; every boundary must stay process/protocol only (no FFI) | **Accepted for v2** |
| C. Full Rust rewrite now | 3–8 MB footprint, one static binary, strong types, native D-Bus and TUI crates | Months before user value; re-porting 331 tests; learner heuristics not yet stable | Deferred behind the G-Core gate |
| D. Go | Static binaries, simple concurrency | GC'd daemon still 10–20 MB; no Go toolchain in this packaging environment; weaker fit for tiny privileged binaries | Rejected |
| E. Python plus C extension | Faster `/proc` scans | Packaging pain and memory-unsafe code | Rejected |

## Decision

- The core (daemon, learner, governor, configuration, CLI) stays Python, stdlib-only, with
  the 3.11 floor (D17).
- A `rust/` cargo workspace produces binaries only: the rewritten `taema-attach` helper
  with an identical CLI plus the new `oom-restore` verb (differential tests against the
  Python helper and a fuzz target, with the Python helper kept as a fallback for one
  release); the multicall `taema-fast` for `hook`, `prompt`, `launch`, and `bar --follow`;
  and the optional `taema-eventd`.
- The only contracts between languages are the IPC socket protocol (JSON Schemas), the
  SQLite schema, and command-line interfaces — never FFI.
- Rust dependency policy: no async runtime; crates limited to `libc`/`rustix`, `serde`,
  `serde_json`, and `toml` where configuration is read; vendored for offline xbps builds;
  `cargo audit` and `cargo deny` run in CI.
- A full core port happens only through the **G-Core** gate reviewed at the end of M7,
  which opens if any of these hold after optimization: idle RSS above 30 MB or CPU above
  0.2%; pass p95 above 100 ms with 300 scopes; two or more production defects per quarter
  that a type system would have caught; or a demonstrated need for a single static binary.
  A port then follows a strangler order — collectors, actuators, then policy and learner —
  using protocol contract tests and the decision replay corpus as the executable spec.

## Consequences

- Privileged and latency-critical paths become memory-safe and fast while the heuristics
  keep their fast iteration loop and full test coverage.
- The project now maintains two toolchains and a CI matrix for both, and every new
  cross-language feature must be designed as a process, schema, or CLI contract.
- Python/Rust parity becomes a permanent obligation: helper behavior is proven by
  differential tests over a shared corpus, including refusals.
- Option C remains reachable later without a rewrite because the contracts are already
  executable, but until G-Core triggers there is no single static binary.
- Contributors need competence in both languages at the boundaries; the default contribution
  (core logic) remains Python.
