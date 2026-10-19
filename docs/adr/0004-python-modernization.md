# ADR-0004: Python modernization — pyproject, ruff, mypy, and typed module layout

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §1 and §9; `taema-v2.md` §11.6
- Related decisions: D17 (Python floor stays 3.11), D7 (version line 0.3.0 → 1.0.0)

## Context

The v2 line roughly doubles the Python surface — resource governor, session agent, store
and migrations, protocol, and new CLI — so typed contracts become the main defense against
regressions. The 0.2.1 codebase has no `pyproject.toml`, no lint or type-checker
configuration, and module boundaries that mix kernel facts with policy decisions. The
README promises a Python 3.11 floor (`tomllib` requires it), the Makefile install layout
and xbps template are release-critical, and the 331 existing tests must keep passing
throughout. Startup latency is a product requirement, so import cost at CLI start must be
controlled.

## Options considered

| Option | Assessment |
|---|---|
| Keep the status quo: no tooling, no typing, stdlib only | Rejected: doubling an untyped, unlinted surface makes the governor and protocol work unsafe, and CI would have no static gate. |
| **Modernize in place: `pyproject.toml` for metadata/tool config, ruff, mypy strict for new modules, typed immutable records** | **Accepted:** adds static guarantees and linting while preserving the Makefile/xbps release path and the stdlib-only runtime. |
| Adopt third-party build/format stacks (poetry/hatch, black/isort, setuptools-based installs) | Rejected: changes the packaging story the release workflow is built on and adds tooling dependencies for no runtime benefit. |
| Re-type and restructure the whole legacy tree before v2 work starts | Rejected: blocks value on a rewrite-style effort; strictness is applied incrementally where the risk is. |

## Decision

- The version floor stays 3.11 (D17); CI tests 3.11 and the current Void Python (3.14).
- `pyproject.toml` holds project metadata and tool configuration only — the Makefile
  install layout and the xbps template do not change.
- Tooling: `ruff` for lint and format; `mypy` strict for the new model, store, governor,
  and authorization modules, applied gradually to older modules with per-module overrides.
- Code style: `dataclasses(slots=True, frozen=True)` for records and `typing.Protocol`
  for pluggable parts (`Store`, `Collector`, `Actuator`, `WindowBackend`, `Notifier`).
- The package restructures into responsibility-based subpackages (`core/`, `model/`,
  `store/`, `governor/`, `daemon/`, `agent/`, `cli/`, `ui/`, `config/`) under the
  unchanged import root `taema`; compatibility shims keep old imports working for one
  release, and M0 does not depend on the restructure.
- The CLI entry point imports only argparse and the command module it needs, keeping
  start-up latency within the product targets.

## Consequences

- New code gains a static-check gate in CI while old code migrates module by module,
  avoiding a big-bang typing effort.
- Two configuration homes now exist (Makefile/xbps and `pyproject.toml`); they must not
  drift, so packaging tests keep guarding the install layout.
- Frozen slotted dataclasses make decision inputs immutable by construction, which the
  pure decision-model tests can rely on.
- Compatibility shims are temporary debt: they must be removed after the promised release,
  with their expiry tracked like any other decision.
- Contributors see lint/format/type errors before review, but the strict-mypy surface grows
  with each new module, and per-module overrides must be justified rather than default.
