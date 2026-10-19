# ADR-0007: Build, packaging, and CI — Makefile/xbps kept, matrix and cargo added

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §9; `taema-v2.md` §11.9
- Related decisions: D7 (packages progress 0.3.0 → 1.0.0), D12 (Rust components), D13 (eventd as a separate optional subpackage), D20 (native builds target x86_64 glibc and x86_64 musl only)

## Context

tæma 0.2.1 is built and released today through a Makefile plus an xbps-src `gnu-makefile`
template, with a signed XBPS repository published by a tag-triggered GitHub Actions
workflow that runs `make test` as the release gate. CI exists only for that release path:
there is no lint, no type checking, no glibc/musl matrix, and no pull-request feedback.
The v2 line adds Rust binaries that must build offline from vendored sources, man pages,
completions, and new configuration files, while the Void package must keep its current
`depends` set, its signed-release flow, and its ability to install without a desktop
stack.

## Options considered

| Option | Assessment |
|---|---|
| Keep Makefile/xbps with tests-only CI | Rejected: no static gates, no musl coverage, and no way to build the incoming Rust components reproducibly. |
| **Keep Makefile/xbps, extend CI into a full matrix, add cargo/scdoc and subpackages** | **Accepted:** preserves the proven release path while adding every gate the spec requires. |
| Replace the packaging with a Python-native flow (wheels, pip, a different distro packaging style) | Rejected: the target platform is Void/XBPS, the runit/sudoers/group installation is package-specific, and switching costs would buy nothing for users. |

## Decision

- The xbps template keeps `build_style=gnu-makefile` and adds
  `hostmakedepends="cargo scdoc"`; the Makefile builds the `rust/` workspace with
  `cargo build --release --offline` from vendored crates shipped as a second distfile.
- `depends` is unchanged; `libnotify` is documented as optional because Void has no
  "recommends" and the agent degrades without it.
- Subpackages: `taema` (core, CLI, agent, `taema-fast`, Rust helper),
  `taema-eventd` (optional root forwarder with its runit integration), and an optional
  `taema-contrib` (DMS widget and unit packs).
- The CI matrix runs in `void-glibc` and `void-musl` containers: `ruff check` and
  `ruff format --check`; `mypy`; `unittest` via pytest with coverage (at least 85% for new
  modules); hypothesis property tests; `cargo fmt --check`, `clippy -D warnings`,
  `cargo test`, and `cargo audit`; JSON Schema contract tests; the existing packaging
  tests; an `xbps-src pkg` build; and an optional live-cgroup job, since cgroup delegation
  inside CI containers varies.
- Once native components land, packages are built only for x86_64 glibc and x86_64 musl
  (D20).
- The existing tag workflow and signed repository stay: the tag must match
  `__version__`, tests gate the release, and release notes are generated from the
  changelog plus a "behaviour changes" section that is mandatory whenever mode semantics
  change.

## Consequences

- Every pull request gets lint, format, type, test, and packaging feedback on both libcs,
  instead of only releases getting tests.
- Offline builds make vendoring a discipline: crate updates must refresh the vendor tree
  and distfile checksums together, and `cargo audit`/`cargo deny` become release-blocking.
- The xbps template grows hostmakedepends and subpackage splits, so template and build
  script must stay in sync (their `conf_files` lists have already drifted once).
- CI time and infrastructure cost increase with the matrix, and jobs that need live
  cgroups remain explicitly optional to avoid flaky gates.
- The signed-release model is unchanged, so no new trust root is introduced; behaviour
  changes become visible to upgraders through the mandatory release-notes section.
