# Fuzzing the privileged helper's parsers

cargo-fuzz targets for the trust boundary of `taema-attach`: the
argument vector (`argv`), the rules file (`rules`), and the OOM
restoration record (`oom_record`). Each target asserts the parse/execution
split — any input must validate to a value or a `Refused` message, never
panic. An empty pid word, for example, parses fine and is refused
downstream as "bad pid", exactly like the Python fallback.

This crate is its own workspace (nightly + libFuzzer): it stays out of
the locked offline build and never ships in the package.

## Run

```sh
cargo fuzz run argv -- -max_total_time=60
cargo fuzz run rules -- -max_total_time=60
cargo fuzz run oom_record -- -max_total_time=60
```

CI runs each target with a short budget on every change (`.github/workflows/ci.yml`);
the weekly `fuzz-long` workflow (`.github/workflows/fuzz.yml`) runs chunked
campaigns with the corpus cached between runs.

## Corpus

`corpus/<target>/` holds small curated seeds only — one file per
interesting shape, each under a few hundred bytes. Do not commit
fuzzer-grown entries; the long campaign keeps those in the CI cache.
`artifacts/` (crashers) is gitignored: triage every crasher, and for
each real bug add a regression test on both sides (Rust unit test in
`rust/attach/src/lib.rs`, Python parity case) before deleting the
artifact.
