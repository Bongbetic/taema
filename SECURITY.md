# Security policy

## Reporting a vulnerability

taema runs a privileged helper (`libexec/taema-attach`, with its Rust
implementation in `taema/rust/attach`). If you find a way to escape a
scope, escalate privilege through the helper, or crash it, please tell
us privately before disclosing it anywhere else:

- Email: <soubarna@live.in>, or
- GitHub: use **Report a vulnerability** on the
  [Bongbetic/taema security tab](https://github.com/Bongbetic/taema/security).

Say what you ran, what you expected, and what happened; a reproducer
(a command line, a rules file, or a fuzzer input) cuts triage time to
near zero. We will confirm receipt, fix the issue, and credit you in
the release notes unless you ask us not to.

## What counts as the privilege boundary

The privilege boundary is the argument and request parsing plus the
file trust checks of the privileged helper: `parse_op`, `parse_rules`,
and `parse_oom_record` in `taema/rust/attach/src/lib.rs`, and the
matching Python fallback in `libexec/taema-attach.py`. Anything that
lets an unprivileged caller cross that boundary — a parse/execution
split, a trust check bypass, a panic that kills the helper — is a
security bug, not a normal bug.

## Release notes

Release notes must call out every fix to the privilege boundary: what
the flaw allowed, which versions are affected, and which release closes
it. Fixes elsewhere need no special marking.
