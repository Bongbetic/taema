# ADR-0005: IPC protocol v2 with versioned envelopes and streaming

- Status: Accepted
- Date: 2026-10-19
- Source: spec issue #1 §9; `taema-v2.md` §11.7
- Related decisions: D12, D15 (Rust clients and the widget consume the same protocol)

## Context

The 0.2.1 IPC is one unversioned JSON object per line over an `AF_UNIX` socket with a
`SO_PEERCRED` uid check, one reply per connection, and 64 KiB / 0.5 second request bounds.
There is no envelope, no version, and no correlation id, so replies cannot be matched to
streamed events, errors are ad-hoc `{"error": …}` strings, and Rust clients have no typed
contract to mirror. The v2 line needs streaming subscriptions with replay, structured
error codes the CLI can map to exit codes, decision ids on mutating replies, agent
messages with nonces, and a compatibility window so shell hooks written against v1 keep
working through the upgrade.

## Options considered

| Option | Assessment |
|---|---|
| Keep unversioned v1 as is | Rejected: no correlation, no streaming, no structured errors, and no contract to test or mirror in Rust. |
| varlink | Rejected: no Void library for it and a small ecosystem around it. |
| A D-Bus service for the daemon | Rejected: the daemon deliberately stays off the session bus; session concerns belong to the agent. |
| gRPC | Rejected: heavyweight toolchain and runtime for a same-machine, same-uid socket. |
| **JSON envelope v2 over the existing `AF_UNIX` socket** | **Accepted:** keeps the proven transport and peer checks, adds versioning, correlation, structured errors, and streaming with plain line framing. |

## Decision

- JSON over `AF_UNIX` with `SO_PEERCRED` same-uid checks stays; request bounds stay at
  64 KiB and 0.5 seconds, and invalid types, bounds, or unknown fields are rejected without
  crash or mutation.
- Requests use the envelope `{"v":2,"id":N,"cmd":…,"args":{…}}`; replies are
  `{"v":2,"id":N,"ok":true,"result":…}` or
  `{"v":2,"id":N,"ok":false,"error":{"code":…,"message":…,"hint":…}}`.
- `subscribe` keeps the connection open and pushes
  `{"v":2,"id":N,"seq":S,"event":…,"data":…}` lines with a durable monotonic sequence;
  clients resume from `seq`, replaying at most 1,000 missed events before resyncing from a
  snapshot. At most 16 subscribers with 4,096 queued events each; slow consumers are
  disconnected rather than blocking the daemon.
- Payload schemas live in `schema/ipc/*.json`; tests validate them and the Rust clients
  mirror them with serde types.
- Mutating replies carry the decision id plus mode and authority, so clients and the audit
  trail can be correlated. Agent messages require registered same-uid connections, and
  answers require a valid, unexpired, unused nonce.
- Unversioned v1 messages (no `v` field) are accepted for one release so existing shell
  hooks upgrade gradually.

## Consequences

- Old hooks and clients keep working during the compatibility window, but the daemon must
  maintain two request paths until that window closes.
- Schema files become a versioned contract: schema changes need tests, release notes, and
  Rust mirror updates in the same change.
- Structured error codes let the CLI implement its exit-code scheme (0/1/2/3/4) without
  parsing prose, and decision ids make replies auditable.
- Streaming introduces sequence, replay, and slow-consumer behavior that must be tested
  (resume, resync, caps), adding protocol complexity that v1 never had.
- The same-uid security boundary is unchanged: versioning adds no new trust surface, and
  nonce validation protects the new answer paths.
