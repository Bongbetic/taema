# 0.3.0

## Behaviour changes

### adopt now contains and asks

In `adopt`, a GUI app's surviving processes now move into a dedicated `leftover/` scope
when its root exits, and tæma queues a review so you can decide what should happen next.
An unanswered review keeps the leftover. `taema run --bind` honors the explicit owner
binding by stopping its scope when the command exits, with the same safety and veto checks
as other stops. In `auto`, unlearned leftovers are kept for review, while eligible idle
runtime scopes whose configured runtime directory disappeared can be collected after the
usual safety checks. `observe` continues to report would-actions without moving or stopping
processes.
