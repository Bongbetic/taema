# Glossary

The shared vocabulary of tæma. Use these terms, exactly as defined here, in issue titles,
commit messages, review comments, documentation, and test names. The definitions follow the
product spec in issue #1 and the committed v2 proposal (`taema-v2.md`); where a paraphrase
differs from those sources, the sources win.

Two companion documents complete the domain docs:

- `docs/adr/` holds the architectural decisions (context, options considered, decision,
  consequences) for storage, collectors, language strategy, Python modernization, IPC,
  desktop stack, and packaging.
- `docs/decisions.md` is the append-only record of product decisions D1 and onward; cite
  its ids (for example "per D12") whenever a change rests on one of them.

The third column lists **synonyms to avoid**. These are words that look interchangeable but
are not: each one either names a different mechanism, has a precise meaning elsewhere in
tæma, or would mislead a reader about what the system actually does. If you need a concept
that is not in this glossary, do not invent a near-synonym — note the gap instead.

## Core lifecycle vocabulary

| Term | Meaning | Synonyms to avoid |
|---|---|---|
| Scope / leaf | A scope (called a leaf in code such as `cgroup.mkleaf`) is one tæma-managed cgroup directory under the delegated user tree `/sys/fs/cgroup/user/<uid>/…` that holds a set of processes; the two words are interchangeable because every scope the daemon manages is a leaf of that hierarchy. | *cgroup* (the kernel mechanism, not the tæma concept), *container* (reserved for podman/docker-class runtimes), *job* (a job is one shell-command lifetime, and only one kind of scope) |
| Member | A member is a process directly or transitively contained in a scope; membership is what the daemon counts, moves, protects, and stops. | *child* (a parent/child relation, which is not containment), *thread* (threads are not counted separately), *process group* (POSIX process groups do not match cgroup membership) |
| Root | The root is the process whose lifetime defines an app scope: when it exits, the scope's close is evaluated and its survivors are handled. | *main process*, *parent*, *session leader* (session-leader is a classification filter, not the definition of a root) |
| Survivor / leftover | A survivor (or leftover) is a member still running after its root or job exited; survivors are contained in a `leftover/` scope and then reviewed, deprioritized, frozen, reclaimed, or stopped through the action ladder. | *orphan* (an orphan is reparented to init; a survivor may have a living parent), *zombie* (a defunct process, unrelated), *stray*, *daemon* |
| Pair | A pair is the `(owner, leftover)` learning record that connects an owner identity to a leftover key; 0.2.x answers attach to pairs, and pairs remain the fallback authority when no signature matches. | *match*, *mapping*, *row* |
| Signature | A signature is the stable fingerprint of a survivor set — sorted resolved member keys and counts, the runtime hash, and the tty flag, excluding pid and start time — so the same survivors match across process instances while a new member key requires review. | *identity* (an app identity is the owner side of a pair, not a survivor set), *hash* or *checksum* (an ingredient of the fingerprint, not the record itself) |
| Provenance | Provenance is the durable ownership history of an application — instances keyed by pid and start time, parent evidence, runtime class, scope, desktop identity, and launch source — retained across restarts so any decision can be explained. | *lineage* (the in-memory process-tree observation implemented by `lineage.py`, not the durable record), *history* (the `history` view is a presentation over retained decisions) |

## Authority, overruling, and review vocabulary

| Term | Meaning | Synonyms to avoid |
|---|---|---|
| Authority | Authority is the permission that lets tæma act on a scope or survivor — an explicit answer, learned evidence, a unit rule, or a manual mode; it is a separate knob from capability (what a mode may do) and from confidence (how strong the evidence is). | *capability*, *confidence*, *trust* |
| Veto | A veto is a hard user-created block that stops tæma from stopping, freezing, or reclaiming a matched object (pid, scope, pair, signature, app, owner, unit, cgroup prefix, or executable path), enforced online and offline until explicitly removed. | *keep* (a learned preference, weaker than a veto), *protected* (config-driven hard safety rules, not a user action), *denylist* or *blocklist* |
| Hold | A hold is a runtime pause of all stops and reclaims that changes neither mode nor profile, while observation, learning, and reviewing continue; a snooze is its timed form and resume ends it. | *mode* (a hold never changes the mode), *mute* (muting affects notifications only), *pause* (too generic; process pausing uses SIGSTOP) |
| Review | A review is a pending close or provenance question queued for the user to answer from the CLI, dashboard, or notifications; an unanswered review expires to keep, never to consent. | *question* (a question is the terminal shell prompt surface, a different channel), *notification* (a notification may deliver a review but is not one), *suggestion* (suggestions are optional improvements applied by id) |

## Action ladder and resource vocabulary

| Term | Meaning | Synonyms to avoid |
|---|---|---|
| Action ladder | The action ladder is the ordered response to a close — contain → deprioritize → freeze → reclaim → stop — that tries reversible stages before destructive ones; only an authorized stop may reach the last stage, and explicit stop answers may skip reversible waiting but never hard safety or probation. | *pipeline*, *workflow*, *state machine* |
| Deprioritize | To deprioritize is to lower a contained scope's competitive position through `cpu.idle`/CPU weight, IO weight, and a raised `oom_score_adj`, without stopping or freezing anything and with the original values retained for undo. | *throttle* (no rate limiting is applied), *nice* (tæma does not set nice values), *suspend* |
| Freeze | To freeze is to set `cgroup.freeze` on an eligible idle scope so its members stop running (historically also called quarantine); thaw reverses it, and eligibility requires sustained idleness with no open window, pty, outside edge, audio/video client, established connection, answered keep/standalone decision, or veto. | *suspend* (host or system suspend), *stop* (the last, irreversible ladder stage), *pause* (process-level SIGSTOP) |
| Wake-on-connect | Wake-on-connect is the rule that a scope with a listening socket may be frozen only if a pending connection thaws it immediately, with accept queues sampled while such scopes exist. | *wake-on-LAN* (a different technique using network magic packets), *auto-thaw*, *keepalive* |
| Windowless | An app is windowless while its root process is alive but its last window has closed; windowless closes keep their close kind and enter the same ladder as other closes, defaulting to ask. | *headless* (a headless install runs without a desktop or agent at all), *minimized*, *trayed* or *hidden* |
| Budget | The budget is the advisory per-user memory pool — 80% of RAM bounded by the delegated-user maximum with a 512 MiB floor — divided into per-scope soft shares; soft shares are not a physical allocation of memory. | *quota*, *hard limit* (`memory.max` is the hard limit and requires explicit unit opt-in) |
| Reclaim | Reclaim returns page cache — and only with additional opt-in, anonymous memory via swap — from a live scope under the reclaim ladder; tæma never transfers physical pages between applications. | *garbage collection*, *OOM kill* (the guard escalates reclaim and freeze long before any authorized stop) |
| Guard | The guard is the pressure-triggered memory-protection ladder that escalates from cache reclaim to eligible freeze to one-at-a-time authorized stops while PSI pressure is high, and that never kills an unlearned scope for pressure relief. | *OOM killer* (the kernel's killer and external handlers such as earlyoom are diagnosed, not owned), *watchdog*, *reclaim* (reclaim is only one stage of the guard's ladder) |

## Desktop integration vocabulary

| Term | Meaning | Synonyms to avoid |
|---|---|---|
| Session agent | The session agent (`taema agent`) is the per-session companion that relays windows, answers, and launches between the desktop and the daemon; it has no decision authority, signals no processes, and keeps no durable policy. | *daemon* (the daemon owns every decision), *service* (it is not a system service), *helper* (the helper is the privileged `taema-attach`) |
| Window backend | A window backend is the compositor adapter that implements the single `WindowBackend` snapshot/events contract and maps window pids to scopes and instances; niri ships first, with sway, i3, and Hyprland behind the same contract as follow-ons. | *compositor* (niri and sway are compositors; the backend is our adapter), *integration*, *driver* |
| Launch-time scoping | Launch-time scoping starts an app inside an already-prepared scope (`taema launch`), moving the process in before exec so containment and provenance begin at birth instead of being adopted later. | *auto-adopt* (adoption observes a process that has already started), *wrapping* (desktop wrapping edits launch entries and is a separate reversible feature) |
| Profile | A profile is a named overlay of configuration keys (`default`, `focus`, `battery`, `game`, `quiet`, `server`, plus user overlays) switched manually or automatically with a logged reason; a profile can never grant authority beyond the mode's and the safety rules' limits. | *mode* (modes are `observe`, `adopt`, `auto`, and `enforce`), *preset*, *theme* |
| Drop-in | A drop-in is a configuration fragment merged after its base config file in lexical order (system layers before user layers), so live configuration changes never rewrite handwritten files. | *override* (environment variables and `TAEMA_CONFIG` replace configuration; drop-ins merge it), *plugin* |

## Platform and delivery vocabulary

| Term | Meaning | Synonyms to avoid |
|---|---|---|
| Eventd | Eventd (`taema-eventd`) is the optional root forwarder that subscribes to netlink process events, filters them by uid, and streams compact records to per-user sockets; it accepts no commands, makes no decisions, and is disabled by default. | *daemon* (it is not a policy daemon — decisions stay with the per-user daemon), *collector* (collectors run inside the daemon) |
| G-Core | G-Core is the data-driven gate, reviewed at the end of M7, that decides whether the daemon core is ported to Rust; it opens only on footprint, latency, defect-rate, or static-binary evidence. | *the rewrite* (the gate may well keep the Python core), *v3*, *migration milestone* |
