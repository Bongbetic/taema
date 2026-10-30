taema-learning(7)

# NAME

taema-learning - learning, provenance, review, and recovery

# DESCRIPTION

Tæma records validated application identities, owner-to-survivor pairs, stable
survivor signatures, reviews, vetoes, and retained action outcomes in a
per-user SQLite database. The daemon remains the single writer; CLI views open
the database read-only while it runs. The audit log records decisions and
their authorization reasons.

A pair connects one application identity (the owner) with one survivor key. A
signature describes a survivor set by its sorted member keys and counts,
runtime-directory hash, terminal state, and owner. Process IDs and start times
do not affect a signature. An explicit signature answer applies to an
identical relaunched survivor set; a changed set is reviewed and cannot inherit
authority for a new member.

# INSPECTING LEARNING

*taema learn show*
	Show a summary of apps, pairs, and signatures.

*taema learn apps*
	List validated application identities and retained evidence.

*taema learn pairs*
	List learned owner-to-survivor decisions, confidence, counts, and reasons.

*taema learn signatures*
	List survivor signatures, explicit answers, and stop outcomes.

*taema learn show --legacy*
	List quarantined legacy answers that need confirmation.

*taema why TARGET*
	Explain provenance, evidence, matching signatures, vetoes, and possible
	actions.

# ANSWERING AND OVERRULING

*taema review*
	List pending close and provenance reviews.

*taema answer ID CHOICE*
	Answer a review with *stop*, *keep*, *standalone*, or *never*.

*taema teach OWNER SURVIVOR CHOICE*
	Record an explicit pair answer without waiting for a review.

*taema do-not-kill TARGET*
	Create a durable veto. Pending vetoes are enforced while the daemon is
	down.

*taema undo [ID]*
	Reverse a retained automatic action. Undoing a stop adds keep evidence
	and a veto, clears pending stop state, and suspends matching automatic
	authority during the regret interval.

*taema forget --all APP*
	Remove an app's learned records while retaining its vetoes.

# AUTOMATIC OUTCOMES

The learner records successful stops, respawns, and regret against the
matching pair and signature. Regret means the same pair or signature returned
during its configured window; it adds keep evidence and suspends automatic
authority. Outcomes do not override hard protection, dependencies, holds, or
vetoes. Self-derived stop authority is disabled by default.

# STORAGE AND MIGRATION

The default state directory is _$XDG_STATE_HOME/taema_ or
_~/.local/state/taema_. It holds *state.db*, the append-only
*decisions.log*, and pending offline feedback. Database files are private to
the user. On the first 0.4.0 start, valid 0.3.0 JSON learning is imported
transactionally; invalid-owner answers become reviews. The importer keeps the
source and creates a mode-0600 *knowledge.json.backup-\** file before
committing. Migration does not stop processes. See
_/usr/share/doc/taema/legacy-state-migration.md_ and
_/usr/share/doc/taema/state-schema.md_ for upgrade and schema details.

To prepare a downgrade to 0.2, export the compatible JSON format before
stopping the daemon:

	*taema learn export --format v2 --output "$HOME/taema-knowledge-v2.json"*

Keep the SQLite database and its sidecars as a rollback copy. The migration
guide describes how to restore the exported file for a 0.2 downgrade.

# FILES

_~/.local/state/taema/state.db_
	SQLite learning, provenance, review, veto, and decision state.

_~/.local/state/taema/decisions.log_
	Human-readable JSON Lines audit events.

_~/.local/state/taema/knowledge.json.backup-\*_
	Private source backup retained for 30 days after legacy import.

# SEE ALSO

*taema*(1), *taema.unit*(5)
