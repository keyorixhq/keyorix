### Documentation

- The air-gap design note and the `RefWithinPrefix` doc comments now say what the code does: the evidence-pack and audit-checkpoint HMAC keys are derived from the KEK (not the DEK), and an empty reference prefix matches an empty or `/`-led reference rather than "nothing" (callers skip it first). The hardening guide's backup section now lists the refusal of `admin backup` on a database upgraded in place from v0.95.x until the new server has started once, on both SQLite and PostgreSQL.
