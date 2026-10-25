# Formal models

TLA+ models of Keyorix protocols, checked with TLC. They are R&D artefacts:
not run by CI, and each model's README says what it covers and what it does not.

| Model | What | Run |
|---|---|---|
| [`owed-audit/`](owed-audit/README.md) | revocations, grants, the mixed-request split, break-glass and the owed-audit backfill while the audit log refuses writes (ADR-112 Amendment 6) | `docs/formal/owed-audit/run-tlc.sh` |
