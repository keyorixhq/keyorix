# internal/audit/siem invariants

Read this before changing anything in `internal/audit/siem`. This package forwards audit events
to an external SIEM (Splunk HEC, Datadog, generic webhook). Forwarding is asynchronous and
best-effort, but the outbound connection must still be SSRF-safe: its dial-time classifier,
TLS-by-default rule and refuse-redirect policy are the controls.

Format: `INV-SIEM-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-SIEM-<slug>.md`, one per file.
Rules a change in this package must keep. New invariants go in
`INVARIANTS.d/INV-SIEM-<slug>.md` (one per file); see
`docs/invariants-fragments.md`.

Format: `INV-SIEM-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Outbound event formatting
