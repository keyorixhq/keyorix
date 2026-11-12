# internal/evidencesink invariants

Read this before changing anything in `internal/evidencesink`. This package delivers the
scheduled compliance-evidence pack off-box — a webhook POST (bearer token + full pack) and an
object-store sink. The webhook path must not be turned into an SSRF/exfil channel: its
dial-time classifier, https-by-default rule and refuse-redirect policy are the controls.

Format: `INV-EVIDENCESINK-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-EVIDENCESINK-<slug>.md`, one per file.
