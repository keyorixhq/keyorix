# internal/notifychan invariants

Read this before changing anything in `internal/notifychan`. This package delivers notification
and chat (Slack/Teams) webhooks. The webhook URL is often itself the bearer credential, so the
outbound connection must be SSRF-safe and must not leak the URL: its dial-time classifier,
https-by-default rule, refuse-redirect policy and URL redaction are the controls.

Format: `INV-NOTIFYCHAN-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-NOTIFYCHAN-<slug>.md`, one per file.
