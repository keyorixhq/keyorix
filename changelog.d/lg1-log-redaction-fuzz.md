### Testing
- **Added `FuzzLogRedaction` (internal/logging), the package's first fuzz
  target.** Drives the real logger configuration (`logging.Setup` in text and
  json modes over the standard `log` package) with per-family secret canaries
  and with newline/ANSI/control-character log-injection payloads. Metamorphic
  oracles: recognisable secrets are removed by `Redact` and never survive the
  `Event()` path in either format (format independence), `Redact` is idempotent
  over arbitrary input, and log injection cannot forge a JSON record or a text
  line through the sanitised fields. Metered with the shared `resguard` layer
  (`log_bytes`/`alloc` ceiling, advisory `wall`/`cpu` for regex ReDoS). Red/green
  proofs and characterization tests for the redaction behaviour are committed
  alongside.
