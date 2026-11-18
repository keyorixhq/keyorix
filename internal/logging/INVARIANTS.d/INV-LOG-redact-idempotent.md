- **INV-LOG-redact-idempotent** `Redact(Redact(s)) == Redact(s)` for every input
  `s`: a second pass is a no-op. Each regex replacement guards against re-matching
  its own `[REDACTED]`/`kx_[REDACTED]` output (the `reKV` already-redacted guard,
  the bearer short-token heuristic), so redaction is a stable projection. Why: log
  pipelines and the `jsonWriter` can re-scan already-scrubbed text; a non-idempotent
  scrubber would corrupt lines or loop. Guard: `FuzzLogRedaction` oracle O2 (over
  arbitrary fuzzer bytes and over every secret-bearing payload) in
  `internal/logging/redaction_fuzz_test.go`.
