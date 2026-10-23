### Fixed
- **Refused-secret-read summary rows open at shutdown are no longer lost.** A graceful
  stop (SIGTERM) now writes the audit summary row of every refusal-aggregation window
  still open, so the count of refusals after each window's first row is recorded
  instead of dropped (#3377).
