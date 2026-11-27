### Changed
- The fault-injected-operations fuzz harness now normalises fuzzer-supplied strings (invalid UTF-8, NUL) before seeding Postgres rows, so a raw byte such as `0xad` no longer fails the seeding step before any fault is injected. Test-only; no product code changes.
