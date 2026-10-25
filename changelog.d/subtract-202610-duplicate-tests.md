### Testing
- **Removed 63 Go tests that duplicated another test in the same package line for line,** plus one test that only skipped, for a reason that no longer holds (SearchUsers on SQLite). The copy that stays is in the descriptively named file or the earlier coverage wave. Tests cited by security closures or INVARIANTS docs were kept even when duplicated.
