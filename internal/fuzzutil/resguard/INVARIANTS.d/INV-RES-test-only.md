- **INV-RES-test-only** Nothing outside `*_test.go` imports
  `internal/fuzzutil/resguard`. The package imports `testing` and installs
  process-wide seams (clock, dialer, log meter), so a non-test import would link
  both into a shipped binary.
  Why: it is test-only measurement infrastructure; the walk covers every
  non-test `.go` file in the repository, `operator/` included.
  Guard: `TestResguardImportedOnlyFromTests` in
  `internal/fuzzutil/resguard/importonly_test.go` (skips, rather than passing
  blind, when the repository root cannot be resolved).
