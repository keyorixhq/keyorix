### Added

- Fuzzing: an OS-level air-gap / egress harness (`internal/fuzzutil/osairgap`,
  test-only) that runs real Keyorix binaries as a child process inside a fresh
  network namespace (`CLONE_NEWNET`, loopback-only) and proves, at the OS layer,
  that the child makes no egress attempt to anything outside loopback and the one
  configured database endpoint. It complements the in-process resguard `NetMeter`
  (which only sees dials routed through the seam it hands the code under test) and
  the source-level `internal/egressguard` scanner (which cannot see a transitively
  imported library that dials at `init`). Two detectors: netns containment (a
  non-loopback connect fails with `ENETUNREACH`) and attempt detection (a loopback
  canary that the child's proxy env points at, plus `/proc/<pid>/net/*` sampling).
  New fuzz targets `FuzzEgressClassifier` and `FuzzProcNetParser` fuzz the oracle's
  classifier and `/proc/net` decoder.
- Fuzzing: `FuzzAirgapConfigFailClosed` (`internal/config`) fuzzes the air-gap /
  connector configuration surface and asserts fail-closed startup per ADR-109 /
  ADR-082 — connector validation rejects every config `server/wire_connect.go`
  would `log.Fatalf` on, and the air-gapped autocert decision never fails open.
