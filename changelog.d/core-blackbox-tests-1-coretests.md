### Internal

- 40 black-box test files moved out of `internal/core` into the new test-only package `internal/core/coretests` (ADR-121 decision 2, wave 1): they use only core's exported API and the `storagetest` kit, so editing them no longer rebuilds the `internal/core` test binary and editing core no longer reruns them in that binary. Test code only; no production file changed.
