### Testing
- **ML-KEM-1024 decrypt path fuzz harness.** `FuzzPKCS7DecryptMLKEM1024` in
  `internal/libconformance` covers the ML-KEM-1024 decapsulation branch of
  `(*PKCS7).Decrypt` (LS6 follow-on to LS3's ML-KEM-768 harness; same
  `kem.go` code path, different key size). Positive-control check ensures
  the ML-KEM-1024 path is live before fuzzing starts.
- **pkcs7 pilot fuzz targets registered.** All 15 `FuzzXxx` functions from
  the LS2–LS6 pkcs7 pilot (`internal/libconformance`) now have entries in
  `scripts/fuzzing/targets.d/`; `scripts/fuzzing/targets.conf` regenerated.
  Previously none of the LS2–LS5 targets had been registered (pilot sessions
  were `--not-pushed`), which would have failed the `fuzz-targets` CI job on
  merge.
