### Fixed
- **`verify-release.sh --skip-binaries --assets-dir DIR` no longer fails `release.assets`
  for the binaries it was told to skip (#4269).** The documented air-gapped transfer
  (signed files plus SBOMs, no binaries) ended `release.assets FAIL: 14 missing ... of 32
  expected assets` and `RESULT: FAILED - do not deploy`, while the same flags online
  passed that check and ended INCOMPLETE (exit 2). With `--skip-binaries` and a directory,
  the 14 binaries are now not required; an unknown file in the directory, a missing SBOM,
  an SBOM or `checksums.txt` that does not match, still FAIL. The self-test gains the
  offline flag matrix, the negative cases and a check that the 32 expected names equal
  what `make -n release` and `release.yml` emit.
