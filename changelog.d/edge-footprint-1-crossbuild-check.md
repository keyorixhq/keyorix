### Testing
- **ARM static-binary guard.** `scripts/edge/crossbuild-check.sh` builds the server and the CLI for `linux/arm64` and `linux/arm` (armv7) with `CGO_ENABLED=0` and fails if a non-stdlib dependency imports `"C"` or the result is not a static pure-Go build. `--self-test` proves it fails on a cgo package. Cross-compile only; running on ARM hardware is not covered.

### Documentation
- **Footprint and architectures.** The edge guide has a short section naming the four scripts that guard cgo-freedom, ARM cross-builds and footprint ceilings, what each checks, and how to run them.
