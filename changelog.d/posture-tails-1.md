### Security
- **`admin validate --posture` no longer overstates the integrity tier.** A release-manifest match whose signature is not verified (any `checksums.txt.sig`, `.sigstore.json` or `.bundle` file, even empty, unlocked the comparison) now prints `ok (signature not verified)` and does not count toward tier 3, which is fs-verity only. `tpm-sealing` prints `ok (weaker fallback configured: <kind>)` and does not count toward tier 5 when a fallback weaker than a TPM is configured. Guarded by `internal/integrity` and `server/admin` tests; see `docs/security/integrity-posture.md`.

### Fixed
- **A FIFO can no longer hang `admin validate --posture`.** The integrity checks open `checksums.txt`, the running binary and the `/sys` and `/proc` sources through `secretenv.OpenRegular`; a FIFO at one of those paths reports `unknown` instead of blocking.
