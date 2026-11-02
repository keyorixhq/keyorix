### Added

- `admin validate --posture` prints advisory, self-reported host integrity lines (POSTURE-INTEG-1, RD-INTEG-POSTURE-1 / RD-TIER-POSTURE-1): Secure Boot, kernel lockdown, IMA policy, fs-verity on the running binary, the binary's SHA-256 against a locally shipped release manifest, TPM sealing state and Keylime agent presence, plus a detected integrity tier 0 to 6. Every line is labelled "advisory (self-reported)", an unreadable source is "unknown", and none of it affects `/health`, startup or the exit code. See `docs/security/integrity-posture.md`.
