### Testing
- **Hardened four fuzz oracles against their measured mutation-survivors.** The
  `oraclehealth` mutation harness found oracle holes in `FuzzIPv4EmbeddingSSRFParity`
  (SSRF encoding parity), `FuzzAEADTamperRoundTrip` (AEAD tamper detection),
  `FuzzComponentPathContainment` (bundle path containment) and `FuzzOIDCVerifierClaims`
  (OIDC claim validation). The parity oracle now also exercises the Teredo, 6to4 and
  local-use-NAT64 IPv6 encodings; the AEAD oracle now asserts that a wiped DEK refuses
  every encrypt/decrypt operation; the containment oracle now asserts the accept (liveness)
  direction for a fixed set of always-benign names; the OIDC oracle now pins the accept
  direction and the crit-header and multi-audience/azp paths. No production code changed.
- **Made the oracle-health measurement repeatable.** `tools/oraclehealth` gained an
  equivalent/dead-mutant allowlist, and `scripts/fuzzing/oracle-health.sh` runs the harness
  over a fixed target list against a committed per-target kill-rate baseline, failing when a
  target regresses below its baseline (minus a tolerance) or a baseline target goes missing.
