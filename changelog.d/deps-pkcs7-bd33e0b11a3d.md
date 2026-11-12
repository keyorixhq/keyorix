### Security
- **`github.com/digitorus/pkcs7` updated to `v0.0.0-20261104113855-bd33e0b11a3d`.** Picks up the
  upstream CBC decryption padding fix (GHSA-cj86-7jch-72f4, PR #25). Keyorix does not call the
  decrypt path (`internal/notary` only parses and verifies), so this is not reachable from the
  server; the update keeps scanners quiet and the dependency current. The earlier BER fixes
  (GHSA-3xqc-rpq8-wgp9, GHSA-73j8-gqc5-c98v) were already in the previous pin.
