### Testing
- **Reachability-first third-party fuzzing (`scripts/fuzzing/reachgen`).** New
  offline, read-only tool that enumerates the exported third-party functions
  Keyorix actually calls with attacker/operator-influenced arguments
  (go/packages + a lightweight provenance taint), ranks the uncovered ones, and
  emits draft fuzz skeletons for the fuzzable leads. Ships the Phase-0 ranked
  top-40 (`scripts/fuzzing/reachgen/RANKED-TOP40.md`) and unit tests on an
  offline fixture module.
- **Five promoted third-party fuzz targets with sound oracles**, each traced to
  a live Keyorix caller and red-proofed: `precis.Profile.String` idempotence
  (identity name normalization), `bcrypt` round-trip + fail-closed + cost-bomb
  bound (login), `ssh.ParseAuthorizedKey` round-trip stability (admin
  recovery-key recipient), `webauthncose.ParsePublicKey` bounded-work
  (WebAuthn COSE classify), and `go.yaml.in/yaml/v4` bounded-work/anti-alias-bomb
  (config + credstore). Targets live under `fuzz/thirdparty/`. The precis, ssh
  and webauthn targets are direct library-level complements to existing
  Keyorix-level targets (`internal/identity` fold oracles,
  `server/admin` recovery-key recipient, `internal/libconformance` COSE key).
