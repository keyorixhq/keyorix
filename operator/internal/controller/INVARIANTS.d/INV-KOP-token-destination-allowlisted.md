- **INV-KOP-token-destination-allowlisted** The machine-identity bearer token is only
  ever sent to a destination whose scheme is `https` and whose host matches the
  operator's `--allowed-servers` allow-list; an empty allow-list rejects every CR (fail
  closed). A CR author controls `spec.server`, so without this the operator would ship a
  namespace Secret's bytes (the token) to an attacker-chosen host — the confused-deputy
  exfiltration primitive. The accept decision must be derived from the destination
  net/http actually dials (`net/url` Scheme+Host), not from the raw string, so a
  `user@host` / backslash / embedded-credential URL cannot smuggle a dialled host past
  the check. Why: `validateServer` (`keyorixsecret_controller.go`), the
  `AllowedServers` doc comment. Guard: `FuzzValidateServer` and `TestValidateServer`
  (`operator/internal/controller`); the client-side mirror is
  `FuzzValidateClientBaseURL` (`operator/internal/keyorix`).
