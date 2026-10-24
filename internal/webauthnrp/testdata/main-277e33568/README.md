Rows written by main at 277e33568 (before internal/webauthnrp existed), through
its real code paths with the W3C NoneES256 spec-vector relying party
(RPID example.org):

- `session-register.json`, `session-login.json`, `session-reauth.json`,
  `session-passwordless.json`: `WebAuthnSession.Data` as stored by
  `BeginWebAuthnRegistration`, `BeginWebAuthnLogin`, `BeginWebAuthnReauth`,
  `BeginWebAuthnPasswordlessLogin`.
- `credential-registered.json`: `WebAuthnCredential.CredentialBlob` as stored by
  `FinishWebAuthnRegistration` (spec attestation).
- `credential-after-login.json`: the same blob as rewritten by
  `persistUpdatedCredential` after `FinishWebAuthnLogin` (spec assertion).

`TestGolden_MainRowsRoundTripByteIdentical` decodes each through the adapter and
requires `json.Marshal` of the result (what core stores) to reproduce these
bytes exactly. Do not regenerate them from a newer tree: their point is that
they predate the adapter.
