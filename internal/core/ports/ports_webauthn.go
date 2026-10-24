// ports_webauthn.go — the WebAuthn relying-party seam (ADR-036 behind an
// ADR-109-style port; CORE-DECOUPLE-WEBAUTHN-1). internal/core used to import
// github.com/go-webauthn/webauthn directly, which brought go-tpm, cbor and msgp
// (about 20 MB of compiled packages) into every package that imports core. The
// library now lives in internal/webauthnrp, wired from server/wire_webauthn.go.
//
// The port is the relying party's cryptography and encoding ONLY. Every
// security decision stays in internal/core: consume-first ordering, the
// account and lockout gates, clone detection (rejectIfCloned reads
// WebAuthnVerified.CloneWarning), counter persistence, step-up grants and the
// audit trail. That is why this is not "a WebAuthn service": moving a
// ceremony out of core would move those decisions with it.
//
// Every value the library owns crosses this boundary as an opaque `any`
// (WebAuthnParsed, WebAuthnCredential, WebAuthnSession). Core never looks
// inside them; it hands them back to the relying party, and it json-encodes
// credentials and sessions itself with encoding/json, so stored rows keep the
// exact bytes the library's own structs marshal to.
package ports

import "encoding/json"

// WebAuthnParsed is a ceremony response the transport has already parsed (the
// HTTP handlers parse before reserving a login-attempt slot, F2 ordering). In
// the real adapter it is a *protocol.ParsedCredentialCreationData
// (registration) or *protocol.ParsedCredentialAssertionData (login, reauth,
// passwordless); the adapter refuses anything else.
type WebAuthnParsed any

// WebAuthnCredential is one stored credential decoded by DecodeCredential
// (a *webauthn.Credential in the real adapter). json.Marshal of it gives the
// stored CredentialBlob bytes.
type WebAuthnCredential any

// WebAuthnSession is the in-flight ceremony state a Begin returns and
// DecodeSession reads back (a *webauthn.SessionData in the real adapter).
// json.Marshal of it gives the stored WebAuthnSession.Data bytes.
type WebAuthnSession any

// WebAuthnUser is the account a ceremony runs for.
type WebAuthnUser struct {
	// ID is the user handle stored on the authenticator: the 8-byte big-endian
	// user id, never PII.
	ID          []byte
	Name        string
	DisplayName string
	// Credentials are the usable (not clone-disabled, decodable) credentials,
	// already filtered by core. Registration excludes them; login offers them.
	Credentials []WebAuthnCredential
}

// WebAuthnVerified is everything core needs about a credential the relying
// party just verified (registration) or validated (login).
type WebAuthnVerified struct {
	// ID is the credential id (the indexed CredentialID column).
	ID []byte
	// SignCount is the authenticator's signature counter after this ceremony.
	SignCount uint32
	// CloneWarning is the library's signature-counter regression signal
	// (Authenticator.CloneWarning). Core refuses the login and disables the
	// credential when it is set (rejectIfCloned, #212).
	CloneWarning bool
	// Credential is the updated credential; json.Marshal of it is the blob core
	// persists (CreateWebAuthnCredential, AdvanceWebAuthnCredentialCounter).
	Credential WebAuthnCredential
}

// WebAuthnRelyingParty runs the relying-party side of the WebAuthn ceremonies.
// A nil WebAuthnRelyingParty means passkeys are disabled (core returns
// ErrWebAuthnDisabled). Options are the JSON of the publicKey member of the
// navigator.credentials.create/get options, as the transport sends them.
type WebAuthnRelyingParty interface {
	// DecodeCredential decodes a stored CredentialBlob. An error means the row
	// is unreadable; core skips it, as it always has.
	DecodeCredential(blob []byte) (WebAuthnCredential, error)
	// DecodeSession decodes a stored ceremony row's Data.
	DecodeSession(data []byte) (WebAuthnSession, error)

	// BeginRegistration starts enrolment. The adapter excludes u.Credentials
	// and asks for a discoverable credential (resident key preferred).
	BeginRegistration(u WebAuthnUser) (options json.RawMessage, session WebAuthnSession, err error)
	// FinishRegistration verifies the attestation against session.
	FinishRegistration(u WebAuthnUser, session WebAuthnSession, parsed WebAuthnParsed) (WebAuthnVerified, error)

	// BeginLogin starts an assertion for a known user (second-factor login and
	// step-up reauth). The adapter requires user verification.
	BeginLogin(u WebAuthnUser) (options json.RawMessage, session WebAuthnSession, err error)
	// ValidateLogin validates the assertion against u's credentials.
	ValidateLogin(u WebAuthnUser, session WebAuthnSession, parsed WebAuthnParsed) (WebAuthnVerified, error)

	// BeginPasskeyLogin starts a discoverable (usernameless) assertion. The
	// adapter requires user verification.
	BeginPasskeyLogin() (options json.RawMessage, session WebAuthnSession, err error)
	// ValidatePasskeyLogin validates a discoverable assertion. resolve maps the
	// assertion's raw credential id and user handle to the account (core's
	// closure: it decides what a bad handle or a storage failure means); its
	// error is returned inside the relying party's own error.
	ValidatePasskeyLogin(resolve func(rawID, userHandle []byte) (WebAuthnUser, error), session WebAuthnSession, parsed WebAuthnParsed) (WebAuthnVerified, error)
}
