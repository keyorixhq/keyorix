// Package webauthnrp is the go-webauthn implementation of
// ports.WebAuthnRelyingParty (ADR-036; CORE-DECOUPLE-WEBAUTHN-1). It is a leaf:
// internal/core never imports it, so the library (and go-tpm, cbor, msgp below
// it) stays out of core's production closure. server/wire_webauthn.go builds it
// from the webauthn config block and hands it to KeyorixCore.SetWebAuthn.
//
// It owns only what the library needs: the ceremony options (exclusions and a
// preferred resident key on registration, user verification REQUIRED on every
// assertion), the webauthn.User adapter, and the JSON of credentials and
// sessions, which are the library's own Credential and SessionData structs, so
// stored rows and 5-minute ceremony rows are byte-compatible with what core
// wrote before this package existed. Every decision about what a result means
// (clone detection, lockout, audit) is core's.
package webauthnrp

import (
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// Config is the relying-party identity (the webauthn config block).
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// New builds the relying party. A bad config (no origins, invalid RP ID) is an
// error, so the server fails loud instead of silently disabling passkeys. It
// returns the interface: never a typed nil pointer, which core would take for
// an enabled relying party.
func New(cfg Config) (ports.WebAuthnRelyingParty, error) {
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &relyingParty{rp: rp}, nil
}

// Wrap adapts an already-built library relying party. Wrap(nil) is a nil
// interface (passkeys disabled), never a non-nil interface around nil.
func Wrap(rp *webauthn.WebAuthn) ports.WebAuthnRelyingParty {
	if rp == nil {
		return nil
	}
	return &relyingParty{rp: rp}
}

type relyingParty struct {
	rp *webauthn.WebAuthn
}

var _ ports.WebAuthnRelyingParty = (*relyingParty)(nil)

// The ceremony options core used to pass at each call site. They are fixed
// here, one place per ceremony kind; webauthnrp_test.go pins each of them.
var (
	// Registration asks for a discoverable (resident) credential so the passkey
	// can also be used for passwordless login (ADR-036 addendum). "preferred" is
	// backward-compatible: an authenticator that cannot store a resident key
	// still registers for the second-factor flow.
	registrationResidentKey = protocol.ResidentKeyRequirementPreferred
	// WAUN-001: every assertion (second-factor login, step-up reauth,
	// passwordless) requires user verification (PIN or biometric), not just key
	// presence, so a stolen or found key cannot satisfy it alone.
	assertionUserVerification = protocol.VerificationRequired
)

// user adapts a ports.WebAuthnUser to the library's webauthn.User.
type user struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.displayName }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func toUser(u ports.WebAuthnUser) (*user, error) {
	creds := make([]webauthn.Credential, 0, len(u.Credentials))
	for i, c := range u.Credentials {
		cred, ok := c.(*webauthn.Credential)
		if !ok || cred == nil {
			return nil, fmt.Errorf("webauthnrp: credential %d is %T, not one DecodeCredential returned", i, c)
		}
		creds = append(creds, *cred)
	}
	return &user{id: u.ID, name: u.Name, displayName: u.DisplayName, creds: creds}, nil
}

func toSession(s ports.WebAuthnSession) (webauthn.SessionData, error) {
	sd, ok := s.(*webauthn.SessionData)
	if !ok || sd == nil {
		return webauthn.SessionData{}, fmt.Errorf("webauthnrp: session is %T, not one this relying party returned", s)
	}
	return *sd, nil
}

func verified(cred *webauthn.Credential) ports.WebAuthnVerified {
	return ports.WebAuthnVerified{
		ID:           cred.ID,
		SignCount:    cred.Authenticator.SignCount,
		CloneWarning: cred.Authenticator.CloneWarning,
		Credential:   cred,
	}
}

// DecodeCredential decodes a stored CredentialBlob into the library's
// Credential. The json error is returned unchanged.
func (r *relyingParty) DecodeCredential(blob []byte) (ports.WebAuthnCredential, error) {
	var cred webauthn.Credential
	if err := json.Unmarshal(blob, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// DecodeSession decodes a stored ceremony row into the library's SessionData.
// The json error is returned unchanged.
func (r *relyingParty) DecodeSession(data []byte) (ports.WebAuthnSession, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

func (r *relyingParty) BeginRegistration(u ports.WebAuthnUser) (json.RawMessage, ports.WebAuthnSession, error) {
	wu, err := toUser(u)
	if err != nil {
		return nil, nil, err
	}
	// Exclude already-registered authenticators so the user can't double-register one.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for i := range wu.creds {
		exclusions = append(exclusions, wu.creds[i].Descriptor())
	}
	creation, sd, err := r.rp.BeginRegistration(wu,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(registrationResidentKey),
	)
	if err != nil {
		return nil, nil, err
	}
	options, err := json.Marshal(creation.Response)
	if err != nil {
		return nil, nil, err
	}
	return options, sd, nil
}

func (r *relyingParty) FinishRegistration(u ports.WebAuthnUser, session ports.WebAuthnSession, parsed ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	p, ok := parsed.(*protocol.ParsedCredentialCreationData)
	if !ok {
		return ports.WebAuthnVerified{}, fmt.Errorf("webauthnrp: registration response is %T, not *protocol.ParsedCredentialCreationData", parsed)
	}
	wu, err := toUser(u)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	sd, err := toSession(session)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	cred, err := r.rp.CreateCredential(wu, sd, p)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	return verified(cred), nil
}

func (r *relyingParty) BeginLogin(u ports.WebAuthnUser) (json.RawMessage, ports.WebAuthnSession, error) {
	wu, err := toUser(u)
	if err != nil {
		return nil, nil, err
	}
	assertion, sd, err := r.rp.BeginLogin(wu, webauthn.WithUserVerification(assertionUserVerification))
	if err != nil {
		return nil, nil, err
	}
	options, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, nil, err
	}
	return options, sd, nil
}

func (r *relyingParty) ValidateLogin(u ports.WebAuthnUser, session ports.WebAuthnSession, parsed ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	p, ok := parsed.(*protocol.ParsedCredentialAssertionData)
	if !ok {
		return ports.WebAuthnVerified{}, fmt.Errorf("webauthnrp: assertion response is %T, not *protocol.ParsedCredentialAssertionData", parsed)
	}
	wu, err := toUser(u)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	sd, err := toSession(session)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	cred, err := r.rp.ValidateLogin(wu, sd, p)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	return verified(cred), nil
}

func (r *relyingParty) BeginPasskeyLogin() (json.RawMessage, ports.WebAuthnSession, error) {
	assertion, sd, err := r.rp.BeginDiscoverableLogin(webauthn.WithUserVerification(assertionUserVerification))
	if err != nil {
		return nil, nil, err
	}
	options, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, nil, err
	}
	return options, sd, nil
}

func (r *relyingParty) ValidatePasskeyLogin(resolve func(rawID, userHandle []byte) (ports.WebAuthnUser, error), session ports.WebAuthnSession, parsed ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	p, ok := parsed.(*protocol.ParsedCredentialAssertionData)
	if !ok {
		return ports.WebAuthnVerified{}, fmt.Errorf("webauthnrp: assertion response is %T, not *protocol.ParsedCredentialAssertionData", parsed)
	}
	sd, err := toSession(session)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	// resolve's error goes to the library untouched: the library folds its text
	// into its own error, and core reads what it means from its own closure.
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		pu, err := resolve(rawID, userHandle)
		if err != nil {
			return nil, err
		}
		wu, err := toUser(pu)
		if err != nil {
			return nil, err
		}
		return wu, nil
	}
	_, cred, err := r.rp.ValidatePasskeyLogin(handler, sd, p)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	return verified(cred), nil
}
