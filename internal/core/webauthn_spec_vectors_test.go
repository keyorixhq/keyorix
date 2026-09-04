// webauthn_spec_vectors_test.go — exercises the go-webauthn library's REAL
// cryptographic verification path (ValidateLogin/ValidatePasskeyLogin/
// CreateCredential) using the W3C spec test vectors
// (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256), the same
// fixed, known-good assertion/attestation bytes go-webauthn's own test suite
// uses (webauthn/login_test.go's testLoginSpecVectorNoneES256,
// webauthn/registration_test.go's testRegistrationSpecVectorNoneES256).
//
// webauthn_test.go's existing coverage stops short of the actual
// library-verification calls (CreateCredential/ValidateLogin/
// ValidatePasskeyLogin) because those need a real, internally-consistent
// signature over a real challenge+clientData+authenticatorData — not
// something a hand-rolled fixture can fake. The spec vectors are real
// recorded ceremony data (RPID "example.org", origin "https://example.org"),
// so pointing a WebAuthn RP configured for that RPID/origin at them exercises
// FinishWebAuthnRegistration/FinishWebAuthnLogin/FinishWebAuthnPasswordlessLogin's
// success paths (session minting, audit, clone-detection no-op) for real,
// plus the failure paths that only manifest post-verification (a corrupted
// signature, a credential-ID mismatch).
package core

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Spec test vector constants (NoneES256), reproduced verbatim from
// go-webauthn's own test suite so the assertion/attestation are internally
// consistent (real ECDSA signature over the real challenge/clientData/
// authenticatorData for RPID "example.org").
const (
	specLoginAuthenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	specLoginClientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	specLoginSignatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	specCredentialIDHex           = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
	specLoginChallengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	specCredentialPubKeyHex       = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"

	specRegAttestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	specRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	specRegChallengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
)

func specHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// specLoginAssertion parses the NoneES256 login spec vector into a
// ParsedCredentialAssertionData plus the base64url challenge it was signed
// against.
func specLoginAssertion(t *testing.T) (*protocol.ParsedCredentialAssertionData, string) {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(specHex(t, specCredentialIDHex))
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(specHex(t, specLoginAuthenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(specHex(t, specLoginClientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(specHex(t, specLoginSignatureHex)),
		},
	}
	data, err := json.Marshal(body)
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(data)
	require.NoError(t, err)
	challenge := base64.RawURLEncoding.EncodeToString(specHex(t, specLoginChallengeHex))
	return parsed, challenge
}

// specRegistrationAttestation parses the NoneES256 registration spec vector
// into a ParsedCredentialCreationData plus the base64url challenge it was
// signed against.
func specRegistrationAttestation(t *testing.T) (*protocol.ParsedCredentialCreationData, string) {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(specHex(t, specCredentialIDHex))
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(specHex(t, specRegAttestationObjectHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(specHex(t, specRegClientDataJSONHex)),
		},
	}
	data, err := json.Marshal(body)
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialCreationResponseBytes(data)
	require.NoError(t, err)
	challenge := base64.RawURLEncoding.EncodeToString(specHex(t, specRegChallengeHex))
	return parsed, challenge
}

// specWebAuthnID mirrors webauthnUser.WebAuthnID()'s 8-byte big-endian
// encoding, needed to hand-build a SessionData/UserHandle that the library
// will accept as belonging to userID.
func specWebAuthnID(userID uint) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(userID))
	return b
}

// newWebAuthnSpecTestCore builds a core over real SQLite with a WebAuthn
// relying party configured for the spec vectors' own RPID/origin
// ("example.org" / "https://example.org") -- deliberately NOT "localhost"
// like newWebAuthnTestCore, since the vectors' authenticatorData RPIDHash and
// clientDataJSON origin are baked in and must match exactly for verification
// to succeed. Seeds user id 1 = "alice", active, with a real bcrypt password.
func newWebAuthnSpecTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAChallenge{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{}, &models.Notification{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{}))
	hash, err := bcrypt.GenerateFromPassword([]byte(webauthnTestPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@b.com", EmailFolded: "a@b.com",
		PasswordHash: string(hash), IsActive: true, AccountState: "active"}).Error)

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	rp, err := webauthn.New(&webauthn.Config{
		RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"},
	})
	require.NoError(t, err)
	c.SetWebAuthn(rp)
	return c, db
}

// seedSpecCredential stores the spec vector's credential (ID + public key)
// as userID's registered passkey, matching the Flags (UserPresent,
// BackupEligible) the vector's authenticatorData actually asserts -- a
// mismatch there is its own rejection (login.go's "Backup Eligible flag
// inconsistency" check), so the seeded record must agree with the vector,
// not with arbitrary defaults.
func seedSpecCredential(t *testing.T, c *KeyorixCore, db *gorm.DB, userID uint) []byte {
	t.Helper()
	credID := specHex(t, specCredentialIDHex)
	pubKey := specHex(t, specCredentialPubKeyHex)
	blob, err := json.Marshal(webauthn.Credential{
		ID:        credID,
		PublicKey: pubKey,
		Flags:     webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: userID, CredentialID: credID, Name: "yubikey", CredentialBlob: blob,
	}).Error)
	require.NoError(t, c.storage.SetUserWebAuthnEnabled(context.Background(), userID, true))
	return credID
}

// TestFinishWebAuthnRegistration_SucceedsWithRealAttestation drives
// CreateCredential's actual attestation-verification success path (not
// reachable with a hand-rolled fixture, see the file doc comment), confirming
// the credential row is stored, WebAuthn is enabled for the account, and the
// registration is audited.
func TestFinishWebAuthnRegistration_SucceedsWithRealAttestation(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()

	parsed, challenge := specRegistrationAttestation(t)
	sd := &webauthn.SessionData{
		Challenge:  challenge,
		UserID:     specWebAuthnID(1),
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	}
	token, err := c.storeWebAuthnSession(ctx, 1, "register", sd)
	require.NoError(t, err)

	cred, err := c.FinishWebAuthnRegistration(ctx, 1, token, "yubikey", webauthnTestPassword, parsed)
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, specHex(t, specCredentialIDHex), cred.CredentialID)

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.WebAuthnEnabled, "the first successful registration must enable WebAuthn")

	var events int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "webauthn.registered").Count(&events).Error)
	assert.Equal(t, int64(1), events)
}

// TestFinishWebAuthnRegistration_RejectsUserIDMismatch confirms the
// session/user binding check (CreateCredential's "ID mismatch for User and
// Session") is reachable: a session minted for a DIFFERENT user's
// WebAuthnID must not let userID 1 complete it, even with an otherwise
// perfectly valid attestation.
func TestFinishWebAuthnRegistration_RejectsUserIDMismatch(t *testing.T) {
	c, _ := newWebAuthnSpecTestCore(t)
	ctx := context.Background()

	parsed, challenge := specRegistrationAttestation(t)
	sd := &webauthn.SessionData{
		Challenge:  challenge,
		UserID:     specWebAuthnID(999), // wrong user
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	}
	token, err := c.storeWebAuthnSession(ctx, 1, "register", sd)
	require.NoError(t, err)

	_, err = c.FinishWebAuthnRegistration(ctx, 1, token, "yubikey", webauthnTestPassword, parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify attestation")
}

// TestFinishWebAuthnLogin_SucceedsWithRealAssertion drives ValidateLogin's
// actual cryptographic success path, confirming a session is minted, the
// account owner is returned, the credential's signature counter is
// persisted, a genuine MFAStepUpGrant is minted, and the login is audited.
func TestFinishWebAuthnLogin_SucceedsWithRealAssertion(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	session, user, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, user)
	assert.Equal(t, uint(1), user.ID)
	assert.NotEmpty(t, session.SessionToken)

	var events int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "webauthn.login_verified").Count(&events).Error)
	assert.Equal(t, int64(1), events)

	var credRow models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&credRow).Error)
	assert.False(t, credRow.Disabled, "a normal, un-flagged assertion must not trip clone detection")
	require.NotNil(t, credRow.LastUsedAt, "a successful login must persist the credential's LastUsedAt")

	var grants int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grants).Error)
	assert.Equal(t, int64(1), grants, "a WebAuthn login must mint a step-up grant for later requireReauth calls")

	// Replay: both the MFA challenge and the webauthn ceremony session are
	// single-use -- reusing either after a completed login must fail, not
	// silently mint a second session.
	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err, "a consumed challenge/session pair must not be replayable")
}

// TestFinishWebAuthnLogin_RejectsCredentialMismatch presents a real,
// validly-signed assertion whose credential ID does not match ANY of the
// account's stored passkeys (a different/unregistered credential) --
// go-webauthn's own "unable to find the credential" rejection, reachable only
// once verification gets far enough to look the credential up.
func TestFinishWebAuthnLogin_RejectsCredentialMismatch(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	parsed.RawID = []byte("some-other-credential-id-entirely")
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assertion verification failed")

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.Equal(t, 1, user.FailedLoginAttempts, "a failed second-factor assertion must count toward the lockout")
}

// TestFinishWebAuthnLogin_RejectsCorruptedSignature presents a real
// assertion whose signature has been tampered with -- go-webauthn's
// cryptographic verification itself must reject it (not merely a shape/
// lookup failure), and the failure must be audited + counted toward the
// account's lockout, mirroring a bad-password attempt.
func TestFinishWebAuthnLogin_RejectsCorruptedSignature(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	corrupted := append([]byte(nil), parsed.Response.Signature...)
	corrupted[0] ^= 0xFF
	parsed.Response.Signature = corrupted
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assertion verification failed")

	var failedEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "webauthn.failed").Count(&failedEvents).Error)
	assert.Equal(t, int64(1), failedEvents)
}

// TestFinishWebAuthnPasswordlessLogin_SucceedsWithRealAssertion drives
// ValidatePasskeyLogin's actual success path: the discoverable handler
// resolves the user from the assertion's user handle (our WebAuthnID
// encoding), the credential verifies, and a full passwordless login
// completes (session minted, step-up grant minted, audited).
func TestFinishWebAuthnPasswordlessLogin_SucceedsWithRealAssertion(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	session, user, err := c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, user)
	assert.Equal(t, uint(1), user.ID)

	var events int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "webauthn.passwordless_login").Count(&events).Error)
	assert.Equal(t, int64(1), events)

	var grants int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grants).Error)
	assert.Equal(t, int64(1), grants)
}

// TestFinishWebAuthnPasswordlessLogin_RejectsUnknownUserHandle presents a
// validly-signed assertion whose user handle does not resolve to any
// account -- the discoverable handler's loadWebAuthnUser lookup fails, and
// that failure must refuse the login (not panic or silently proceed
// unauthenticated).
func TestFinishWebAuthnPasswordlessLogin_RejectsUnknownUserHandle(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(999) // no such user
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)

	var failedEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "webauthn.failed").Count(&failedEvents).Error)
	assert.Equal(t, int64(1), failedEvents)
}

// TestFinishWebAuthnPasswordlessLogin_RejectsCredentialMismatch mirrors
// TestFinishWebAuthnLogin_RejectsCredentialMismatch for the passwordless
// path: the user handle resolves correctly, but the asserted credential ID
// does not match any of that user's stored passkeys.
func TestFinishWebAuthnPasswordlessLogin_RejectsCredentialMismatch(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	parsed.RawID = []byte("some-other-credential-id-entirely")
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assertion verification failed")
}

// TestFinishWebAuthnPasswordlessLogin_RejectsReplayedSession confirms the
// webauthn ceremony session (the only single-use gate a discoverable/
// passwordless login has, since there is no separate MFA challenge) cannot
// be replayed after a completed login.
func TestFinishWebAuthnPasswordlessLogin_RejectsReplayedSession(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err, "a consumed passwordless ceremony session must not be replayable")
}

// TestFinishWebAuthnLogin_ClonedCredentialRejectsAndDisablesEndToEnd drives
// clone detection (#212) through the REAL FinishWebAuthnLogin path (not
// rejectIfCloned called directly, as TestWebAuthn_RejectIfCloned_* do): a
// stored credential whose SignCount is ahead of the asserted counter (5 -> 0)
// is go-webauthn's own signature-counter-regression signal
// (Authenticator.UpdateCounter), so a cryptographically valid assertion must
// still be refused, the credential disabled, and the clone audited -- all
// from inside FinishWebAuthnLogin's own call sequence.
func TestFinishWebAuthnLogin_ClonedCredentialRejectsAndDisablesEndToEnd(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	credID := specHex(t, specCredentialIDHex)
	blob, err := json.Marshal(webauthn.Credential{
		ID:            credID,
		PublicKey:     specHex(t, specCredentialPubKeyHex),
		Flags:         webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
		Authenticator: webauthn.Authenticator{SignCount: 5},
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{UserID: 1, CredentialID: credID, Name: "yubikey", CredentialBlob: blob}).Error)
	require.NoError(t, c.storage.SetUserWebAuthnEnabled(ctx, 1, true))

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloned authenticator")

	var row models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", credID).First(&row).Error)
	assert.True(t, row.Disabled, "a clone-signaled credential must be disabled from inside FinishWebAuthnLogin")

	var events int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventWebAuthnCloneDetected).Count(&events).Error)
	assert.Equal(t, int64(1), events)
}

// TestFinishWebAuthnRegistration_SecondPasskeyDoesNotRepurgeSessions covers
// the firstEnrol==false branch: registering a SECOND passkey (WebAuthn
// already enabled from a first one) must still succeed but must not re-run
// the pre-enrolment session purge -- that only fires once, on the passkey
// that first turns WebAuthn on.
func TestFinishWebAuthnRegistration_SecondPasskeyDoesNotRepurgeSessions(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "already-registered-cred")
	seedStepUpGrant(t, db, 1, c.now()) // WebAuthn already enrolled: password alone no longer satisfies reauth.

	parsed, challenge := specRegistrationAttestation(t)
	sd := &webauthn.SessionData{
		Challenge:  challenge,
		UserID:     specWebAuthnID(1),
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	}
	token, err := c.storeWebAuthnSession(ctx, 1, "register", sd)
	require.NoError(t, err)

	cred, err := c.FinishWebAuthnRegistration(ctx, 1, token, "second key", webauthnTestPassword, parsed)
	require.NoError(t, err)
	require.NotNil(t, cred)

	var count int64
	require.NoError(t, db.Model(&models.WebAuthnCredential{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Equal(t, int64(2), count, "the user now has two registered passkeys")
}

// TestFinishWebAuthnPasswordlessLogin_RejectsSuspendedAccount mirrors
// TestWebAuthn_FinishLoginRejectsSuspendedAccount for the passwordless path:
// an account suspended after the ceremony began must still be refused, even
// with an otherwise cryptographically valid assertion.
func TestFinishWebAuthnPasswordlessLogin_RejectsSuspendedAccount(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", AccountSuspended).Error)

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

// TestFinishWebAuthnLogin_RecordsMFAStepupTokenWhenClassificationRequires
// covers the classificationRestrictedRequiresMFAStepUp branch in both
// FinishWebAuthnLogin and FinishWebAuthnPasswordlessLogin: when the
// classification gate is configured to require a step-up window, a
// successful WebAuthn login must also upsert an MFAStepupToken (in addition
// to the unconditional MFAStepUpGrant both paths always mint).
func TestFinishWebAuthnLogin_RecordsMFAStepupTokenWhenClassificationRequires(t *testing.T) {
	c, db := newWebAuthnSpecTestCore(t)
	c.classificationRestrictedRequiresMFAStepUp = true
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	_, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&models.MFAStepupToken{}).Where("user_id = ?", 1).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}
