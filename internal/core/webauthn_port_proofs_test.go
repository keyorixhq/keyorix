// webauthn_port_proofs_test.go — CORE-DECOUPLE-WEBAUTHN-1: the security
// decisions that stayed in core still hold when the relying party is reached
// through ports.WebAuthnRelyingParty (internal/webauthnrp), driven with the W3C
// spec vectors through the real adapter. Each proof has a mutation half: a
// decorator around the real adapter that models a plausible adapter bug, and
// the same scenario must then come out differently, so the scenario is shown
// to depend on what the adapter hands core.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/webauthnrp"
)

// --- adapter bugs, modelled -------------------------------------------------

// dropCloneWarning is an adapter that forgets to carry the library's
// Authenticator.CloneWarning into WebAuthnVerified.
type dropCloneWarning struct{ ports.WebAuthnRelyingParty }

func (d dropCloneWarning) ValidateLogin(u ports.WebAuthnUser, s ports.WebAuthnSession, p ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	v, err := d.WebAuthnRelyingParty.ValidateLogin(u, s, p)
	v.CloneWarning = false
	return v, err
}

func (d dropCloneWarning) ValidatePasskeyLogin(r func(rawID, userHandle []byte) (ports.WebAuthnUser, error), s ports.WebAuthnSession, p ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	v, err := d.WebAuthnRelyingParty.ValidatePasskeyLogin(r, s, p)
	v.CloneWarning = false
	return v, err
}

// uvPreferred is an adapter whose assertion ceremonies ask for user
// verification "preferred" instead of "required".
type uvPreferred struct{ ports.WebAuthnRelyingParty }

func preferUV(s ports.WebAuthnSession) ports.WebAuthnSession {
	sd := *s.(*webauthn.SessionData)
	sd.UserVerification = protocol.VerificationPreferred
	return &sd
}

func (d uvPreferred) BeginLogin(u ports.WebAuthnUser) (json.RawMessage, ports.WebAuthnSession, error) {
	o, s, err := d.WebAuthnRelyingParty.BeginLogin(u)
	return o, preferUV(s), err
}

func (d uvPreferred) BeginPasskeyLogin() (json.RawMessage, ports.WebAuthnSession, error) {
	o, s, err := d.WebAuthnRelyingParty.BeginPasskeyLogin()
	return o, preferUV(s), err
}

// bypassResolve is an adapter that resolves the passkey's user itself instead
// of through core's callback (here: to nobody), so core never learns why the
// lookup failed.
type bypassResolve struct{ ports.WebAuthnRelyingParty }

func (d bypassResolve) ValidatePasskeyLogin(_ func(rawID, userHandle []byte) (ports.WebAuthnUser, error), s ports.WebAuthnSession, p ports.WebAuthnParsed) (ports.WebAuthnVerified, error) {
	return d.WebAuthnRelyingParty.ValidatePasskeyLogin(func(_, h []byte) (ports.WebAuthnUser, error) {
		return ports.WebAuthnUser{ID: h}, nil
	}, s, p)
}

func countWhere(t *testing.T, db *gorm.DB, model any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(model).Where(query, args...).Count(&n).Error)
	return n
}

// --- (a) clone detection through the adapter --------------------------------

type cloneOutcome struct {
	err         error
	disabled    bool
	cloneAudits int64
	sessions    int64
}

// runClonedLogin stores the spec credential with signature counter 5 and
// presents the real spec assertion (counter 0) on the given path, with the
// relying party the core was built with, optionally decorated.
func runClonedLogin(t *testing.T, passwordless bool, decorate func(ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty) cloneOutcome {
	t.Helper()
	c, db := newWebAuthnSpecTestCore(t)
	c.SetWebAuthn(decorate(c.webauthnRP))
	ctx := context.Background()
	credID := specHex(t, specCredentialIDHex)
	blob, err := json.Marshal(webauthn.Credential{
		ID: credID, PublicKey: specHex(t, specCredentialPubKeyHex),
		Flags:         webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
		Authenticator: webauthn.Authenticator{SignCount: 5},
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{UserID: 1, CredentialID: credID, Name: "yubikey", CredentialBlob: blob}).Error)
	require.NoError(t, c.storage.SetUserWebAuthnEnabled(ctx, 1, true))

	parsed, challenge := specLoginAssertion(t)
	var out cloneOutcome
	if passwordless {
		parsed.Response.UserHandle = specWebAuthnID(1)
		token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
		require.NoError(t, err)
		_, _, _, out.err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "ua", "203.0.113.5", parsed)
	} else {
		ch, err := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, err)
		token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
		require.NoError(t, err)
		_, _, _, out.err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "203.0.113.5", parsed)
	}
	var row models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", credID).First(&row).Error)
	out.disabled = row.Disabled
	out.cloneAudits = countWhere(t, db, &models.AuditEvent{}, "event_type = ?", EventWebAuthnCloneDetected)
	out.sessions = countWhere(t, db, &models.Session{}, "user_id = ?", 1)
	return out
}

// TestCloneDetection_ThroughAdapter_RedWhenFlagDropped (proof a): a real
// assertion with a regressed signature counter, through the real adapter, is
// refused on both login paths with the credential disabled, the clone audited
// and no session. With an adapter that drops the flag the same ceremony mints
// a session and leaves the credential usable.
func TestCloneDetection_ThroughAdapter_RedWhenFlagDropped(t *testing.T) {
	t.Parallel()
	same := func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return rp }
	drop := func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return dropCloneWarning{rp} }
	for _, passwordless := range []bool{false, true} {
		got := runClonedLogin(t, passwordless, same)
		require.Error(t, got.err, "passwordless=%v: a regressed counter must refuse the login", passwordless)
		assert.Contains(t, got.err.Error(), "cloned authenticator")
		assert.True(t, got.disabled, "passwordless=%v: the credential must be disabled", passwordless)
		assert.Equal(t, int64(1), got.cloneAudits, "passwordless=%v: the clone must be audited", passwordless)
		assert.Zero(t, got.sessions, "passwordless=%v: no session on a clone signal", passwordless)

		mut := runClonedLogin(t, passwordless, drop)
		require.NoError(t, mut.err, "passwordless=%v: mutation: with the flag dropped the clone logs in (else this scenario does not exercise the flag)", passwordless)
		assert.False(t, mut.disabled)
		assert.Zero(t, mut.cloneAudits)
		assert.Equal(t, int64(1), mut.sessions)
		t.Logf("passwordless=%v real adapter: err=%q disabled=%v audits=%d sessions=%d; flag dropped: err=%v disabled=%v audits=%d sessions=%d",
			passwordless, got.err, got.disabled, got.cloneAudits, got.sessions, mut.err, mut.disabled, mut.cloneAudits, mut.sessions)
	}
}

// --- (b) user verification required, end to end ----------------------------

// pointRowAtSpecChallenge rewrites the stored ceremony row's challenge to the
// one the spec vector was signed over; every other member (UV included) stays
// as the relying party wrote it.
func pointRowAtSpecChallenge(t *testing.T, db *gorm.DB, purpose, challenge string) {
	t.Helper()
	var row models.WebAuthnSession
	require.NoError(t, db.Where("purpose = ?", purpose).Order("id desc").First(&row).Error)
	var m map[string]any
	require.NoError(t, json.Unmarshal(row.Data, &m))
	m["challenge"] = challenge
	data, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.WebAuthnSession{}).Where("id = ?", row.ID).Update("data", data).Error)
}

// runNoUVLogin begins a ceremony through core (so the stored row is the
// relying party's own) and finishes it with the spec assertion, whose
// authenticator did NOT verify the user.
func runNoUVLogin(t *testing.T, passwordless bool, decorate func(ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty) (int64, error) {
	t.Helper()
	c, db := newWebAuthnSpecTestCore(t)
	c.SetWebAuthn(decorate(c.webauthnRP))
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	parsed, challenge := specLoginAssertion(t)
	var err error
	if passwordless {
		_, token, berr := c.BeginWebAuthnPasswordlessLogin(ctx)
		require.NoError(t, berr)
		pointRowAtSpecChallenge(t, db, "passwordless", challenge)
		parsed.Response.UserHandle = specWebAuthnID(1)
		_, _, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, token, "ua", "203.0.113.5", parsed)
	} else {
		ch, cerr := c.CreateMFAChallenge(ctx, 1)
		require.NoError(t, cerr)
		_, token, berr := c.BeginWebAuthnLogin(ctx, ch)
		require.NoError(t, berr)
		pointRowAtSpecChallenge(t, db, "login", challenge)
		_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "203.0.113.5", parsed)
	}
	return countWhere(t, db, &models.Session{}, "user_id = ?", 1), err
}

// TestAssertionWithoutUV_RefusedThroughCore_RedWhenPreferred (proof b, end to
// end): a cryptographically valid assertion without user verification is
// refused on both login paths when core began the ceremony through the real
// adapter; with an adapter that asks for "preferred" the same assertion logs
// in. internal/webauthnrp's TestAssertionWithoutUV_IsRejected_RedWhenPreferred
// pins the adapter's own option.
func TestAssertionWithoutUV_RefusedThroughCore_RedWhenPreferred(t *testing.T) {
	t.Parallel()
	same := func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return rp }
	pref := func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return uvPreferred{rp} }
	for _, passwordless := range []bool{false, true} {
		sessions, err := runNoUVLogin(t, passwordless, same)
		require.Error(t, err, "passwordless=%v: an assertion without UV must be refused", passwordless)
		assert.Contains(t, err.Error(), "assertion verification failed")
		perr, ok := errors.AsType[*protocol.Error](err)
		require.True(t, ok, "the library's error stays in the chain: %v", err)
		assert.Contains(t, perr.DevInfo, "User verification required")
		assert.Zero(t, sessions)

		sessions, err = runNoUVLogin(t, passwordless, pref)
		require.NoError(t, err, "passwordless=%v: mutation: with UV preferred it logs in (else this scenario does not exercise UV)", passwordless)
		assert.Equal(t, int64(1), sessions)
	}
}

// --- (d) disabled server, typed-nil trap ------------------------------------

// typedNilRP lets the test build a non-nil interface holding a nil pointer.
type typedNilRP struct{ ports.WebAuthnRelyingParty }

// TestWebAuthnDisabled_NilAndWrappedNil (proof d): with no relying party, or
// with webauthnrp.Wrap(nil), every WebAuthn entry point returns
// ErrWebAuthnDisabled (the HTTP 501). The mutation half shows why the adapter
// must never return a typed nil: core would take it for an enabled relying
// party.
func TestWebAuthnDisabled_NilAndWrappedNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, rp := range map[string]ports.WebAuthnRelyingParty{"nil": nil, "Wrap(nil)": webauthnrp.Wrap(nil)} {
		c, _ := newWebAuthnTestCore(t, true)
		c.SetWebAuthn(rp)
		require.False(t, c.WebAuthnEnabled(), name)
		calls := map[string]func() error{
			"BeginWebAuthnRegistration": func() error { _, _, err := c.BeginWebAuthnRegistration(ctx, 1); return err },
			"FinishWebAuthnRegistration": func() error {
				_, err := c.FinishWebAuthnRegistration(ctx, 1, "t", "n", webauthnTestPassword, nil)
				return err
			},
			"BeginWebAuthnReauth":  func() error { _, _, err := c.BeginWebAuthnReauth(ctx, 1); return err },
			"FinishWebAuthnReauth": func() error { return c.FinishWebAuthnReauth(ctx, 1, "t", nil) },
			"BeginWebAuthnLogin":   func() error { _, _, err := c.BeginWebAuthnLogin(ctx, "ch"); return err },
			"BeginWebAuthnLoginHoldingLoginSlot": func() error {
				_, _, err := c.BeginWebAuthnLoginHoldingLoginSlot(ctx, "ch", nil)
				return err
			},
			"FinishWebAuthnLogin": func() error { _, _, _, err := c.FinishWebAuthnLogin(ctx, "ch", "t", "ua", "ip", nil); return err },
			"FinishWebAuthnLoginPending": func() error {
				_, _, _, _, err := c.FinishWebAuthnLoginPending(ctx, "ch", "t", "ua", "ip", nil)
				return err
			},
			"BeginWebAuthnPasswordlessLogin": func() error { _, _, err := c.BeginWebAuthnPasswordlessLogin(ctx); return err },
			"BeginWebAuthnPasswordlessLoginHoldingLoginSlot": func() error {
				_, _, err := c.BeginWebAuthnPasswordlessLoginHoldingLoginSlot(ctx, nil)
				return err
			},
			"FinishWebAuthnPasswordlessLogin": func() error {
				_, _, _, err := c.FinishWebAuthnPasswordlessLogin(ctx, "t", "ua", "ip", nil)
				return err
			},
			"FinishWebAuthnPasswordlessLoginPending": func() error {
				_, _, _, _, err := c.FinishWebAuthnPasswordlessLoginPending(ctx, "t", "ua", "ip", nil)
				return err
			},
		}
		for fn, call := range calls {
			assert.ErrorIs(t, call(), ErrWebAuthnDisabled, "%s with %s", fn, name)
		}
	}

	c, _ := newWebAuthnTestCore(t, false)
	var typed *typedNilRP
	c.SetWebAuthn(typed)
	assert.True(t, c.WebAuthnEnabled(), "mutation: a typed nil is a non-nil interface and would read as enabled — the reason New/Wrap return a nil interface")
}

// --- (f) passwordless resolve-callback semantics ----------------------------

type passkeyOutcome struct {
	err          error
	failedAudits int64
}

func runPasskeyResolve(t *testing.T, handle []byte, storageDown bool, decorate func(ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty) passkeyOutcome {
	t.Helper()
	c, db := newWebAuthnSpecTestCore(t)
	c.SetWebAuthn(decorate(c.webauthnRP))
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	if storageDown {
		c.storage = userReadFaultStub(c.storage, errPreVerdictStorageDown)
	}
	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = handle
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)
	_, _, _, _, err = c.FinishWebAuthnPasswordlessLoginPending(ctx, token, "ua", "203.0.113.5", parsed)
	return passkeyOutcome{err: err, failedAudits: countWhere(t, db, &models.AuditEvent{}, "event_type = ?", "webauthn.failed")}
}

// TestPasskeyResolve_StorageFailureNotEvaluated_UnknownHandleFailedAttempt
// (proof f): through the adapter's ValidatePasskeyLogin, a storage failure
// loading the handle's user is ErrWebAuthnLoginNotEvaluated (no webauthn.failed
// audit; the transport hands the slot back), while a handle naming no user, or
// a malformed one, is a failed attempt. The mutation half is an adapter that
// resolves the user without core's callback: the storage failure then
// masquerades as a failed attempt.
func TestPasskeyResolve_StorageFailureNotEvaluated_UnknownHandleFailedAttempt(t *testing.T) {
	t.Parallel()
	same := func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return rp }

	down := runPasskeyResolve(t, specWebAuthnID(1), true, same)
	require.ErrorIs(t, down.err, ErrWebAuthnLoginNotEvaluated, "a storage failure resolving the passkey's user evaluated nothing")
	require.ErrorIs(t, down.err, errPreVerdictStorageDown)
	assert.Zero(t, down.failedAudits, "not evaluated is not a failed attempt")

	for name, handle := range map[string][]byte{
		"unknown user": specWebAuthnID(999),
		"malformed":    []byte("short"),
		"id zero":      specWebAuthnID(0),
	} {
		got := runPasskeyResolve(t, handle, false, same)
		require.Error(t, got.err, name)
		assert.NotErrorIs(t, got.err, ErrWebAuthnLoginNotEvaluated, "%s: a bad handle is a credential guess", name)
		assert.Contains(t, got.err.Error(), "assertion verification failed", name)
		assert.Equal(t, int64(1), got.failedAudits, "%s: counted as a failed attempt", name)
	}

	mut := runPasskeyResolve(t, specWebAuthnID(1), true, func(rp ports.WebAuthnRelyingParty) ports.WebAuthnRelyingParty { return bypassResolve{rp} })
	require.Error(t, mut.err)
	assert.NotErrorIs(t, mut.err, ErrWebAuthnLoginNotEvaluated, "mutation: without core's callback the storage failure is no longer seen")
	assert.Equal(t, int64(1), mut.failedAudits)
}
