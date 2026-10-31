package core

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/webauthnrp"
)

// MFA-RESET-TAILS-2 item 1 (REVIEW-3838-DEEP-1 L1): a passkey is the enrolment an
// administrator MFA reset demanded, so registering one clears
// users.mfa_enrolment_required in the transaction that stores it, as TOTP
// activation does. The gate reads MFAEnrolmentOwed (flag AND no factor), so a
// stale flag only shows once the passkey is removed: the user would be confined to
// enrolment again although they enrolled.
func runResetUserRegistersPasskeyThenRemovesIt(t *testing.T, open func() *gorm.DB, migrate bool) {
	t.Helper()
	ctx := context.Background()
	w := newMFAResetWorld(t, open, migrate)
	c := w.setup
	c.SetRequireMFA(false)
	// The spec vector's attestation is bound to RPID example.org (webauthn_spec_vectors_test.go).
	rp, err := webauthn.New(&webauthn.Config{RPID: "example.org", RPDisplayName: "Keyorix", RPOrigins: []string{"https://example.org"}})
	require.NoError(t, err)
	c.SetWebAuthn(webauthnrp.Wrap(rp))

	req, err := c.RequestMFAReset(ctx, w.admin.ID, false, MFAResetRequestInput{
		User: "target", Reason: "lost phone", VerifiedBy: "video", Code: w.code(w.admin.ID, w.clock.step()),
	})
	require.NoError(t, err)
	approval, err := c.ApproveMFAReset(ctx, w.adminB.ID, false, req.ID, w.code(w.adminB.ID, w.clock.step()))
	require.NoError(t, err)
	st := store.NewLocalStorage(open())
	reload := func() *models.User {
		u, err := st.GetUser(ctx, w.target.ID)
		require.NoError(t, err)
		return u
	}
	require.True(t, MFAEnrolmentOwed(reload()), "premise: the approved reset leaves an enrolment owed")

	parsed, challenge := specRegistrationAttestation(t)
	token, err := c.storeWebAuthnSession(ctx, w.target.ID, "register", &webauthn.SessionData{
		Challenge:  challenge,
		UserID:     specWebAuthnID(w.target.ID),
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	})
	require.NoError(t, err)
	cred, err := c.FinishWebAuthnRegistration(ctx, w.target.ID, token, "yubikey", approval.OneTimePassword, parsed)
	require.NoError(t, err)
	u := reload()
	require.True(t, u.WebAuthnEnabled)
	assert.False(t, u.MFAEnrolmentRequired, "passkey registration must clear mfa_enrolment_required")

	// Removing the passkey re-authenticates with the password plus a step-up grant
	// (what a passkey re-assertion mints for a passkey-only account).
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: w.target.ID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: w.clock.now().Add(MFAResetRequestTTL),
	}))
	require.NoError(t, c.DeleteWebAuthnCredential(ctx, w.target.ID, cred.ID, approval.OneTimePassword))
	u = reload()
	require.False(t, userHasSecondFactor(u), "premise: the passkey was the only factor")
	assert.False(t, MFAEnrolmentOwed(u), "the user enrolled once; removing the passkey must not owe the reset's enrolment again")
	assert.NotContains(t, c.pendingSetupStepsFor(u), SetupStepEnrollMFA, "confined to enrolment again after removing the passkey")
}

func TestMFAReset_PasskeyRegistrationClearsOwedEnrolment_SQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa-reset-passkey.db")
	runResetUserRegistersPasskeyThenRemovesIt(t, func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open("file:"+path+sqliteProdPragmas), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		return db
	}, true)
}

func TestMFAReset_PasskeyRegistrationClearsOwedEnrolment_Postgres(t *testing.T) {
	dsn := pgMigratedDatabaseDSN(t, pgTestDSN(t))
	runResetUserRegistersPasskeyThenRemovesIt(t, func() *gorm.DB { return pgOpen(t, dsn) }, false)
}
