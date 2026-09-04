// webauthn_storage_error_test.go — closes the storage-failure branches
// webauthn.go's Begin/Finish functions each guard but MockStorage cannot
// exercise: several WebAuthn storage.Storage methods (CreateWebAuthnSession,
// ConsumeWebAuthnSession, ListWebAuthnCredentials, CreateWebAuthnCredential,
// DeleteWebAuthnCredential, CountWebAuthnCredentials, SetUserWebAuthnEnabled)
// are FIXED no-op stubs on MockStorage (mock_storage_test.go), not real
// mock.Called() expectations — they cannot be made to return an error via
// ms.On(...). webauthnStorageErrStub instead wraps a real LocalStorage
// (over SQLite) and overrides exactly one method at a time to inject a
// targeted failure, mirroring the userRoleScopesStub pattern already used in
// authz_readable_scopes_test.go for the same reason.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// webauthnStorageErrStub wraps a real storage.Storage and overrides
// individual WebAuthn-related methods to return a fixed error, leaving
// everything else (including the OTHER WebAuthn methods) to the real
// implementation.
type webauthnStorageErrStub struct {
	corestorage.Storage
	createSessionErr error
	listCredsErr     error
	createCredErr    error
	deleteCredErr    error
	countCredsErr    error
	setEnabledErr    error
}

func (s *webauthnStorageErrStub) CreateWebAuthnSession(ctx context.Context, sess *models.WebAuthnSession) error {
	if s.createSessionErr != nil {
		return s.createSessionErr
	}
	return s.Storage.CreateWebAuthnSession(ctx, sess)
}

func (s *webauthnStorageErrStub) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	if s.listCredsErr != nil {
		return nil, s.listCredsErr
	}
	return s.Storage.ListWebAuthnCredentials(ctx, userID)
}

func (s *webauthnStorageErrStub) CreateWebAuthnCredential(ctx context.Context, cred *models.WebAuthnCredential) error {
	if s.createCredErr != nil {
		return s.createCredErr
	}
	return s.Storage.CreateWebAuthnCredential(ctx, cred)
}

func (s *webauthnStorageErrStub) DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error {
	if s.deleteCredErr != nil {
		return s.deleteCredErr
	}
	return s.Storage.DeleteWebAuthnCredential(ctx, userID, id)
}

func (s *webauthnStorageErrStub) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	if s.countCredsErr != nil {
		return 0, s.countCredsErr
	}
	return s.Storage.CountWebAuthnCredentials(ctx, userID)
}

func (s *webauthnStorageErrStub) SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error {
	if s.setEnabledErr != nil {
		return s.setEnabledErr
	}
	return s.Storage.SetUserWebAuthnEnabled(ctx, userID, enabled)
}

// ── storeWebAuthnSession ──────────────────────────────────────────────────

func TestStoreWebAuthnSession_StorageErrorPropagates(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, createSessionErr: wantErr}

	_, err := c.storeWebAuthnSession(context.Background(), 1, "login", &webauthn.SessionData{})
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// ── BeginWebAuthnRegistration ────────────────────────────────────────────

func TestBeginWebAuthnRegistration_StoreSessionFails(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, createSessionErr: wantErr}

	_, _, err := c.BeginWebAuthnRegistration(context.Background(), 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// ── BeginWebAuthnLogin ────────────────────────────────────────────────────

func TestBeginWebAuthnLogin_DisabledServerRejects(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, false)
	_, _, err := c.BeginWebAuthnLogin(context.Background(), "irrelevant")
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

func TestBeginWebAuthnLogin_LoadUserFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	ch, err := c.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, listCredsErr: wantErr}

	_, _, err = c.BeginWebAuthnLogin(context.Background(), ch)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestBeginWebAuthnLogin_StoreSessionFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	ch, err := c.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, createSessionErr: wantErr}

	_, _, err = c.BeginWebAuthnLogin(context.Background(), ch)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// ── BeginWebAuthnPasswordlessLogin ───────────────────────────────────────

func TestBeginWebAuthnPasswordlessLogin_StoreSessionFails(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, createSessionErr: wantErr}

	_, _, err := c.BeginWebAuthnPasswordlessLogin(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// ── FinishWebAuthnRegistration ───────────────────────────────────────────

func TestFinishWebAuthnRegistration_SessionPurposeMismatch(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	// A session minted for the LOGIN flow must not complete a registration.
	tok, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: "x"})
	require.NoError(t, err)
	_, err = c.FinishWebAuthnRegistration(ctx, 1, tok, "laptop", webauthnTestPassword, &protocol.ParsedCredentialCreationData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration session mismatch")
}

func TestFinishWebAuthnRegistration_InvalidSessionToken(t *testing.T) {
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	_, err := c.FinishWebAuthnRegistration(ctx, 1, "not-a-real-token", "laptop", webauthnTestPassword, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired registration session")
}

func TestFinishWebAuthnRegistration_CreateCredentialStorageFails(t *testing.T) {
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

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, createCredErr: wantErr}

	_, err = c.FinishWebAuthnRegistration(ctx, 1, token, "yubikey", webauthnTestPassword, parsed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store credential")

	var count int64
	require.NoError(t, db.Model(&models.WebAuthnCredential{}).Count(&count).Error)
	assert.Zero(t, count, "a failed store must not leave a partial credential row")
}

// ── DeleteWebAuthnCredential ─────────────────────────────────────────────

func TestDeleteWebAuthnCredential_GetUserFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	err := c.DeleteWebAuthnCredential(context.Background(), 999, cred.ID, webauthnTestPassword)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// Deleting one of TWO passkeys must succeed and leave WebAuthn enabled,
// unlike deleting the LAST one (already covered by
// TestWebAuthn_DeleteClearsFlagOnLastAndIsUserScoped) -- the n>0 branch.
func TestDeleteWebAuthnCredential_NotLastPasskeyStaysEnabled(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	seedCredential(t, c, db, 1, "cred-2")
	seedStepUpGrant(t, db, 1, c.now())

	var first models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", []byte("cred-1")).First(&first).Error)

	require.NoError(t, c.DeleteWebAuthnCredential(context.Background(), 1, first.ID, webauthnTestPassword))

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.WebAuthnEnabled, "one passkey remains, so WebAuthn must stay enabled")

	var remaining int64
	require.NoError(t, db.Model(&models.WebAuthnCredential{}).Where("user_id = ?", 1).Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining)
}

func TestDeleteWebAuthnCredential_StorageDeleteFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	seedStepUpGrant(t, db, 1, c.now())
	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, deleteCredErr: wantErr}

	err := c.DeleteWebAuthnCredential(context.Background(), 1, cred.ID, webauthnTestPassword)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestDeleteWebAuthnCredential_CountFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	seedStepUpGrant(t, db, 1, c.now())
	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, countCredsErr: wantErr}

	err := c.DeleteWebAuthnCredential(context.Background(), 1, cred.ID, webauthnTestPassword)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestDeleteWebAuthnCredential_SetEnabledFalseFails(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-1")
	seedStepUpGrant(t, db, 1, c.now())
	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	wantErr := errors.New("db down")
	c.storage = &webauthnStorageErrStub{Storage: c.storage, setEnabledErr: wantErr}

	err := c.DeleteWebAuthnCredential(context.Background(), 1, cred.ID, webauthnTestPassword)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// ── loadWebAuthnUser ──────────────────────────────────────────────────────

// An unreadable stored credential blob (corrupted JSON) must be skipped, not
// fail the whole ceremony -- one bad row shouldn't lock the user out of every
// OTHER passkey they hold.
func TestLoadWebAuthnUser_SkipsUnreadableCredentialBlob(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-good")
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: []byte("cred-bad"), Name: "corrupt", CredentialBlob: []byte("{not json"),
	}).Error)

	wu, err := c.loadWebAuthnUser(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, wu.creds, 1, "only the readable credential should load")
	assert.Equal(t, []byte("cred-good"), wu.creds[0].ID)
}

// A credential flagged Disabled (#212 clone detection) must never be offered
// to a NEW ceremony, whether login candidate set or registration exclusion
// list.
func TestLoadWebAuthnUser_SkipsDisabledCredential(t *testing.T) {
	c, db := newWebAuthnTestCore(t, true)
	seedCredential(t, c, db, 1, "cred-active")
	blob, err := json.Marshal(webauthn.Credential{ID: []byte("cred-disabled")})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: 1, CredentialID: []byte("cred-disabled"), Name: "disabled", CredentialBlob: blob, Disabled: true,
	}).Error)

	wu, err := c.loadWebAuthnUser(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, wu.creds, 1)
	assert.Equal(t, []byte("cred-active"), wu.creds[0].ID)
}
