// mfa_verify_permissions_fail_closed_test.go — handler-level regression for
// https://github.com/keyorixhq/keyorix/issues/2412 (found by CI fuzzing on PR
// #2392, FuzzStorageFaultOperations input c67f27: REST POST /auth/mfa/verify,
// fault GetUserPermissions#1/error — ORACLE (c): a fault on an
// authz-resolution read produced a SUCCESSFUL result, HTTP 200, instead of an
// error/deny). VerifyMFA calls buildLoginResponse AFTER VerifyMFALogin has
// already minted the session; buildLoginResponse's identity-summary read
// (GetUserRolesByID + GetUserPermissions, via GetUserIdentity) was
// best-effort by design for the password-login path (it only feeds a UI nav
// hint, never the real per-request Authorize check) -- but VerifyMFA must not
// hand the client a usable session token and a 200 while that resolution
// itself failed: the client would hold a working token with no way to tell
// its roles/permissions summary is a lie rather than a genuine "no
// permissions," and the storage error is silently discarded instead of
// surfacing as the infra failure it is.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const mfaVerifyPermsFailClosedTestPassword = "Secret#Passw0rd!"

// setupMFAVerifyPermsFailClosedTest mirrors setupMFAVerifyStorageErrorTest.
func setupMFAVerifyPermsFailClosedTest(t *testing.T) (*AuthHandler, *faultstorage.FaultyStorage, *gorm.DB, time.Time) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A :memory: SQLite DSN gives each physical connection its own PRIVATE
	// database -- the background goSafe(LogAuthLogin/RecordLogin) goroutines a
	// successful login fires can otherwise race the test's own queries onto a
	// second, freshly-empty connection. Cap the pool at 1 so every query (test
	// and handler alike) shares the single connection AutoMigrate ran on.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{}, &models.LoginAttempt{},
		&models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{}))

	hash, err := bcrypt.GenerateFromPassword([]byte(mfaVerifyPermsFailClosedTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	coreService := core.NewKeyorixCore(fs)
	coreService.SetAuthEncryptor(enc)
	coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
	})
	fixed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	coreService.SetClockForTesting(func() time.Time { return fixed })

	return NewAuthHandler(coreService, false), fs, db, fixed
}

// TestVerifyMFA_GetUserPermissionsStorageError_FailsClosed: a storage error
// resolving the post-login identity summary (GetUserPermissions, reached via
// buildLoginResponse -> GetUserIdentity) must not produce the same HTTP 200 +
// session-cookie + token response a genuine success does. The MFA code itself
// is correct -- VerifyMFALogin succeeds and mints a real session -- but the
// client must never receive it while this resolution is unconfirmed.
func TestVerifyMFA_GetUserPermissionsStorageError_FailsClosed(t *testing.T) {
	h, fs, db, fixed := setupMFAVerifyPermsFailClosedTest(t)
	ctx := context.Background()

	_, secret, err := h.coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = h.coreService.ActivateMFA(ctx, 1, actCode, mfaVerifyPermsFailClosedTestPassword)
	require.NoError(t, err)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	challenge, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)

	// Fires on buildLoginResponse's GetUserIdentity call, AFTER VerifyMFALogin
	// (and its own GetUser/GetMFASecret/etc. calls) has already succeeded and
	// minted the session.
	fs.Arm(&faultstorage.FaultSpec{Method: "GetUserPermissions", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})

	body, err := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": good})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, r)

	assert.True(t, fs.Fired(), "the armed GetUserPermissions fault must actually have fired")
	assert.NotEqual(t, http.StatusOK, w.Code,
		"a storage error resolving the identity summary must not be reported as a successful login")
	assert.Empty(t, w.Result().Cookies(), "no session cookie must be set while the identity resolution is unconfirmed")

	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Empty(t, resp.Data.Token, "no usable session token must reach the client while the resolution is unconfirmed")

	// The reserved LoginAttempt row must be released too: the code itself was
	// genuinely correct (VerifyMFALogin succeeded), so this later, unrelated
	// storage failure must not consume the account's lockout budget.
	var attemptCount int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", "192.0.2.1").Count(&attemptCount).Error)
	assert.Zero(t, attemptCount, "the reserved LoginAttempt row must be released, not left counted")
}
