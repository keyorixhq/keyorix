// mfa_stepup_handler_test.go — HTTP handler tests for POST /api/v1/auth/mfa/stepup.
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const stepUpTestPassword = "Secret#Passw0rd!"

// setupMFAStepUpTest builds an AuthHandler over real SQLite with an enabled encryptor
// (TOTP secrets are encrypted at rest), seeding user id 1 = "alice" with a known password.
func setupMFAStepUpTest(t *testing.T) (*AuthHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
		&models.MFAChallenge{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
	))
	hash, err := bcrypt.GenerateFromPassword([]byte(stepUpTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuthEncryptor(enc)

	return NewAuthHandler(coreService, false), coreService, db
}

// activateMFAForStepUpTest enrolls and activates MFA for user 1 using the real clock,
// returning the base32 secret and initial recovery codes.
func activateMFAForStepUpTest(t *testing.T, coreService *core.KeyorixCore) (secret string, codes []string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	_, secret, err := coreService.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)

	// Activate using the previous step so the current step remains available for test calls.
	actCode, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	require.NoError(t, err)
	codes, err = coreService.ActivateMFA(ctx, 1, actCode, stepUpTestPassword)
	require.NoError(t, err)
	return secret, codes
}

// TestMFAStepUpHandler_NoUserContext_Unauthorized verifies that a request without
// a user context is rejected with 401.
func TestMFAStepUpHandler_NoUserContext_Unauthorized(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/stepup",
		bytes.NewBufferString(`{"code":"123456"}`))
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestMFAStepUpHandler_BadJSON_BadRequest verifies that malformed JSON is rejected with 400.
func TestMFAStepUpHandler_BadJSON_BadRequest(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/stepup",
		bytes.NewBufferString(`{not-json}`))
	r = withUserContext(r, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestMFAStepUpHandler_EmptyCode_BadRequest verifies that a request with an empty code
// is rejected with 400.
func TestMFAStepUpHandler_EmptyCode_BadRequest(t *testing.T) {
	h, _, _ := setupMFAStepUpTest(t)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": ""}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestMFAStepUpHandler_WrongCode_Unauthorized verifies that an incorrect TOTP code
// is rejected with 401.
func TestMFAStepUpHandler_WrongCode_Unauthorized(t *testing.T) {
	h, coreService, _ := setupMFAStepUpTest(t)
	activateMFAForStepUpTest(t, coreService)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "000000"}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestMFAStepUpHandler_CorrectCode_Success verifies that a correct TOTP code returns 200
// and the success message.
func TestMFAStepUpHandler_CorrectCode_Success(t *testing.T) {
	h, coreService, _ := setupMFAStepUpTest(t)
	secret, _ := activateMFAForStepUpTest(t, coreService)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	r := postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": code}, 1)
	rr := httptest.NewRecorder()
	h.MFAStepUp(rr, r)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "step-up verified")
}
