package handlers

import (
	"context"
	"crypto/fips140"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// FIPS-TAILS-2 item 1: every handler that can reach a TOTP check answers
// core.ErrTOTPUnavailableInFIPSMode, bare or wrapped in the pre-verdict
// sentinel, with 503 and the fixed text, never the generic 400/401 bodies.
func TestTOTPUnavailable_EveryErrorMapperAnswers503(t *testing.T) {
	h := NewAuthHandler(core.NewKeyorixCore(nil), false)
	wrapped := fmt.Errorf("%w: %w", core.ErrMFAVerificationUnavailable, core.ErrTOTPUnavailableInFIPSMode)
	mappers := map[string]func(http.ResponseWriter, error){
		"writeMFAErr":       h.writeMFAErr,
		"writeWebAuthnErr":  h.writeWebAuthnErr,
		"sendMFAResetError": func(w http.ResponseWriter, err error) { sendMFAResetError(w, "request", err) },
	}
	for name, mapErr := range mappers {
		for _, err := range []error{core.ErrTOTPUnavailableInFIPSMode, wrapped} {
			w := httptest.NewRecorder()
			mapErr(w, err)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, name)
			assert.Contains(t, w.Body.String(), errTOTPUnavailableInFIPSMode, name)
		}
	}
	// Anything else keeps its old mapping.
	w := httptest.NewRecorder()
	h.writeMFAErr(w, errors.New("invalid code"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Under GODEBUG=fips140=only the real endpoints answer 503 with the fixed text
// instead of panicking (Recovery's 500), and a refused login hands its budget
// slot back (nothing was evaluated).
func TestMFAEndpoints_UnderFIPS140Only_Answer503(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; TestTOTPUnavailable_EveryErrorMapperAnswers503 covers the mapping")
	}
	h, c, db := setupMFAStepUpTest(t)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{})) // so the budget slots are rows we can count
	// Activated TOTP written directly: enrolment refuses in this mode, and the
	// secret is never decrypted on a refused path.
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), Activated: true}).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("mfa_enabled", true).Error)

	check := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, name)
		assert.Contains(t, w.Body.String(), errTOTPUnavailableInFIPSMode, name)
	}

	w := httptest.NewRecorder()
	h.EnrollMFA(w, postJSON("/api/v1/auth/mfa/enroll", map[string]string{}, 1))
	check("enroll", w)

	w = httptest.NewRecorder()
	h.ActivateMFA(w, postJSON("/api/v1/auth/mfa/activate", map[string]string{"code": "123456", "password": stepUpTestPassword}, 1))
	check("activate", w)

	w = httptest.NewRecorder()
	h.MFAStepUp(w, postJSON("/api/v1/auth/mfa/stepup", map[string]string{"code": "123456"}, 1))
	check("stepup", w)

	w = httptest.NewRecorder()
	h.DisableMFA(w, postJSON("/api/v1/auth/mfa/disable", map[string]string{"code": "123456"}, 1))
	check("disable", w)

	ch, err := c.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	w = postJSONTo(t, h.VerifyMFA, "/api/v1/auth/mfa/verify", map[string]string{"mfa_challenge": ch, "code": "123456"})
	check("verify", w)

	var counted int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&counted).Error)
	assert.Zero(t, counted, "a refused TOTP check keeps no login budget slot (every endpoint above reserved one)")
}
