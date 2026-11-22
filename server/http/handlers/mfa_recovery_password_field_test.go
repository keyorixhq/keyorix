// mfa_recovery_password_field_test.go — #4224: only the "code" field of
// POST /auth/mfa/disable and /auth/mfa/recovery-codes/regenerate can carry a
// recovery code. The "password" field goes to the password check alone, so a
// recovery code sent there is refused and not consumed, and a recovery-shaped
// password is never hashed as a recovery code.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMFAReauth_RecoveryCodeInPasswordFieldIsRefusedAndNotConsumed(t *testing.T) {
	h, coreService, db := setupMFAStepUpTest(t)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.WebAuthnCredential{}))
	_, codes := activateMFAForStepUpTest(t, coreService)

	unused := func() int64 {
		var n int64
		require.NoError(t, db.Model(&models.MFARecoveryCode{}).Where("user_id = ? AND used_at IS NULL", 1).Count(&n).Error)
		return n
	}
	before := unused()
	require.NotZero(t, before)

	for name, handler := range map[string]http.HandlerFunc{
		"disable":    h.DisableMFA,
		"regenerate": h.RegenerateRecoveryCodes,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler(w, reauthRequest(t, http.MethodPost, "/auth/mfa/x", map[string]string{"password": codes[0]}, nil))
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), "invalid code or password")
			require.Equal(t, before, unused(), "a recovery code in the password field is not consumed")
		})
	}

	// The same code in the code field is accepted.
	w := httptest.NewRecorder()
	h.DisableMFA(w, reauthRequest(t, http.MethodPost, "/auth/mfa/disable", map[string]string{"code": codes[0]}, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
