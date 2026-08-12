// webauthn_test.go — G50 regression coverage: webauthn.go's self-service
// handlers must never forward a raw backend/driver error to the client.
// DeleteWebAuthnCredential now routes its core error through writeWebAuthnErr
// (previously it built its own raw sendError call), and writeWebAuthnErr's
// non-ErrWebAuthnDisabled fallback must sanitize via clientSafe() — this test
// exercises BOTH fixes in one shot, since DeleteWebAuthnCredential's failure
// path IS writeWebAuthnErr's fallback branch.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestDeleteWebAuthnCredential_DBErrorSanitized inserts a real passkey row for
// user 1 directly (bypassing the WebAuthn attestation ceremony, which isn't
// needed to exercise the delete path), drops the webauthn_credentials table
// so core.DeleteWebAuthnCredential's storage delete fails with a raw SQLite
// driver error, and proves that raw text never reaches the HTTP response
// while still landing in the server-side log.
func TestDeleteWebAuthnCredential_DBErrorSanitized(t *testing.T) {
	h, _, db := setupMFAReauthTest(t)

	cred := &models.WebAuthnCredential{
		UserID:         1,
		CredentialID:   []byte("cred-1"),
		Name:           "laptop",
		CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, db.Create(cred).Error)

	require.NoError(t, db.Migrator().DropTable(&models.WebAuthnCredential{}))

	logBuf := captureLogBuf(t)

	body, _ := json.Marshal(map[string]string{"password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/1", bytes.NewReader(body))
	r = withUserContext(r, 1)
	r = withChiParams(r, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertNoRawDBLeak(t, w, logBuf, "webauthn_credentials")
}
