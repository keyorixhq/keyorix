// mfa_management_proxy_target_state_test.go — G80 overnight campaign, Tier 1
// Group A fix #4. UpsertMFASecretProxy used to trust the wire body
// unconditionally, skipping the two target-state checks
// core.BeginMFAEnrollment enforces before ever calling this storage primitive:
// fail closed if at-rest encryption is disabled, and refuse if the target
// already has MFA enabled. Both depend only on hub-local state (no actor
// context), so both were safe to add with no RemoteStorage wire-protocol
// change.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setTestAuthEncryptor wires a real, enabled auth encryptor onto cs, mirroring
// internal/core/mfa_test.go's newMFATestCore setup but callable from outside
// the core package (exported API only). Shared by every test in this package
// that exercises UpsertMFASecretProxy post-G80 (it now refuses when
// AuthEncryptionActive() is false, matching core.BeginMFAEnrollment).
func setTestAuthEncryptor(t *testing.T, cs *core.KeyorixCore) {
	t.Helper()
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("g80-test-passphrase"))
	cs.SetAuthEncryptor(enc)
}

// mfaProxyTestCore builds a real core with an enabled auth encryptor and a
// seeded user.
func mfaProxyTestCore(t *testing.T, mfaEnabled bool) (*core.KeyorixCore, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	user := &models.User{Username: "g80-mfa-target-state", Email: "g80-mfa-target-state@example.com",
		AccountState: "active", MFAEnabled: mfaEnabled}
	require.NoError(t, db.Create(user).Error)
	setTestAuthEncryptor(t, cs)
	return cs, user.ID
}

// TestUpsertMFASecretProxy_RefusesWhenAlreadyEnabled_RealServer.
func TestUpsertMFASecretProxy_RefusesWhenAlreadyEnabled_RealServer(t *testing.T) {
	cs, userID := mfaProxyTestCore(t, true)
	h := NewAuthHandler(cs, false)

	body, err := json.Marshal(map[string]interface{}{
		"user_id":    userID,
		"secret_enc": "Y2lwaGVydGV4dA==",
		"activated":  true,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, req)
	assert.Equal(t, 409, w.Code, "planting a secret for an already-MFA-enabled user must be refused: %s", w.Body.String())
}

// TestUpsertMFASecretProxy_RefusesWhenEncryptionDisabled_RealServer.
func TestUpsertMFASecretProxy_RefusesWhenEncryptionDisabled_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t) // no SetAuthEncryptor call -- encryption off
	user := &models.User{Username: "g80-mfa-noenc", Email: "g80-mfa-noenc@example.com", AccountState: "active"}
	require.NoError(t, db.Create(user).Error)
	h := NewAuthHandler(cs, false)

	body, err := json.Marshal(map[string]interface{}{
		"user_id":    user.ID,
		"secret_enc": "cGxhaW50ZXh0",
		"activated":  true,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, req)
	assert.Equal(t, 409, w.Code, "planting a secret while at-rest encryption is disabled must be refused: %s", w.Body.String())
}

// TestUpsertMFASecretProxy_AllowsFirstEnrollment_RealServer is the control
// case: a fresh, not-yet-MFA-enabled user with encryption on must still be
// able to enrol through this proxy.
func TestUpsertMFASecretProxy_AllowsFirstEnrollment_RealServer(t *testing.T) {
	cs, userID := mfaProxyTestCore(t, false)
	h := NewAuthHandler(cs, false)

	body, err := json.Marshal(map[string]interface{}{
		"user_id":    userID,
		"secret_enc": "Y2lwaGVydGV4dA==",
		"activated":  false,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, req)
	require.Equal(t, 200, w.Code, "first enrolment for a not-yet-enabled user must still succeed: %s", w.Body.String())
}
