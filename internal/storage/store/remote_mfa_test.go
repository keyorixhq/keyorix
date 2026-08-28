package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MFA secret management ---

func TestRemoteStorage_GetMFASecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/secrets", r.URL.Path)
		assert.Equal(t, "42", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 7, "user_id": 42,
			"secret_enc":  []byte("encdata"),
			"secret_meta": []byte("metainfo"),
			"activated":   true,
			"created_at":  time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s, err := rs.GetMFASecret(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, uint(7), s.ID)
	assert.Equal(t, uint(42), s.UserID)
	assert.True(t, s.Activated)
}

// TestRemoteStorage_ActivateMFASecret_Unsupported: ActivateMFASecretProxy was
// deleted (#1593, docs/adr-089-mfa-purge-relay-deletion.md) -- no live
// caller. ActivateMFASecret is now a hard stub, same as
// ConsumeMFARecoveryCode/CreateMFAChallenge below.
func TestRemoteStorage_ActivateMFASecret_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.ActivateMFASecret(context.Background(), 42)
	assert.Error(t, err)
}

func TestRemoteStorage_MarkTOTPStepUsed_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	_, err = rs.MarkTOTPStepUsed(context.Background(), 1, 12345)
	assert.Error(t, err)
}

// TestRemoteStorage_DeleteMFAForUser_Unsupported: DeleteMFAForUserProxy was
// deleted (#1593, docs/adr-089-mfa-purge-relay-deletion.md) -- no live
// caller.
func TestRemoteStorage_DeleteMFAForUser_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.DeleteMFAForUser(context.Background(), 42)
	assert.Error(t, err)
}

// TestRemoteStorage_SetUserMFAEnabled_Unsupported: SetUserMFAEnabledProxy was
// deleted (#1593, docs/adr-089-mfa-purge-relay-deletion.md) -- no live
// caller.
func TestRemoteStorage_SetUserMFAEnabled_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.SetUserMFAEnabled(context.Background(), 42, true)
	assert.Error(t, err)
}

// --- Recovery codes ---

// TestRemoteStorage_CreateMFARecoveryCodes_Unsupported:
// CreateMFARecoveryCodesProxy was deleted (#1593,
// docs/adr-089-mfa-purge-relay-deletion.md) -- no live caller.
func TestRemoteStorage_CreateMFARecoveryCodes_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.CreateMFARecoveryCodes(context.Background(), 42, []string{"hash1", "hash2", "hash3"})
	assert.Error(t, err)
}

func TestRemoteStorage_ConsumeMFARecoveryCode_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	_, err = rs.ConsumeMFARecoveryCode(context.Background(), 1, "code", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_CountUnusedMFARecoveryCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/mfa/recovery-codes/count", r.URL.Path)
		assert.Equal(t, "42", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{"count": 6}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	n, err := rs.CountUnusedMFARecoveryCodes(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, 6, n)
}

// TestRemoteStorage_DeleteMFARecoveryCodes_Unsupported:
// DeleteMFARecoveryCodesProxy was deleted (#1593,
// docs/adr-089-mfa-purge-relay-deletion.md) -- no live caller.
func TestRemoteStorage_DeleteMFARecoveryCodes_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.DeleteMFARecoveryCodes(context.Background(), 42)
	assert.Error(t, err)
}

// --- MFA challenge (CreateMFAChallenge is an unsupported stub) ---

func TestRemoteStorage_CreateMFAChallenge_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	err = rs.CreateMFAChallenge(context.Background(), &models.MFAChallenge{UserID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_ConsumeMFAChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/users/mfa-challenge/consume", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         55,
			"user_id":    42,
			"token_hash": "tkhash123",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ch, err := rs.ConsumeMFAChallenge(context.Background(), "tkhash123", now)
	require.NoError(t, err)
	assert.Equal(t, uint(55), ch.ID)
	assert.Equal(t, uint(42), ch.UserID)
	assert.Equal(t, "tkhash123", ch.TokenHash)
}

func TestRemoteStorage_GetActiveMFAChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/users/mfa-challenge/active", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         56,
			"user_id":    42,
			"token_hash": "activehash",
			"expires_at": now.Add(5 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ch, err := rs.GetActiveMFAChallenge(context.Background(), "activehash", now)
	require.NoError(t, err)
	assert.Equal(t, uint(56), ch.ID)
	assert.Equal(t, uint(42), ch.UserID)
}

// --- RemoteMFAVerifier proxy ---

func TestRemoteStorage_IssueMFAChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/users/42/mfa-challenge", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"challenge": "opaque-challenge-token"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	tok, err := rs.IssueMFAChallenge(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, "opaque-challenge-token", tok)
}

func TestRemoteStorage_VerifyMFALoginCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/users/verify-mfa", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 42, "username": "alice", "used_recovery": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, usedRecovery, err := rs.VerifyMFALoginCredentials(context.Background(), "opaque-challenge-token", "123456")
	require.NoError(t, err)
	assert.Equal(t, uint(42), user.ID)
	assert.Equal(t, "alice", user.Username)
	assert.False(t, usedRecovery)
}

func TestRemoteStorage_VerifyMFALoginCredentials_WithRecovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 42, "username": "alice", "used_recovery": true,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	user, usedRecovery, err := rs.VerifyMFALoginCredentials(context.Background(), "challenge", "recovery-code-hash")
	require.NoError(t, err)
	assert.Equal(t, uint(42), user.ID)
	assert.True(t, usedRecovery)
}

func TestRemoteStorage_VerifyMFALoginCredentials_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"UNAUTHORIZED","message":"invalid code"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.VerifyMFALoginCredentials(context.Background(), "bad-challenge", "000000")
	assert.Error(t, err)
}
