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

// --- WebAuthn credentials ---

func TestRemoteStorage_ListWebAuthnCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials", r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id": 99, "user_id": 7, "name": "YubiKey 5C",
					"credential_id":   []byte{0x01, 0x02},
					"credential_blob": []byte(`{}`),
					"created_at":      time.Now(), "disabled": false,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListWebAuthnCredentials(context.Background(), 7)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(99), list[0].ID)
	assert.Equal(t, "YubiKey 5C", list[0].Name)
}

func TestRemoteStorage_GetWebAuthnCredentialByCredID(t *testing.T) {
	credID := []byte{0xAB, 0xCD}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials/lookup", r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("user_id"))
		// credential_id is base64-encoded on the wire
		assert.NotEmpty(t, r.URL.Query().Get("credential_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 100, "user_id": 7, "name": "MacBook Touch ID",
			"credential_id":   credID,
			"credential_blob": []byte(`{}`),
			"created_at":      time.Now(), "disabled": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	c, err := rs.GetWebAuthnCredentialByCredID(context.Background(), credID, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(100), c.ID)
	assert.Equal(t, "MacBook Touch ID", c.Name)
}

// LockWebAuthnCredentialForUpdate delegates to GetWebAuthnCredentialByCredID.
func TestRemoteStorage_LockWebAuthnCredentialForUpdate(t *testing.T) {
	credID := []byte{0x11, 0x22}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials/lookup", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 101, "user_id": 5, "name": "Locked Key",
			"credential_id":   credID,
			"credential_blob": []byte(`{}`),
			"created_at":      time.Now(), "disabled": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	c, err := rs.LockWebAuthnCredentialForUpdate(context.Background(), credID, 5)
	require.NoError(t, err)
	assert.Equal(t, uint(101), c.ID)
	assert.Equal(t, "Locked Key", c.Name)
}

func TestRemoteStorage_UpdateWebAuthnCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials/99", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{
		ID: 99, UserID: 7, Name: "Updated Key", Disabled: true,
	})
	require.NoError(t, err)
}

func TestRemoteStorage_AdvanceWebAuthnCredentialCounter(t *testing.T) {
	credID := []byte{0xBE, 0xEF}
	newBlob := []byte(`{"signCount":42}`)
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PATCH", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials/advance-counter", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"advanced": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	advanced, err := rs.AdvanceWebAuthnCredentialCounter(context.Background(),
		credID, 7, newBlob, 42, now)
	require.NoError(t, err)
	assert.True(t, advanced)
}

func TestRemoteStorage_AdvanceWebAuthnCredentialCounter_NotAdvanced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PATCH", r.Method)
		_, _ = w.Write(apiOK(map[string]interface{}{"advanced": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	advanced, err := rs.AdvanceWebAuthnCredentialCounter(context.Background(),
		[]byte{0x01}, 7, []byte(`{}`), 1, time.Now())
	require.NoError(t, err)
	assert.False(t, advanced)
}

func TestRemoteStorage_CountWebAuthnCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/credentials/count", r.URL.Path)
		assert.Equal(t, "7", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{"count": int64(3)}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	n, err := rs.CountWebAuthnCredentials(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

// --- WebAuthn sessions ---

func TestRemoteStorage_CreateWebAuthnSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/sessions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         200,
			"user_id":    7,
			"token_hash": "sess-hash",
			"purpose":    "register",
			"data":       []byte(`{}`),
			"expires_at": now.Add(10 * time.Minute),
			"created_at": now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	s := &models.WebAuthnSession{
		UserID:    7,
		TokenHash: "sess-hash",
		Purpose:   "register",
		Data:      []byte(`{}`),
		ExpiresAt: now.Add(10 * time.Minute),
	}
	err = rs.CreateWebAuthnSession(context.Background(), s)
	require.NoError(t, err)
	// The method mutates the argument in-place with upstream-assigned fields.
	assert.Equal(t, uint(200), s.ID)
	assert.Equal(t, "register", s.Purpose)
}

func TestRemoteStorage_ConsumeWebAuthnSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/webauthn/sessions/consume", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":         200,
			"user_id":    7,
			"token_hash": "sess-hash",
			"purpose":    "login",
			"data":       []byte(`{}`),
			"expires_at": now.Add(5 * time.Minute),
			"used_at":    now,
			"created_at": now.Add(-1 * time.Minute),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	sess, err := rs.ConsumeWebAuthnSession(context.Background(), "sess-hash", now)
	require.NoError(t, err)
	assert.Equal(t, uint(200), sess.ID)
	assert.Equal(t, uint(7), sess.UserID)
	assert.Equal(t, "login", sess.Purpose)
	assert.NotNil(t, sess.UsedAt)
}

func TestRemoteStorage_ConsumeWebAuthnSession_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"NOT_FOUND","message":"not found"}}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeWebAuthnSession(context.Background(), "nonexistent-hash", time.Now())
	assert.Error(t, err)
}
