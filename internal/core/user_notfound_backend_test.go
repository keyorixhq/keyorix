// user_notfound_backend_test.go — regression coverage for #504: sso.go, scim.go,
// users.go, and setup_consume.go used to detect "user not found" by string-matching
// LocalStorage's i18n error text, which never matched a RemoteStorage error (before or
// after round 112's #501 fix gave RemoteStorage a structured remote.HTTPError type).
// This file proves the shared storage.IsUserNotFound primitive those call sites now
// use is correct under BOTH backends, using real errors — a genuine sqlite miss for
// LocalStorage, and a genuine 404 response (the real sendError JSON shape
// server/http/handlers actually emits — see helpers.go's sendError) round-tripped
// through the real remote.HTTPClient/store.RemoteStorage for RemoteStorage. Mirrors
// #484/#454's own established "real SQLite + real httptest RemoteStorage" test style
// in this package (see password_remote_test.go, login_lockout_remote_test.go).
package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestIsUserNotFound_RealLocalStorage proves storage.IsUserNotFound recognizes a
// genuine LocalStorage miss for every one of the lookup methods #504's call sites use
// (GetUser, GetUserByEmail, GetUserByUsername, GetUserByExternalID, RestoreUser) — all
// against a real sqlite DB, not a hand-rolled mock error.
func TestIsUserNotFound_RealLocalStorage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	local := store.NewLocalStorage(db)
	ctx := context.Background()

	_, err = local.GetUser(ctx, 999999)
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUser miss must be detected; got: %v", err)

	_, err = local.GetUserByEmail(ctx, "ghost@nowhere.test")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByEmail miss must be detected; got: %v", err)

	_, err = local.GetUserByUsername(ctx, "ghost")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByUsername miss must be detected; got: %v", err)

	_, err = local.GetUserByExternalID(ctx, "sso:none:none")
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "GetUserByExternalID miss must be detected; got: %v", err)

	err = local.RestoreUser(ctx, 999999)
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "RestoreUser miss must be detected; got: %v", err)

	// Negative: an existing user is not "not found".
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "carol", Email: "carol@example.com"}).Error)
	u, err := local.GetUser(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), u.ID)
}

// sendErrorJSON writes the exact flat envelope server/http/handlers/helpers.go's
// sendError emits, so the RemoteStorage side of this test pins the genuine wire shape
// (see internal/storage/remote/client.go's serverErrorBody), not a stand-in.
func sendErrorJSON(w http.ResponseWriter, errorType, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   errorType,
		"message": message,
		"code":    statusCode,
	})
}

// TestIsUserNotFound_RealRemoteStorage404 proves storage.IsUserNotFound recognizes a
// genuine RemoteStorage 404 — round-tripped through the real remote.HTTPClient
// (internal/storage/remote/client.go's newHTTPError/HTTPError.IsNotFound), against a
// server emitting the exact JSON shape sendError produces — as "not found", and that a
// real non-404 failure (500) is NOT misclassified as "not found" (fail-closed).
func TestIsUserNotFound_RealRemoteStorage404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendErrorJSON(w, "NotFound", "User not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)

	_, err = rs.GetUser(context.Background(), 999999)
	require.Error(t, err)
	assert.True(t, corestorage.IsUserNotFound(err), "a genuine RemoteStorage 404 must be detected; got: %v", err)

	// 403, not 500: a 5xx is retryable (isRetryableError), which would burn real
	// wall-clock time on the client's exponential backoff for no benefit to this
	// assertion — 403 exercises the same "not a 404" fail-closed path instantly.
	srv403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendErrorJSON(w, "PermissionDenied", "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv403.Close)
	rs403, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv403.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)
	_, err = rs403.GetUser(context.Background(), 1)
	require.Error(t, err)
	assert.False(t, corestorage.IsUserNotFound(err), "a real 403 must not be misdetected as not-found; got: %v", err)
}

// TestResolveSSOUser_EmailFallback_RealRemoteStorage404 is the #504 regression for
// sso.go's resolveSSOUser email fallback under storage.type: remote. sub is left empty
// so only the email-fallback branch (c.storage.GetUserByEmail) runs — resolveSSOUser's
// externalId branch (c.storage.GetUserByExternalID) hard-fails unconditionally under
// storage.type: remote regardless of #504 (RemoteStorage.GetUserByExternalID is an
// unconditional storage.ErrUnsupportedByBackend stub, a separate, pre-existing
// architectural gap — not part of this fix). Before #504's fix, resolveSSOUser's
// `strings.Contains(err.Error(), notFound)` never matched a real RemoteStorage error,
// so a genuinely-absent account's email lookup surfaced as a hard login error instead
// of the documented (nil, nil) "no match" outcome.
func TestResolveSSOUser_EmailFallback_RealRemoteStorage404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendErrorJSON(w, "NotFound", "User not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)
	c := &KeyorixCore{storage: rs, now: func() time.Time { return time.Now() }, passwordPolicy: DefaultPasswordPolicy()}

	u, err := c.resolveSSOUser(context.Background(), "okta", "", "ghost@example.com", true)
	require.NoError(t, err, "resolveSSOUser must treat the real 404 as 'no match', not a hard error")
	assert.Nil(t, u)
}
