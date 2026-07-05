package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newRemoteBackedCore spins up a REAL upstream *core.KeyorixCore (LocalStorage) behind
// a REAL production NewRouter/httptest server — the same pattern
// TestRemoteStorage_404_SurfacesStructuredError (#501, PR #812) and
// TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip (#498, PR #794) use — and
// returns a SECOND *core.KeyorixCore whose storage is a REAL RemoteStorage client
// pointed at that server. Calling any exported KeyorixCore method on the returned
// "downstream" core drives the exact internal/core call sites this file exercises
// (#504) through a genuine HTTP round trip against a real handler, not a hand-rolled
// mock standing in for the wire shape.
func newRemoteBackedCore(t *testing.T) (downstream, upstream *core.KeyorixCore, upstreamSrv *httptest.Server) {
	t.Helper()
	upstream = newTestCore(t)
	token := createTestToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv = httptest.NewServer(router)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         token,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return downstream, upstream, upstreamSrv
}

// TestIsUserNotFound_RealBothBackends proves the shared #504 detection primitive,
// storage.IsUserNotFound, correctly recognizes "this user does not exist" under BOTH
// active storage backends using REAL errors — not constructed stand-ins:
//   - LocalStorage: a genuine gorm.ErrRecordNotFound from a real sqlite DB, wrapped by
//     LocalStorage.GetUserByEmail (internal/storage/store/local_users.go).
//   - RemoteStorage: a genuine 404 from a REAL NewRouter-backed server
//     (handlers.GetUser -> sendError), round-tripped through the real
//     remote.HTTPClient/store.RemoteStorage.
//
// It also proves the negative: a real, non-"not found" failure (a 403 from a
// caller with no permission) is NOT misclassified as "not found" — the fail-closed
// half of the contract every #504 call site relies on.
func TestIsUserNotFound_RealBothBackends(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	t.Run("LocalStorage: real gorm.ErrRecordNotFound", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&models.User{}))
		local := store.NewLocalStorage(db)
		_, err = local.GetUserByEmail(context.Background(), "ghost-does-not-exist@example.com")
		require.Error(t, err)
		assert.True(t, storage.IsUserNotFound(err), "a genuine LocalStorage miss must be detected; got: %v", err)
	})

	t.Run("RemoteStorage: real 404 from a real NewRouter server", func(t *testing.T) {
		downstream, _, _ := newRemoteBackedCore(t)
		const nonExistentUserID = 999999
		_, err := downstream.GetUser(context.Background(), nonExistentUserID)
		require.Error(t, err)
		assert.True(t, storage.IsUserNotFound(err), "a genuine RemoteStorage 404 must be detected; got: %v", err)
	})

	t.Run("RemoteStorage: a real non-404 failure is NOT misclassified as not-found", func(t *testing.T) {
		_, upstream, srv := newRemoteBackedCore(t)
		// A limited (non-admin) token hitting an admin-only route gets a real 403 from
		// the real permission middleware — a genuine failure that must NOT be
		// misdetected as "not found" (fail-closed).
		limitedToken := createLimitedToken(t, upstream)
		rs, err := store.NewRemoteStorage(&remote.Config{
			BaseURL: srv.URL, APIKey: limitedToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
		})
		require.NoError(t, err)
		limitedCore := core.NewKeyorixCore(rs)
		_, err = limitedCore.GetUser(context.Background(), 1)
		require.Error(t, err)
		var httpErr *remote.HTTPError
		require.True(t, errors.As(err, &httpErr), "expected a *remote.HTTPError; got: %v", err)
		require.Equal(t, 403, httpErr.StatusCode, "sanity: this must actually be the 403 case, not a 404")
		assert.False(t, storage.IsUserNotFound(err), "a permission-denied failure must not be misdetected as not-found; got: %v", err)
	})
}

// TestFindSCIMUser_RemoteStorage_NotFoundNoLongerHardFails is the #504 regression for
// scim.go's FindSCIMUser: GetUserByEmail's route (GET /api/v1/users/by-email/{email})
// is not yet registered on the server at all (#503, a separate, deliberately
// out-of-scope gap), so under storage.type: remote it 404s UNCONDITIONALLY — even for
// an email that genuinely exists. Before #504's fix, that 404 never matched the
// LocalStorage-only i18n "ErrorUserNotFound" text FindSCIMUser string-matched against,
// so FindSCIMUser returned a hard error for EVERY SCIM email lookup under
// storage.type: remote, 100% of the time. After the fix, storage.IsUserNotFound
// correctly recognizes the real 404 (regardless of its cause) and FindSCIMUser
// returns its documented (nil, nil) "no match" outcome instead of erroring.
func TestFindSCIMUser_RemoteStorage_NotFoundNoLongerHardFails(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	downstream, _, _ := newRemoteBackedCore(t)
	u, err := downstream.FindSCIMUser(context.Background(), "", "nobody@example.com")
	require.NoError(t, err, "FindSCIMUser must treat the real 404 as 'no match', not a hard error")
	assert.Nil(t, u)
}

// TestCreateUser_RemoteStorage_SucceedsForFreshUser is the #504 regression for
// users.go's buildUserForCreate: its email pre-existence check
// (c.storage.GetUserByEmail) hits the same always-404 route as the test above.
// Before #504's fix, buildUserForCreate's `!strings.Contains(err.Error(),
// i18n.T("ErrorUserNotFound"))` guard was ALWAYS true against a RemoteStorage error
// (the i18n text never appears in a *remote.HTTPError's message), so it treated every
// such 404 as a hard retrieval failure — meaning CreateUser was completely broken
// (100% failure rate) under storage.type: remote for every brand-new signup, not just
// a corner case. After the fix, a fresh (never-seen) username/email is correctly
// recognized as "available" and CreateUser succeeds end-to-end through the real
// handler (which hashes the password server-side, #499).
func TestCreateUser_RemoteStorage_SucceedsForFreshUser(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	downstream, _, _ := newRemoteBackedCore(t)
	created, err := downstream.CreateUser(context.Background(), &core.CreateUserRequest{
		Username:    "freshuser1",
		Email:       "freshuser1@example.com",
		DisplayName: "Fresh User",
		Password:    "Zqx9!TrustNoOne42",
	})
	require.NoError(t, err, "CreateUser over storage.type: remote must succeed for a brand-new user")
	require.NotNil(t, created)
	assert.Equal(t, "freshuser1", created.Username)
	assert.Equal(t, "freshuser1@example.com", created.Email)
}

// TestRestoreUser_RemoteStorage_FriendlyNotFoundError is the #504 regression for
// users.go's RestoreUser: it exercises BOTH sides of the fix in one real round trip —
// the upstream handler's own core.RestoreUser (LocalStorage.RestoreUser, whose
// RowsAffected==0 branch is now wrapped in the typed storage.ErrUserNotFound sentinel)
// and the downstream (RemoteStorage-backed) core.RestoreUser that receives the
// resulting real *remote.HTTPError. Before #504's fix, the downstream side's
// string-match never matched that HTTPError, so RestoreUser over storage.type: remote
// always surfaced a generic "storage failed" error instead of the friendly, specific
// "user not found or not deleted" message.
func TestRestoreUser_RemoteStorage_FriendlyNotFoundError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	downstream, _, _ := newRemoteBackedCore(t)
	const nonExistentOrNotDeletedID = 999999
	err := downstream.RestoreUser(context.Background(), 1, nonExistentOrNotDeletedID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found or not deleted",
		"must surface the specific friendly message, not a generic storage-failed wrapper; got: %v", err)
}
