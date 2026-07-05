package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_GetUserByEmail_RealServerRoundTrip proves the fix for #503:
// RemoteStorage.GetUserByEmail targeted /api/v1/users/by-email/{email}, a route
// server/http/router.go never registered, so every call 404'd against a real
// production server regardless of whether the user actually existed. This
// affected every internal/core call site that resolves a user by email under
// storage.type: remote (CreateUser's pre-existence check, plus RBAC/SSO/SCIM
// lookups) — not just CreateUser.
//
// The fix adds GET /api/v1/users/by-email (query-parameter scoped, mirroring
// GetSecretByName's #497 convention rather than a path segment), gated by the
// SAME users.read permission GetUser-by-id already requires (the group-wide
// r.Use(RequirePermission("users.read")) on /users), and returns the same
// generic NotFound shape GetUser-by-id uses on a miss — deliberately NOT a
// distinct shape, so the route introduces no new email-enumeration surface:
// a caller without users.read never reaches the handler (401/403, identical
// for every email), and a caller WITH users.read can already enumerate every
// user's email via GET /users, so this route grants no new capability at that
// permission level.
//
// Like TestRemoteStorage_GetSecretByName_RealServerRoundTrip, this drives the
// method through a REAL running server (NewRouter) via a REAL RemoteStorage
// client over real HTTP — not a hand-rolled mock — so the test would have
// failed against the pre-fix code with a 404, not just against a synthetic
// stand-in of the route.
func TestRemoteStorage_GetUserByEmail_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream: a real Keyorix server ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)
	// A non-admin user with only the system_viewer baseline (system.read) — NOT
	// users.read — the under-permissioned caller for the gating assertions below.
	limitedToken := createLimitedToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	newClient := func(token string) *store.RemoteStorage {
		rs, err := store.NewRemoteStorage(&remote.Config{
			BaseURL:        upstreamSrv.URL,
			APIKey:         token,
			TimeoutSeconds: 5,
			RetryAttempts:  0,
			TLSVerify:      true,
		})
		require.NoError(t, err)
		return rs
	}

	// --- downstream: storage.type: remote, pointed at the upstream, as an
	// admin caller (holds users.read) ---
	rs := newClient(upstreamToken)

	// --- the user genuinely exists: must be found, not 404 ---
	got, err := rs.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err, "GetUserByEmail must reach the real /api/v1/users/by-email route and succeed for a user that genuinely exists (#503)")
	require.NotNil(t, got)
	assert.Equal(t, "testadmin", got.Username)
	assert.Equal(t, "testadmin@example.com", got.Email)

	// --- the user genuinely does NOT exist: must be a real not-found, not a
	// routing 404 confused with "found nothing" ---
	_, err = rs.GetUserByEmail(ctx, "does-not-exist@example.com")
	require.Error(t, err, "an email that genuinely doesn't exist must still return an error")
	var notFoundErr *remote.HTTPError
	require.True(t, errors.As(err, &notFoundErr), "expected a structured remote.HTTPError")
	assert.Equal(t, http.StatusNotFound, notFoundErr.StatusCode)

	// --- gating: an authenticated caller who lacks users.read must be denied
	// identically whether the target email exists or not — proving the route
	// cannot be used to enumerate emails by an under-permissioned caller ---
	limitedRS := newClient(limitedToken)

	_, existsErr := limitedRS.GetUserByEmail(ctx, "testadmin@example.com")
	require.Error(t, existsErr, "an under-permissioned caller must be denied even for an email that exists")
	var existsHTTPErr *remote.HTTPError
	require.True(t, errors.As(existsErr, &existsHTTPErr))

	_, notExistsErr := limitedRS.GetUserByEmail(ctx, "does-not-exist@example.com")
	require.Error(t, notExistsErr, "an under-permissioned caller must be denied even for an email that does not exist")
	var notExistsHTTPErr *remote.HTTPError
	require.True(t, errors.As(notExistsErr, &notExistsHTTPErr))

	// The denial must carry the SAME status for both cases (403 Forbidden, the
	// route's permission gate) — not a 404 for one and a 403 for the other,
	// which would itself leak existence to an under-permissioned caller.
	assert.Equal(t, http.StatusForbidden, existsHTTPErr.StatusCode)
	assert.Equal(t, existsHTTPErr.StatusCode, notExistsHTTPErr.StatusCode,
		"gating must not leak existence via a different status for an existing vs a non-existing email")

	// --- a fully unauthenticated caller must also be denied, identically
	// regardless of whether the email exists (401, before the handler even
	// parses the query) ---
	unauthResp1, err := http.Get(upstreamSrv.URL + "/api/v1/users/by-email?email=testadmin@example.com")
	require.NoError(t, err)
	defer func() { _ = unauthResp1.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, unauthResp1.StatusCode)

	unauthResp2, err := http.Get(upstreamSrv.URL + "/api/v1/users/by-email?email=does-not-exist@example.com")
	require.NoError(t, err)
	defer func() { _ = unauthResp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, unauthResp2.StatusCode)
	assert.Equal(t, unauthResp1.StatusCode, unauthResp2.StatusCode,
		"an unauthenticated caller must not be able to distinguish an existing from a non-existing email")
}
