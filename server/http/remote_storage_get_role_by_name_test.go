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

// TestRemoteStorage_GetRoleByName_RealServerRoundTrip proves the fix for #512:
// RemoteStorage.GetRoleByName targeted /api/v1/roles/by-name/{name}, a route
// server/http/router.go never registered, so every call 404'd against a real
// production server regardless of whether the role actually existed — blocking
// InviteToProject for EVERY role (not just admin roles), the same "implemented
// client method, missing server route" class #503 fixed for users.
//
// The fix adds GET /api/v1/roles/by-name (query-parameter scoped, mirroring
// GetUserByEmail's #503 / GetSecretByName's #497 convention rather than a path
// segment), gated by the SAME roles.read permission GetRole-by-id already
// requires (the group-wide r.Use(RequirePermission("roles.read")) on /roles),
// and returns the same generic NotFound shape GetRole-by-id uses on a miss —
// deliberately NOT a distinct shape, so the route introduces no new
// role-name-enumeration surface: a caller without roles.read never reaches the
// handler (401/403, identical for every name), and a caller WITH roles.read
// can already enumerate every role's name via GET /roles, so this route
// grants no new capability at that permission level.
//
// Like TestRemoteStorage_GetUserByEmail_RealServerRoundTrip and
// TestRemoteStorage_GetSecretByName_RealServerRoundTrip, this drives the
// method through a REAL running server (NewRouter) via a REAL RemoteStorage
// client over real HTTP — not a hand-rolled mock — so the test would have
// failed against the pre-fix code with a 404, not just against a synthetic
// stand-in of the route.
func TestRemoteStorage_GetRoleByName_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream: a real Keyorix server ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)
	// A non-admin user with only the system_viewer baseline (system.read) — NOT
	// roles.read — the under-permissioned caller for the gating assertions below.
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
	// admin caller (holds roles.read) ---
	rs := newClient(upstreamToken)

	// --- the role genuinely exists (seeded by BootstrapSystem): must be found,
	// not 404 ---
	got, err := rs.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err, "GetRoleByName must reach the real /api/v1/roles/by-name route and succeed for a role that genuinely exists (#512)")
	require.NotNil(t, got)
	assert.Equal(t, "system_viewer", got.Name)

	// --- the role genuinely does NOT exist: must be a real not-found, not a
	// routing 404 confused with "found nothing" ---
	_, err = rs.GetRoleByName(ctx, "does_not_exist_role")
	require.Error(t, err, "a role name that genuinely doesn't exist must still return an error")
	var notFoundErr *remote.HTTPError
	require.True(t, errors.As(err, &notFoundErr), "expected a structured remote.HTTPError")
	assert.Equal(t, http.StatusNotFound, notFoundErr.StatusCode)

	// --- gating: an authenticated caller who lacks roles.read must be denied
	// identically whether the target role exists or not — proving the route
	// cannot be used to enumerate role names by an under-permissioned caller ---
	limitedRS := newClient(limitedToken)

	_, existsErr := limitedRS.GetRoleByName(ctx, "system_viewer")
	require.Error(t, existsErr, "an under-permissioned caller must be denied even for a role name that exists")
	var existsHTTPErr *remote.HTTPError
	require.True(t, errors.As(existsErr, &existsHTTPErr))

	_, notExistsErr := limitedRS.GetRoleByName(ctx, "does_not_exist_role")
	require.Error(t, notExistsErr, "an under-permissioned caller must be denied even for a role name that does not exist")
	var notExistsHTTPErr *remote.HTTPError
	require.True(t, errors.As(notExistsErr, &notExistsHTTPErr))

	// The denial must carry the SAME status for both cases (403 Forbidden, the
	// route's permission gate) — not a 404 for one and a 403 for the other,
	// which would itself leak existence to an under-permissioned caller.
	assert.Equal(t, http.StatusForbidden, existsHTTPErr.StatusCode)
	assert.Equal(t, existsHTTPErr.StatusCode, notExistsHTTPErr.StatusCode,
		"gating must not leak existence via a different status for an existing vs a non-existing role name")

	// --- a fully unauthenticated caller must also be denied, identically
	// regardless of whether the role exists (401, before the handler even
	// parses the query) ---
	unauthResp1, err := http.Get(upstreamSrv.URL + "/api/v1/roles/by-name?name=system_viewer")
	require.NoError(t, err)
	defer func() { _ = unauthResp1.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, unauthResp1.StatusCode)

	unauthResp2, err := http.Get(upstreamSrv.URL + "/api/v1/roles/by-name?name=does_not_exist_role")
	require.NoError(t, err)
	defer func() { _ = unauthResp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, unauthResp2.StatusCode)
	assert.Equal(t, unauthResp1.StatusCode, unauthResp2.StatusCode,
		"an unauthenticated caller must not be able to distinguish an existing from a non-existing role name")
}
