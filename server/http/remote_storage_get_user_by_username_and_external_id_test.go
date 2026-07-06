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

// TestRemoteStorage_GetUserByUsername_RealServerRoundTrip proves the fix for
// #505: RemoteStorage.GetUserByUsername was an unconditional
// storage.ErrUnsupportedByBackend stub. The fix adds GET
// /api/v1/users/by-username (query-parameter scoped, mirroring GetUserByEmail's
// #503 convention), gated by the SAME users.read permission GetUser/
// GetUserByEmail already require, returning the same generic NotFound shape on
// a miss so the route introduces no new username-enumeration surface beyond
// what a users.read caller already has via GET /users.
//
// Drives the method through a REAL running server (NewRouter) via a REAL
// RemoteStorage client over real HTTP, per this package's established pattern
// (see TestRemoteStorage_GetUserByEmail_RealServerRoundTrip).
func TestRemoteStorage_GetUserByUsername_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)
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

	rs := newClient(upstreamToken)

	// --- the user genuinely exists: must be found, not 404 ---
	got, err := rs.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err, "GetUserByUsername must reach the real /api/v1/users/by-username route and succeed for a user that genuinely exists (#505)")
	require.NotNil(t, got)
	assert.Equal(t, "testadmin", got.Username)
	assert.Equal(t, "testadmin@example.com", got.Email)

	// --- the user genuinely does NOT exist: real not-found, not a routing 404 ---
	_, err = rs.GetUserByUsername(ctx, "does-not-exist")
	require.Error(t, err)
	var notFoundErr *remote.HTTPError
	require.True(t, errors.As(err, &notFoundErr), "expected a structured remote.HTTPError")
	assert.Equal(t, http.StatusNotFound, notFoundErr.StatusCode)

	// --- gating: identical denial whether the username exists or not ---
	limitedRS := newClient(limitedToken)

	_, existsErr := limitedRS.GetUserByUsername(ctx, "testadmin")
	require.Error(t, existsErr)
	var existsHTTPErr *remote.HTTPError
	require.True(t, errors.As(existsErr, &existsHTTPErr))

	_, notExistsErr := limitedRS.GetUserByUsername(ctx, "does-not-exist")
	require.Error(t, notExistsErr)
	var notExistsHTTPErr *remote.HTTPError
	require.True(t, errors.As(notExistsErr, &notExistsHTTPErr))

	assert.Equal(t, http.StatusForbidden, existsHTTPErr.StatusCode)
	assert.Equal(t, existsHTTPErr.StatusCode, notExistsHTTPErr.StatusCode,
		"gating must not leak existence via a different status for an existing vs a non-existing username")
}

// TestRemoteStorage_GetUserByExternalID_RealServerRoundTrip proves the fix for
// #505: RemoteStorage.GetUserByExternalID was an unconditional
// storage.ErrUnsupportedByBackend stub, so both resolveSSOUser's
// (internal/core/sso.go) externalId-first branch and FindSCIMUser's
// (internal/core/scim.go) externalId-first branch hard-failed unconditionally
// under storage.type: remote — storage.IsUserNotFound(ErrUnsupportedByBackend)
// is false, so neither call site's "fall through to the email fallback" path
// was ever reachable when sub/externalID was non-empty.
//
// The fix adds GET /api/v1/users/by-external-id (same query-parameter/
// permission/NotFound-shape convention as by-email and by-username), and also
// puts external_id on the wire response (userToAPIResponse/userWireResponse) —
// without which a decoded user's ExternalID always read back as "" regardless
// of what the upstream actually stored, silently defeating
// ssoBoundToOtherProvider's cross-provider-takeover guard on the (already
// shipped, #504) email-fallback branch too.
func TestRemoteStorage_GetUserByExternalID_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)
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

	// Stamp a real external_id on the seeded admin, directly against the
	// upstream's own storage — exactly what a SCIM/SSO JIT-provisioning flow
	// would have set, so this test proves a genuine round trip rather than
	// asserting against a value this test itself invents client-side.
	adminUser, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	adminUser.ExternalID = "sso:okta:okta|admin-123"
	_, err = upstreamCore.Storage().UpdateUser(ctx, adminUser)
	require.NoError(t, err)

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

	rs := newClient(upstreamToken)

	// --- the external_id genuinely exists: must be found, and the ExternalID
	// field itself must round-trip correctly (proves the wire-response fix,
	// not just the route) ---
	got, err := rs.GetUserByExternalID(ctx, "sso:okta:okta|admin-123")
	require.NoError(t, err, "GetUserByExternalID must reach the real /api/v1/users/by-external-id route and succeed for an external_id that genuinely exists (#505)")
	require.NotNil(t, got)
	assert.Equal(t, "testadmin", got.Username)
	assert.Equal(t, "sso:okta:okta|admin-123", got.ExternalID,
		"the ExternalID field itself must round-trip over the wire, not just the lookup succeed")

	// GetUserByEmail/GetUser must ALSO now carry external_id correctly — the
	// #504 email-fallback branch's ssoBoundToOtherProvider guard depends on this.
	gotByEmail, err := rs.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	assert.Equal(t, "sso:okta:okta|admin-123", gotByEmail.ExternalID,
		"GetUserByEmail must also surface external_id now that it is on the wire")

	// --- the external_id genuinely does NOT exist: real not-found ---
	_, err = rs.GetUserByExternalID(ctx, "sso:okta:does-not-exist")
	require.Error(t, err)
	var notFoundErr *remote.HTTPError
	require.True(t, errors.As(err, &notFoundErr), "expected a structured remote.HTTPError")
	assert.Equal(t, http.StatusNotFound, notFoundErr.StatusCode)

	// --- gating: identical denial whether the external_id exists or not ---
	limitedRS := newClient(limitedToken)

	_, existsErr := limitedRS.GetUserByExternalID(ctx, "sso:okta:okta|admin-123")
	require.Error(t, existsErr)
	var existsHTTPErr *remote.HTTPError
	require.True(t, errors.As(existsErr, &existsHTTPErr))

	_, notExistsErr := limitedRS.GetUserByExternalID(ctx, "sso:okta:does-not-exist")
	require.Error(t, notExistsErr)
	var notExistsHTTPErr *remote.HTTPError
	require.True(t, errors.As(notExistsErr, &notExistsHTTPErr))

	assert.Equal(t, http.StatusForbidden, existsHTTPErr.StatusCode)
	assert.Equal(t, existsHTTPErr.StatusCode, notExistsHTTPErr.StatusCode,
		"gating must not leak existence via a different status for an existing vs a non-existing external_id")
}
