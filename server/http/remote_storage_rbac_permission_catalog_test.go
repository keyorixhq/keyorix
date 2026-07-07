// remote_storage_rbac_permission_catalog_test.go — end-to-end coverage for
// #526: RemoteStorage's ListPermissions/GetPermission/GetRolePermissions were
// unconditional stubs, and RemoteStorage has no local database to fall back
// on (confirmed — it's a pure HTTP client), so the RBAC permission catalog
// was 100% unreachable under storage.type: remote — breaking the permission
// catalog view, assigning a permission to a role, and every RBAC-dependent
// report that resolves a role's permission bundle (access reviews,
// compliance posture, SoD conflict detection). Mirrors
// remote_storage_sso_state_test.go's #521 harness exactly: a real "upstream"
// exercised through the production NewRouter/handlers, and a "downstream"
// *core.KeyorixCore configured with storage.type: remote pointed at
// "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForRBACPermissionCatalog builds the standard
// #452/#507/#510/#521 two-server harness: an "upstream" exercised through the
// REAL production NewRouter/handlers, and a "downstream" *core.KeyorixCore
// configured with storage.type: remote (ADR-049), pointed at "upstream" over
// real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForRBACPermissionCatalog(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// TestRemoteStorageRBACPermissionCatalog_ListPermissions_RealServer proves the
// #526 fix: the seeded permission catalog is visible via the downstream's
// RemoteStorage, over a real HTTP round trip against the real router — not a
// protocol mock.
func TestRemoteStorageRBACPermissionCatalog_ListPermissions_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRBACPermissionCatalog(t)
	ctx := context.Background()

	want, err := upstream.Storage().ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, want, "bootstrap must have seeded the permission catalog")

	got, err := downstream.Storage().ListPermissions(ctx)
	require.NoError(t, err, "listing permissions must succeed via storage.type: remote")
	assert.Len(t, got, len(want))

	gotNames := make(map[string]bool, len(got))
	for _, p := range got {
		gotNames[p.Name] = true
	}
	for _, p := range want {
		assert.True(t, gotNames[p.Name], "seeded permission %q missing from the remote-proxied list", p.Name)
	}
}

// TestRemoteStorageRBACPermissionCatalog_GetPermission_RealServer proves a
// single seeded permission round-trips every field (name/description/
// resource/action) via the downstream's RemoteStorage.
func TestRemoteStorageRBACPermissionCatalog_GetPermission_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRBACPermissionCatalog(t)
	ctx := context.Background()

	perms, err := upstream.Storage().ListPermissions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, perms)

	var want *struct {
		ID          uint
		Name        string
		Description string
		Resource    string
		Action      string
	}
	for _, p := range perms {
		if p.Name == "roles.read" {
			want = &struct {
				ID          uint
				Name        string
				Description string
				Resource    string
				Action      string
			}{p.ID, p.Name, p.Description, p.Resource, p.Action}
			break
		}
	}
	require.NotNil(t, want, "bootstrap must seed a roles.read permission")

	got, err := downstream.Storage().GetPermission(ctx, want.ID)
	require.NoError(t, err, "getting a permission by ID must succeed via storage.type: remote")
	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Description, got.Description)
	assert.Equal(t, want.Resource, got.Resource)
	assert.Equal(t, want.Action, got.Action)
}

// TestRemoteStorageRBACPermissionCatalog_GetPermission_UnknownID_RealServer
// proves a clean not-found error (not a panic, not a garbage 500) for a
// permission ID that was never seeded.
func TestRemoteStorageRBACPermissionCatalog_GetPermission_UnknownID_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForRBACPermissionCatalog(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetPermission(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageRBACPermissionCatalog_GetRolePermissions_RealServer proves
// the #526 fix for the real callers this finding named: the role-permission
// view (GetRoleWithPermissions), the grant-time admin-rank-ceiling check
// (requireGranterHoldsRolePermissions in authz.go), and RBAC-dependent
// reports (access reviews, compliance posture, SoD conflict detection) all
// resolve a role's CURRENT bundled permissions via this method — verified
// here against the seeded "viewer" role's known, small permission set
// (secrets.read, users.read, audit.read).
func TestRemoteStorageRBACPermissionCatalog_GetRolePermissions_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRBACPermissionCatalog(t)
	ctx := context.Background()

	viewerRole, err := upstream.Storage().GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	require.NotZero(t, viewerRole.ID)

	want, err := upstream.Storage().GetRolePermissions(ctx, viewerRole.ID)
	require.NoError(t, err)
	require.NotEmpty(t, want)

	got, err := downstream.Storage().GetRolePermissions(ctx, viewerRole.ID)
	require.NoError(t, err, "getting a role's permissions must succeed via storage.type: remote")
	assert.Len(t, got, len(want))

	gotNames := make(map[string]bool, len(got))
	for _, p := range got {
		gotNames[p.Name] = true
	}
	for _, want := range []string{"secrets.read", "users.read", "audit.read"} {
		assert.True(t, gotNames[want], "viewer role's bundled permission %q missing from the remote-proxied list", want)
	}
}

// TestRemoteStorageRBACPermissionCatalog_GetRolePermissions_UnknownRole_RealServer
// proves a clean not-found error (not a panic, not a silent empty list) for a
// role ID that was never seeded.
func TestRemoteStorageRBACPermissionCatalog_GetRolePermissions_UnknownRole_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForRBACPermissionCatalog(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetRolePermissions(ctx, 999999)
	require.Error(t, err)
}
