package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForSoD builds the standard #452/#507/#511/#519
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/sod-policies routes,
// server/http/handlers/sod_proxy.go), and a "downstream" *core.KeyorixCore
// configured with storage.type: remote (ADR-049), pointed at "upstream" over
// real HTTP via store.RemoteStorage. Mirrors
// newUpstreamDownstreamForMemberships exactly.
func newUpstreamDownstreamForSoD(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	// #1529: CreateSoDPolicy/DeleteSoDPolicy now require admin-tier authority
	// (a bare node credential, zero RBAC permissions by design, can no longer
	// define or retire a governance control) -- use a real admin session token
	// (createTestToken's "testadmin", admin-tier, bypasses permission checks
	// including system.write) instead of a node token, so this file's tests
	// keep proving the CRUD round-trip, unaffected by the new authority gate.
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

// TestRemoteStorageSoDPolicy_CreateGetList_RealServer proves the #519 fix for
// CreateSoDPolicy/GetSoDPolicy/ListSoDPolicies: a policy is genuinely persisted
// on the upstream server via the DOWNSTREAM's RemoteStorage, fetchable by ID,
// and listed — all via storage.type: remote against a real router, not a
// protocol mock.
func TestRemoteStorageSoDPolicy_CreateGetList_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSoD(t)
	ctx := context.Background()

	p, err := downstream.Storage().CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "no-approve-and-administer",
		Description: "one principal must not both approve access requests and administer secrets",
		PermissionA: "access_requests.approve",
		PermissionB: "secrets.admin",
		CreatedBy:   1,
	})
	require.NoError(t, err, "creating a SoD policy must succeed via storage.type: remote")
	require.NotZero(t, p.ID, "the upstream must assign a real ID")
	assert.Equal(t, "no-approve-and-administer", p.Name)
	assert.Equal(t, "access_requests.approve", p.PermissionA)
	assert.Equal(t, "secrets.admin", p.PermissionB)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetSoDPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "no-approve-and-administer", direct.Name)

	// GetSoDPolicy via the downstream (RemoteStorage) round-trips every field
	// correctly.
	fetched, err := downstream.Storage().GetSoDPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, p.ID, fetched.ID)
	assert.Equal(t, p.Name, fetched.Name)
	assert.Equal(t, p.Description, fetched.Description)
	assert.Equal(t, p.PermissionA, fetched.PermissionA)
	assert.Equal(t, p.PermissionB, fetched.PermissionB)

	// A second policy, then list both back via the downstream's
	// ListSoDPolicies.
	p2, err := downstream.Storage().CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "no-create-and-delete-users",
		PermissionA: "users.create",
		PermissionB: "users.delete",
	})
	require.NoError(t, err)

	rows, err := downstream.Storage().ListSoDPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Name] = true
	}
	assert.True(t, names[p.Name])
	assert.True(t, names[p2.Name])
}

// TestRemoteStorageSoDPolicy_GetNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a nonexistent policy ID.
func TestRemoteStorageSoDPolicy_GetNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSoD(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetSoDPolicy(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageSoDPolicy_Delete_RealServer proves DeleteSoDPolicy removes
// the row on the upstream (a policy existing = active; deleting it retires the
// rule, per local_sod.go's own doc), and that a second delete of the same ID
// (or a delete of a nonexistent ID) surfaces a clean not-found error rather
// than silently "succeeding" — mirroring local_sod.go's own
// RowsAffected == 0 check.
func TestRemoteStorageSoDPolicy_Delete_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSoD(t)
	ctx := context.Background()

	p, err := downstream.Storage().CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "to-be-deleted",
		PermissionA: "roles.assign",
		PermissionB: "secrets.delete",
	})
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().DeleteSoDPolicy(ctx, p.ID))

	// Confirm it's gone on the upstream directly.
	_, err = upstream.Storage().GetSoDPolicy(ctx, p.ID)
	require.Error(t, err, "the policy must be gone from the upstream's real storage")

	// A second delete of the same (now-gone) ID must fail cleanly, not silently
	// report success.
	err = downstream.Storage().DeleteSoDPolicy(ctx, p.ID)
	require.Error(t, err, "deleting an already-deleted policy must surface a clean not-found error")
}

// TestRemoteStorageSoDPolicy_CreateValidation_RealServer proves
// CreateSoDPolicyProxy rejects an incomplete policy body (matching
// local_sod.go's own contract — CreateSoDPolicy has no NOT NULL enforcement of
// its own, but the storage-primitive proxy still refuses an obviously-broken
// payload rather than persisting a useless half-empty row).
func TestRemoteStorageSoDPolicy_CreateValidation_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSoD(t)
	ctx := context.Background()

	_, err := downstream.Storage().CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "incomplete",
		PermissionA: "",
		PermissionB: "secrets.delete",
	})
	require.Error(t, err, "a policy missing permission_a must be rejected")
}
