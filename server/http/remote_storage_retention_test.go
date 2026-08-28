// remote_storage_retention_test.go — end-to-end proxy tests for finding #520's
// remaining three data-retention/purge-sweep RemoteStorage methods
// (server/http/handlers/retention_proxy.go): each test seeds a mix of
// eligible/ineligible rows directly against the upstream's real storage, drives
// the sweep through a REAL downstream RemoteStorage client over a real HTTP
// server (not a protocol mock), and confirms exactly the eligible rows were
// purged/returned while every ineligible row survives untouched.
//
// PurgeDeletedSecretsBefore/PurgeDeletedUsersBefore/PurgeDeletedProjectsBefore/
// PurgeDeletedEnvironmentsBefore and their tests were DELETED (#1593,
// docs/adr-089-mfa-purge-relay-deletion.md) — no live caller.
package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForRetention builds the standard #507/#511/#519-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/retention routes,
// server/http/handlers/retention_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForRetention(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

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

// TestRemoteStorageDeleteExpiredRoleGrants_RealServer proves
// DeleteExpiredRoleGrantsProxy round-trips the FULL removed
// storage.RoleAssignment rows (not just a count) — internal/core.
// RemoveExpiredRoleGrants needs the actual principal/role/scope data to write one
// role.expired audit event per grant. A still-live (unexpired) grant is never
// touched.
func TestRemoteStorageDeleteExpiredRoleGrants_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRetention(t)
	ctx := context.Background()
	scope := coreStorage.Scope{ProjectID: 7, EnvironmentID: 3}

	require.NoError(t, upstream.Storage().AssignRoleWithExpiry(ctx, 101, 5, scope, time.Now().Add(-time.Hour)))
	require.NoError(t, upstream.Storage().AssignRoleToGroupWithExpiry(ctx, 202, 6, scope, time.Now().Add(-time.Hour)))
	// A still-live, non-expiring grant at a DIFFERENT scope — must survive.
	liveScope := coreStorage.Scope{ProjectID: 8, EnvironmentID: 0}
	require.NoError(t, upstream.Storage().AssignRole(ctx, 303, 9, liveScope))

	removed, err := downstream.Storage().DeleteExpiredRoleGrants(ctx, time.Now())
	require.NoError(t, err)
	require.Len(t, removed, 2, "exactly the two expired grants are removed")

	byType := map[string]coreStorage.RoleAssignment{}
	for _, r := range removed {
		byType[r.PrincipalType] = r
	}
	require.Contains(t, byType, "user")
	require.Contains(t, byType, "group")
	assert.EqualValues(t, 101, byType["user"].PrincipalID, "the full row data (not just a count) round-trips")
	assert.EqualValues(t, 5, byType["user"].RoleID)
	assert.EqualValues(t, 7, byType["user"].ProjectID)
	assert.EqualValues(t, 3, byType["user"].EnvironmentID)
	assert.EqualValues(t, 202, byType["group"].PrincipalID)
	assert.EqualValues(t, 6, byType["group"].RoleID)

	liveRoleIDs, err := upstream.Storage().GetUserRoleIDsAt(ctx, 303, liveScope)
	require.NoError(t, err)
	assert.Contains(t, liveRoleIDs, uint(9), "the still-live grant at a different scope must survive")
}

// TestRemoteStorageDeleteExpiredShareRecords_RealServer proves
// DeleteExpiredShareRecordsProxy round-trips the FULL removed
// *models.ShareRecord rows (not just a count) — internal/core.RemoveExpiredShares
// needs the actual secret/recipient data to write one share.expired audit event
// per share. A permanent (nil ExpiresAt) share is never touched.
func TestRemoteStorageDeleteExpiredShareRecords_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRetention(t)
	ctx := context.Background()

	owner, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "owner1", Email: "owner1@example.com", IsActive: true})
	require.NoError(t, err)
	recipient, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "recipient1", Email: "recipient1@example.com", IsActive: true})
	require.NoError(t, err)

	project, err := upstream.CreateProject(ctx, "Share Retention Project", "")
	require.NoError(t, err)
	envs, err := upstream.Storage().ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	secret, err := upstream.Storage().CreateSecret(ctx, &models.SecretNode{
		Name: "shared-secret", ProjectID: project.ID, EnvironmentID: envs[0].ID, Type: "generic", OwnerID: owner.ID,
	})
	require.NoError(t, err)

	expiredAt := time.Now().Add(-time.Hour)
	expiredShare, err := upstream.Storage().CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: owner.ID, RecipientID: recipient.ID, Permission: "read", ExpiresAt: &expiredAt,
	})
	require.NoError(t, err)

	// A second, permanent share to a different recipient — must survive.
	recipient2, err := upstream.Storage().CreateUser(ctx, &models.User{Username: "recipient2", Email: "recipient2@example.com", IsActive: true})
	require.NoError(t, err)
	_, err = upstream.Storage().CreateShareRecord(ctx, &models.ShareRecord{
		SecretID: secret.ID, OwnerID: owner.ID, RecipientID: recipient2.ID, Permission: "write",
	})
	require.NoError(t, err)

	removed, err := downstream.Storage().DeleteExpiredShareRecords(ctx, time.Now())
	require.NoError(t, err)
	require.Len(t, removed, 1, "only the expired share is removed")
	assert.Equal(t, secret.ID, removed[0].SecretID, "the full row data (not just a count) round-trips")
	assert.Equal(t, recipient.ID, removed[0].RecipientID)
	assert.False(t, removed[0].IsGroup)
	assert.Equal(t, "read", removed[0].Permission)

	_, err = upstream.Storage().GetShareRecord(ctx, expiredShare.ID)
	require.Error(t, err, "the expired share must be gone")

	survivors, err := upstream.Storage().ListSharesByUser(ctx, recipient2.ID)
	require.NoError(t, err)
	assert.Len(t, survivors, 1, "the permanent share must survive")
}

// TestRemoteStorageListUsersInStateBefore_RealServer proves
// ListUsersInStateBeforeProxy: only a user in the requested account_state,
// created before the cutoff, is returned — backing internal/core.StaleAccounts
// (ADR-025 stale-account warnings).
func TestRemoteStorageListUsersInStateBefore_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForRetention(t)
	ctx := context.Background()

	// CreatedAt is set explicitly, matching every real production CreateUser call
	// site (internal/core/users.go, scim.go, sso.go all set it themselves) — a
	// User created without it relies on GORM's own auto-timestamp, which (verified
	// empirically during the G81 sweep, see StatsSnapshot.CreatedAt's doc comment)
	// a BeforeSave hook cannot reach, since GORM auto-assigns it AFTER BeforeSave
	// runs.
	stale, err := upstream.Storage().CreateUser(ctx, &models.User{
		Username: "stale-invite", Email: "stale-invite@example.com", IsActive: true,
		AccountState: core.AccountPendingFirstLogin, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// A different account state — must not match the "pending_first_login" query.
	_, err = upstream.Storage().CreateUser(ctx, &models.User{
		Username: "active-user", Email: "active-user@example.com", IsActive: true,
		AccountState: core.AccountActive,
	})
	require.NoError(t, err)

	rows, err := downstream.Storage().ListUsersInStateBefore(ctx, core.AccountPendingFirstLogin, time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, stale.ID, rows[0].ID)
	assert.Equal(t, "stale-invite", rows[0].Username)
	assert.Equal(t, core.AccountPendingFirstLogin, rows[0].AccountState)
}
