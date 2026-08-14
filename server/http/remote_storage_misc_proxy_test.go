// remote_storage_misc_proxy_test.go — end-to-end coverage for #531's four
// independent sub-fixes. Mirrors remote_storage_sso_state_test.go's harness
// exactly: a real "upstream" exercised through the production NewRouter/
// handlers (including the new /api/v1/system/access-activity,
// /api/v1/system/secrets/{id}/including-deleted,
// /api/v1/system/shares/by-owner/{ownerID}, and
// /api/v1/system/users/with-role-grants routes,
// server/http/handlers/misc_remote_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote pointed at "upstream"
// over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForMiscProxy builds the standard two-server harness for
// #531's four sub-fixes, plus a live project and the bootstrap admin's own user
// ID (needed as an already-vetted actorID for CreateUserWithAssignments' own
// escalation-ceiling check).
func newUpstreamDownstreamForMiscProxy(t *testing.T) (upstream, downstream *core.KeyorixCore, projectID, adminID uint) {
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

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Misc Proxy Test Project", "")
	require.NoError(t, err)

	admin, err := upstream.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)

	return upstream, downstream, project.ID, admin.ID
}

// --- 1. Access-activity ---

// TestRemoteStorageAccessActivity_RealServer proves the fix for all five
// LastUser*Activity methods: an activity event logged directly against the
// upstream's own storage is genuinely visible via the DOWNSTREAM's
// RemoteStorage, keyed by the right user, all via storage.type: remote against
// a real router, not a protocol mock.
func TestRemoteStorageAccessActivity_RealServer(t *testing.T) {
	upstream, downstream, projectID, adminID := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, upstream.Storage().LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.read",
		UserID:    &adminID,
		ProjectID: &projectID,
		EventTime: now,
	}))
	require.NoError(t, upstream.Storage().LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.created",
		UserID:    &adminID,
		ProjectID: &projectID,
		EventTime: now.Add(time.Second),
	}))
	require.NoError(t, upstream.Storage().LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.deleted",
		UserID:    &adminID,
		ProjectID: &projectID,
		EventTime: now.Add(2 * time.Second),
	}))
	require.NoError(t, upstream.Storage().LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "role.assigned",
		UserID:    &adminID,
		ProjectID: &projectID,
		EventTime: now.Add(3 * time.Second),
	}))

	readActivity, err := downstream.Storage().LastUserSecretReadActivity(ctx, projectID)
	require.NoError(t, err, "secret-read activity lookup must succeed via storage.type: remote")
	require.Contains(t, readActivity, adminID)
	assert.WithinDuration(t, now, readActivity[adminID], time.Second)

	writeActivity, err := downstream.Storage().LastUserSecretWriteActivity(ctx, projectID)
	require.NoError(t, err)
	require.Contains(t, writeActivity, adminID)
	assert.WithinDuration(t, now.Add(time.Second), writeActivity[adminID], time.Second)

	deletionActivity, err := downstream.Storage().LastUserSecretDeletionActivity(ctx, projectID)
	require.NoError(t, err)
	require.Contains(t, deletionActivity, adminID)
	assert.WithinDuration(t, now.Add(2*time.Second), deletionActivity[adminID], time.Second)

	roleMgmtActivity, err := downstream.Storage().LastUserRoleManagementActivity(ctx, projectID)
	require.NoError(t, err)
	require.Contains(t, roleMgmtActivity, adminID)
	assert.WithinDuration(t, now.Add(3*time.Second), roleMgmtActivity[adminID], time.Second)

	// The broader "any secret activity" bucket (read+create+update+rotate)
	// picks up both the read and the create event, keeping the latest.
	broadActivity, err := downstream.Storage().LastUserSecretActivity(ctx, projectID)
	require.NoError(t, err)
	require.Contains(t, broadActivity, adminID)
	assert.WithinDuration(t, now.Add(time.Second), broadActivity[adminID], time.Second)

	// A project with no activity at all cleanly returns an empty map, not an
	// error.
	otherProject, err := upstream.CreateProject(ctx, "Empty Activity Project", "")
	require.NoError(t, err)
	empty, err := downstream.Storage().LastUserSecretActivity(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// --- 2. GetSecretIncludingDeleted ---

// TestRemoteStorageGetSecretIncludingDeleted_RealServer proves the #531 fix:
// ScopeFromDeletedSecretParam's scope check ahead of POST /secrets/{id}/restore
// now resolves a soft-deleted secret's scope via storage.type: remote instead
// of 404ing before ever reaching the already-proxied RestoreSecret.
func TestRemoteStorageGetSecretIncludingDeleted_RealServer(t *testing.T) {
	upstream, downstream, projectID, adminID := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()

	env, err := upstream.CreateEnvironment(ctx, projectID, "misc-proxy-env-2")
	require.NoError(t, err)

	secret, err := upstream.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "misc-proxy-secret",
		Value:         []byte("s3cr3t"),
		ProjectID:     projectID,
		EnvironmentID: env.ID,
		Type:          "generic",
		CreatedBy:     "testadmin",
		OwnerID:       adminID,
	})
	require.NoError(t, err)

	require.NoError(t, upstream.DeleteSecret(ctx, secret.ID))

	// A live (non-deleted) lookup would 404; GetSecretIncludingDeleted must
	// still resolve it via storage.type: remote.
	fetched, err := downstream.Storage().GetSecretIncludingDeleted(ctx, secret.ID)
	require.NoError(t, err, "fetching a soft-deleted secret must succeed via storage.type: remote")
	require.NotNil(t, fetched)
	assert.Equal(t, secret.ID, fetched.ID)
	assert.Equal(t, projectID, fetched.ProjectID)
	assert.Equal(t, env.ID, fetched.EnvironmentID)
	assert.True(t, fetched.DeletedAt.Valid, "the soft-delete marker must round-trip")

	// A nonexistent ID cleanly not-founds rather than panicking.
	_, err = downstream.Storage().GetSecretIncludingDeleted(ctx, 999999)
	require.Error(t, err)
}

// --- 3. ListSharesByOwner / ListSharesByUser ---

// TestRemoteStorageListSharesByOwner_RealServer proves the #531 fix:
// core.ListSharesByUser's owned-share half no longer hard-fails under
// storage.type: remote.
func TestRemoteStorageListSharesByOwner_RealServer(t *testing.T) {
	upstream, downstream, projectID, adminID := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()

	env, err := upstream.CreateEnvironment(ctx, projectID, "misc-proxy-env-3")
	require.NoError(t, err)

	secret, err := upstream.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "misc-proxy-shared-secret",
		Value:         []byte("s3cr3t"),
		ProjectID:     projectID,
		EnvironmentID: env.ID,
		Type:          "generic",
		CreatedBy:     "testadmin",
		OwnerID:       adminID,
	})
	require.NoError(t, err)

	recipient, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "shareowner-recipient",
		Email:       "shareowner-recipient@example.com",
		DisplayName: "Recipient",
		Password:    "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	created, err := upstream.Storage().CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secret.ID,
		OwnerID:     adminID,
		RecipientID: recipient.ID,
		Permission:  "read",
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	shares, err := downstream.Storage().ListSharesByOwner(ctx, adminID)
	require.NoError(t, err, "listing shares by owner must succeed via storage.type: remote")
	require.Len(t, shares, 1)
	assert.Equal(t, secret.ID, shares[0].SecretID)
	assert.Equal(t, recipient.ID, shares[0].RecipientID)

	// An owner with no shares cleanly returns an empty slice.
	empty, err := downstream.Storage().ListSharesByOwner(ctx, recipient.ID)
	require.NoError(t, err)
	assert.Empty(t, empty)

	// The recipient half (storage.ListSharesByUser) — previously 404'd against
	// a human-facing route that was never registered, closed as an incidental
	// fix alongside this one — proxies correctly too.
	received, err := downstream.Storage().ListSharesByUser(ctx, recipient.ID)
	require.NoError(t, err, "listing shares by user must succeed via storage.type: remote")
	require.Len(t, received, 1)
	assert.Equal(t, secret.ID, received[0].SecretID)
	assert.Equal(t, recipient.ID, received[0].RecipientID)

	// A recipient with no shares cleanly returns an empty slice.
	emptyReceived, err := downstream.Storage().ListSharesByUser(ctx, adminID)
	require.NoError(t, err)
	assert.Empty(t, emptyReceived)

	// Now that both halves are fixed, core.ListSharesByUser itself (backing GET
	// /api/v1/shares and gRPC ShareService.ListShares) works end to end under
	// storage.type: remote for the first time.
	combined, err := downstream.ListSharesByUser(ctx, recipient.ID)
	require.NoError(t, err, "core.ListSharesByUser must succeed via storage.type: remote")
	require.Len(t, combined, 1)
	assert.Equal(t, created.ID, combined[0].ID)
}

// --- 4. CreateUserWithRoleGrants (basic success + duplicate-email) ---
// See remote_storage_misc_proxy_atomic_test.go for the concurrent-race
// regression test proving the atomic primitive itself.

// TestRemoteStorageCreateUserWithRoleGrants_RealServer proves the basic
// success path: a user plus every role grant lands atomically on the upstream
// via the DOWNSTREAM's RemoteStorage. Calls storage.Storage.CreateUserWithRoleGrants
// directly (the raw storage primitive), not core.CreateUserWithAssignments —
// the latter's project-assignment loop needs storage.GetProject, a SEPARATE,
// still-open round-119 gap (unrelated to #531) that would make this test
// depend on a fix outside this PR's scope.
func TestRemoteStorageCreateUserWithRoleGrants_RealServer(t *testing.T) {
	upstream, downstream, _, _ := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()

	viewerRole, err := upstream.Storage().GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	adminRole, err := upstream.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)

	user := &models.User{
		Username:     "atomic-create-user",
		Email:        "atomic-create-user@example.com",
		DisplayName:  "Atomic Create",
		PasswordHash: "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01",
		IsActive:     true,
		AccountState: "active",
	}
	grants := []corestorage.RoleGrant{
		{RoleID: viewerRole.ID},
		{RoleID: adminRole.ID},
	}
	created, err := downstream.Storage().CreateUserWithRoleGrants(ctx, user, grants)
	require.NoError(t, err, "creating a user with role grants must succeed via storage.type: remote")
	require.NotZero(t, created.ID)

	// The user is a REAL row on the upstream, with the already-computed hash
	// persisted verbatim (not re-derived from a plaintext it was never given).
	direct, err := upstream.Storage().GetUser(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "atomic-create-user", direct.Username)

	// BOTH grants landed alongside the user — the whole point of the atomic
	// primitive.
	roleIDs, err := upstream.Storage().GetUserRoleIDsAt(ctx, created.ID, corestorage.Scope{})
	require.NoError(t, err)
	assert.Contains(t, roleIDs, viewerRole.ID)
	assert.Contains(t, roleIDs, adminRole.ID)
}

// TestRemoteStorageCreateUserWithRoleGrants_DuplicateEmail_RealServer proves
// the storage.ErrDuplicateEmail sentinel survives the storage.type: remote HTTP
// hop (#117-class race, translated via the duplicateEmailProxyCode wire
// signal), matching #858/#859's "classify validation-shaped errors, don't
// collapse to 500" convention. Calls the storage primitive directly (bypassing
// core.CreateUserWithAssignments' own check-then-act GetUserByEmail pre-check,
// which would otherwise short-circuit before ever reaching
// storage.CreateUserWithRoleGrants) so this genuinely exercises the DB-level
// race guard, not just the ordinary pre-check.
func TestRemoteStorageCreateUserWithRoleGrants_DuplicateEmail_RealServer(t *testing.T) {
	upstream, downstream, _, _ := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()

	_, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "dup-email-owner",
		Email:       "dup-email@example.com",
		DisplayName: "Dup Owner",
		Password:    "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	viewerRole, err := upstream.Storage().GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	_, err = downstream.Storage().CreateUserWithRoleGrants(ctx, &models.User{
		Username:     "dup-email-newcomer",
		Email:        "dup-email@example.com",
		DisplayName:  "Dup Newcomer",
		PasswordHash: "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01",
		IsActive:     true,
		AccountState: "active",
	}, []corestorage.RoleGrant{{RoleID: viewerRole.ID}})
	require.Error(t, err, "creating a user with an already-used email must fail, not silently succeed")
	assert.True(t, errors.Is(err, corestorage.ErrDuplicateEmail),
		"the storage.ErrDuplicateEmail sentinel must survive the storage.type: remote HTTP hop")

	// The rejected create must not have persisted a half-formed user (the
	// atomic transaction must have rolled back entirely).
	_, lookupErr := upstream.Storage().GetUserByUsername(ctx, "dup-email-newcomer")
	require.Error(t, lookupErr, "a rejected duplicate-email create must not leave a stray user row behind")
	assert.True(t, errors.Is(lookupErr, corestorage.ErrUserNotFound) || corestorage.IsUserNotFound(lookupErr))
}
