// remote_storage_rbac_role_grants_test.go — end-to-end coverage for finding #525:
// RemoteStorage's RBAC role-grant primitives (GetGroupRoleGrants/
// AssignRoleWithExpiry/AssignRoleToGroupWithExpiry/RemoveAllProjectRoleGrants/
// ListGroupRoleAssignments/ListGlobalAdminAssignmentsForUpdate/
// ListProjectRoleAssignments/ListProjectMachineRoleAssignments/
// RemoveGlobalAdminRoleGuarded) were unconditional stubs, breaking adding a user
// to a group, removing a project member, JIT time-bound role grants, and every
// last-global-admin lockout guard under storage.type: remote.
//
// Follows this package's established real-server harness (see
// remote_storage_secret_dependencies_test.go): a REAL upstream exercised through
// the production NewRouter/handlers (including the new
// /api/v1/system/rbac/... routes, server/http/handlers/
// rbac_role_grants_proxy.go), and a downstream *core.KeyorixCore backed by a real
// store.RemoteStorage client over real HTTP.
package http

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createRBACDriverToken creates a fresh admin identity (held via the
// system_admin role, deliberately DISTINCT from the "admin" role the
// last-global-admin tests below juggle) and returns a session token for it —
// used to drive the downstream RemoteStorage client in tests that remove the
// bootstrap admin's OWN "admin"-role grant. Reusing the bootstrap admin's own
// token for those calls would be self-defeating: the moment that removal
// succeeds, the bootstrap admin's session immediately loses system.write
// (permissions are evaluated per-request against CURRENT role assignments, not
// cached at login), so every SUBSEQUENT call over that same token would 403
// regardless of whether the RBAC logic under test is correct.
func createRBACDriverToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	systemAdminRole, err := c.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	driver, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "rbacguardtestdriver", Email: "rbac-guard-test-driver@example.com",
		DisplayName: "RBAC Guard Driver", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRole(ctx, driver.ID, systemAdminRole.ID, coreStorage.Scope{}))
	session, _, err := c.Login(ctx, &core.LoginRequest{Username: "rbacguardtestdriver", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return session.SessionToken
}

// TestRemoteStorageRBACRoleGrants_ReadsAndWrites_RealServer proves the fix for
// GetGroupRoleGrants/AssignRoleWithExpiry/AssignRoleToGroupWithExpiry/
// ListGroupRoleAssignments/ListProjectRoleAssignments/
// ListProjectMachineRoleAssignments/RemoveAllProjectRoleGrants/
// ListGlobalAdminAssignmentsForUpdate: every one of these round-trips through the
// downstream's RemoteStorage against real rows on the upstream's own storage, not
// just "the call didn't error".
func TestRemoteStorageRBACRoleGrants_ReadsAndWrites_RealServer(t *testing.T) {
	upstream, srv, token := newUpstreamForSecretDependencies(t) // shared harness helper
	downstream := newDownstreamRemoteStorage(t, srv, token)
	ctx := context.Background()

	// Fixtures, created directly against the upstream's own storage (exactly what
	// a real admin action would have produced).
	role, err := upstream.Storage().CreateRole(ctx, &models.Role{Name: "rbac-grants-test-role", Description: "test role"})
	require.NoError(t, err)

	group, err := upstream.Storage().CreateGroup(ctx, &models.Group{Name: "rbac-grants-test-group"})
	require.NoError(t, err)

	user, err := upstream.Storage().CreateUser(ctx, &models.User{
		Username: "rbac-grants-test-user", Email: "rbac-grants-test-user@example.com",
	}, "TestPassword123!")
	require.NoError(t, err)

	const projectID = uint(777)
	expiresAt := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)

	// --- AssignRoleWithExpiry: a JIT time-bound grant to the user, via the downstream ---
	require.NoError(t, downstream.Storage().AssignRoleWithExpiry(ctx, user.ID, role.ID, coreStorage.Scope{ProjectID: projectID}, expiresAt),
		"AssignRoleWithExpiry must reach the real /api/v1/system/rbac/assign-role-with-expiry route")

	// A REAL row on the upstream's own storage, not just "the call didn't error".
	directAssignments, err := upstream.Storage().ListProjectRoleAssignments(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, directAssignments, 1)
	assert.Equal(t, "user", directAssignments[0].PrincipalType)
	assert.Equal(t, user.ID, directAssignments[0].PrincipalID)
	assert.Equal(t, role.ID, directAssignments[0].RoleID)

	// --- ListProjectRoleAssignments via the downstream ---
	remoteAssignments, err := downstream.Storage().ListProjectRoleAssignments(ctx, projectID)
	require.NoError(t, err, "ListProjectRoleAssignments must reach the real proxy route")
	require.Len(t, remoteAssignments, 1)
	assert.Equal(t, user.ID, remoteAssignments[0].PrincipalID)

	// --- AssignRoleToGroupWithExpiry: a JIT time-bound grant to the group ---
	require.NoError(t, downstream.Storage().AssignRoleToGroupWithExpiry(ctx, group.ID, role.ID, coreStorage.Scope{ProjectID: projectID}, expiresAt),
		"AssignRoleToGroupWithExpiry must reach the real proxy route")

	// --- GetGroupRoleGrants via the downstream ---
	grants, err := downstream.Storage().GetGroupRoleGrants(ctx, group.ID)
	require.NoError(t, err, "GetGroupRoleGrants must reach the real proxy route")
	require.Len(t, grants, 1)
	assert.Equal(t, role.ID, grants[0].ID)
	assert.Equal(t, role.Name, grants[0].Name)
	require.NotNil(t, grants[0].ExpiresAt)
	assert.WithinDuration(t, expiresAt, *grants[0].ExpiresAt, time.Second)

	// --- ListGroupRoleAssignments via the downstream ---
	groupAssignments, err := downstream.Storage().ListGroupRoleAssignments(ctx, group.ID)
	require.NoError(t, err, "ListGroupRoleAssignments must reach the real proxy route")
	require.Len(t, groupAssignments, 1)
	assert.Equal(t, "group", groupAssignments[0].PrincipalType)
	assert.Equal(t, group.ID, groupAssignments[0].PrincipalID)
	assert.Equal(t, projectID, groupAssignments[0].ProjectID)

	// --- ListProjectMachineRoleAssignments: a machine-identity grant ---
	machine, err := upstream.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: projectID, Name: "rbac-grants-test-machine", IdentityType: "service", State: "active",
	})
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().AssignMachineRole(ctx, machine.ID, role.ID, coreStorage.Scope{ProjectID: projectID}))

	machineAssignments, err := downstream.Storage().ListProjectMachineRoleAssignments(ctx, projectID)
	require.NoError(t, err, "ListProjectMachineRoleAssignments must reach the real proxy route")
	require.Len(t, machineAssignments, 1)
	assert.Equal(t, "machine", machineAssignments[0].PrincipalType)
	assert.Equal(t, machine.ID, machineAssignments[0].PrincipalID)

	// --- ListGlobalAdminAssignmentsForUpdate: a plain read over the seeded admin ---
	adminRole, err := upstream.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	globalAdmins, err := downstream.Storage().ListGlobalAdminAssignmentsForUpdate(ctx, []uint{adminRole.ID})
	require.NoError(t, err, "ListGlobalAdminAssignmentsForUpdate must reach the real proxy route")
	require.Len(t, globalAdmins, 1, "the bootstrap admin holds the seeded global admin role")
	assert.Equal(t, adminRole.ID, globalAdmins[0].RoleID)

	// --- RemoveAllProjectRoleGrants: bulk-removes the user's project-scoped grant ---
	require.NoError(t, downstream.Storage().RemoveAllProjectRoleGrants(ctx, user.ID, projectID),
		"RemoveAllProjectRoleGrants must reach the real proxy route")

	after, err := upstream.Storage().ListProjectRoleAssignments(ctx, projectID)
	require.NoError(t, err)
	for _, a := range after {
		assert.False(t, a.PrincipalType == "user" && a.PrincipalID == user.ID,
			"the user's project-scoped grant must actually be gone from the upstream's own storage")
	}
}

// TestRemoteStorageRBACRoleGrants_RemoveGlobalAdminRoleGuarded_RealServer proves
// RemoveGlobalAdminRoleGuarded's atomic check-then-remove: refuses when the
// target is the last global admin, succeeds and actually removes the row when
// another survives, and reports ErrRoleNotAssigned (not a generic error) when the
// grant doesn't exist — the exact sentinels internal/core/rbac_management.go's
// RemoveUserRole depends on surviving the HTTP hop.
func TestRemoteStorageRBACRoleGrants_RemoveGlobalAdminRoleGuarded_RealServer(t *testing.T) {
	upstream, srv, _ := newUpstreamForSecretDependencies(t)
	driverToken := createRBACDriverToken(t, upstream)
	downstream := newDownstreamRemoteStorage(t, srv, driverToken)
	ctx := context.Background()

	adminRole, err := upstream.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	adminIDs := []uint{adminRole.ID}

	bootstrapAdmin, err := upstream.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	// --- refused: the bootstrap admin is currently the ONLY global admin ---
	err = downstream.Storage().RemoveGlobalAdminRoleGuarded(ctx, bootstrapAdmin.ID, adminRole.ID, adminIDs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrWouldStrandLastAdmin),
		"the refusal must survive the HTTP hop as the exact sentinel, not an opaque error: %v", err)

	// A second global admin — now the removal above would no longer strand the install.
	secondAdmin, err := upstream.Storage().CreateUser(ctx, &models.User{
		Username: "rbac-guarded-second-admin", Email: "rbac-guarded-second-admin@example.com",
	}, "TestPassword123!")
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().AssignRole(ctx, secondAdmin.ID, adminRole.ID, coreStorage.Scope{}))

	// --- succeeds: another admin survives ---
	require.NoError(t, downstream.Storage().RemoveGlobalAdminRoleGuarded(ctx, bootstrapAdmin.ID, adminRole.ID, adminIDs))

	// A REAL removal on the upstream's own storage.
	remaining, err := upstream.Storage().ListGlobalAdminAssignmentsForUpdate(ctx, adminIDs)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "exactly the second admin's grant must remain")
	assert.Equal(t, secondAdmin.ID, remaining[0].PrincipalID)

	// --- refused again: the second admin is now the last one ---
	err = downstream.Storage().RemoveGlobalAdminRoleGuarded(ctx, secondAdmin.ID, adminRole.ID, adminIDs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrWouldStrandLastAdmin))

	// --- not assigned: the bootstrap admin's grant was already removed above ---
	err = downstream.Storage().RemoveGlobalAdminRoleGuarded(ctx, bootstrapAdmin.ID, adminRole.ID, adminIDs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrRoleNotAssigned),
		"a nonexistent grant must surface ErrRoleNotAssigned, not ErrWouldStrandLastAdmin: %v", err)
}

// TestRemoteStorageRBACRoleGrants_ConcurrentRace_LastAdminNeverStranded_RealServer
// is the cross-process analogue of internal/core's
// TestConcurrency_RemoveUserRole_CannotStrandLastTwoAdmins (#340): TWO INDEPENDENT
// *store.RemoteStorage clients (standing in for two downstream spoke servers, each
// with its OWN process-local globalAdminGuardMu that cannot serialize across them)
// race to remove each OTHER's global admin grant against the SAME upstream, via
// RemoveGlobalAdminRoleGuarded directly.
//
// Before this fix (a caller-orchestrated ListGlobalAdminAssignmentsForUpdate +
// RemoveRole sequence inside a WithTransaction closure, with
// RemoteStorage.WithTransaction a no-op passthrough), nothing would have prevented
// both requests from observing "another admin still exists" and both succeeding,
// stranding the install with zero admins. With RemoveGlobalAdminRoleGuarded, the
// upstream's own LocalStorage transaction serializes the two concurrent HTTP
// requests, so exactly one must win.
func TestRemoteStorageRBACRoleGrants_ConcurrentRace_LastAdminNeverStranded_RealServer(t *testing.T) {
	upstream, srv, _ := newUpstreamForSecretDependencies(t)
	driverToken := createRBACDriverToken(t, upstream)
	ctx := context.Background()

	adminRole, err := upstream.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	adminIDs := []uint{adminRole.ID}

	// The bootstrap admin ALSO holds the "admin" role at the global scope
	// (createTestToken's bootstrap flow) — left in place, it would permanently
	// satisfy "another admin survives" for every userA/userB pair below,
	// letting BOTH concurrent removals succeed regardless of the race this test
	// exists to prove. Strip it up front via a raw storage call (no HTTP hop, no
	// guard needed — this is fixture setup, not the flow under test) so the
	// admin-role holder set for the rest of this test is EXACTLY {userA, userB}
	// each iteration.
	bootstrapAdmin, err := upstream.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	require.NoError(t, upstream.Storage().RemoveRole(ctx, bootstrapAdmin.ID, adminRole.ID, coreStorage.Scope{}))

	const iterations = 6
	for i := 0; i < iterations; i++ {
		// Exactly two global admins per iteration: userA and userB, freshly
		// created. The previous iteration's WINNER (if any) is stripped of its
		// admin-role grant at the end of the loop body below, so the admin-role
		// holder set going into THIS iteration's race is exactly {userA, userB} —
		// otherwise every prior iteration's survivor would silently accumulate as
		// a permanent extra admin, letting BOTH of the current iteration's
		// concurrent removals succeed regardless of whether the fix under test
		// actually serializes them.
		userA, err := upstream.Storage().CreateUser(ctx, &models.User{
			Username: fmt.Sprintf("rbac-race-admin-a-%d", i), Email: fmt.Sprintf("rbac-race-admin-a-%d@example.com", i),
		}, "TestPassword123!")
		require.NoError(t, err)
		userB, err := upstream.Storage().CreateUser(ctx, &models.User{
			Username: fmt.Sprintf("rbac-race-admin-b-%d", i), Email: fmt.Sprintf("rbac-race-admin-b-%d@example.com", i),
		}, "TestPassword123!")
		require.NoError(t, err)
		require.NoError(t, upstream.Storage().AssignRole(ctx, userA.ID, adminRole.ID, coreStorage.Scope{}))
		require.NoError(t, upstream.Storage().AssignRole(ctx, userB.ID, adminRole.ID, coreStorage.Scope{}))

		downstreamA := newDownstreamRemoteStorage(t, srv, driverToken)
		downstreamB := newDownstreamRemoteStorage(t, srv, driverToken)

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			results[0] = downstreamA.Storage().RemoveGlobalAdminRoleGuarded(ctx, userA.ID, adminRole.ID, adminIDs)
		}()
		go func() {
			defer wg.Done()
			<-start
			results[1] = downstreamB.Storage().RemoveGlobalAdminRoleGuarded(ctx, userB.ID, adminRole.ID, adminIDs)
		}()
		close(start)
		wg.Wait()

		succeeded, refused := 0, 0
		for _, e := range results {
			if e == nil {
				succeeded++
			} else {
				assert.True(t, errors.Is(e, coreStorage.ErrWouldStrandLastAdmin),
					"iteration %d: the loser must fail with the exact sentinel, not an opaque error: %v", i, e)
				refused++
			}
		}
		assert.Equal(t, 1, succeeded, "iteration %d: exactly one of the two concurrent removals must succeed", i)
		assert.Equal(t, 1, refused, "iteration %d: exactly one of the two concurrent removals must be refused", i)

		stillHeld, err := upstream.Storage().ListGlobalAdminAssignmentsForUpdate(ctx, adminIDs)
		require.NoError(t, err)
		heldByUserAOrB := 0
		var survivorID uint
		for _, a := range stillHeld {
			if a.PrincipalType == "user" && (a.PrincipalID == userA.ID || a.PrincipalID == userB.ID) {
				heldByUserAOrB++
				survivorID = a.PrincipalID
			}
		}
		assert.Equal(t, 1, heldByUserAOrB,
			"iteration %d: exactly one of userA/userB must still hold the admin grant — never both removed, never both surviving unresolved", i)

		// Strip the survivor's grant (raw storage call, outside the flow under
		// test) so it doesn't silently become a permanent extra admin the NEXT
		// iteration's pair could lean on instead of actually racing each other.
		if survivorID != 0 {
			require.NoError(t, upstream.Storage().RemoveRole(ctx, survivorID, adminRole.ID, coreStorage.Scope{}))
		}
	}
}
