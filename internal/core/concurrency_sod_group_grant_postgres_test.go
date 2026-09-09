package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_GroupRoleGrant_CrossReplicaPostgres_SoDBypass is issue #1780's
// regression: AssignRoleToGroup/AssignGroupRoleWithExpiry serialize their
// check-then-write on sodGrantLockKey("group", groupID), but
// requireGroupGrantNoSoDViolation evaluates each MEMBER's held-permission set --
// a different resource than the group key covers. AssignUserRole/
// AssignUserRoleWithExpiry serialize on sodGrantLockKey("user", userID)
// directly. Two different keys for what is, from the SoD invariant's point of
// view, the same resource (member U's effective permission set) -- so a
// group-role grant to a group containing U and a direct role grant to U can
// each read U's pre-grant state clean and both commit, leaving U holding both
// halves of a toxic pair.
//
// Same shape as TestConcurrency_AssignUserRole_CrossReplicaPostgres_SoDBypass
// (concurrency_sod_grant_postgres_test.go), reached through the group edge
// instead of two direct grants.
func TestConcurrency_GroupRoleGrant_CrossReplicaPostgres_SoDBypass(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(sodGrantModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("sod-group-race-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "sod-group-race-token",
	})
	require.NoError(t, err)

	perms, err := setupCore.ListPermissions(ctx)
	require.NoError(t, err)
	var rolesAssignID, secretsDeleteID uint
	for _, p := range perms {
		switch p.Name {
		case "roles.assign":
			rolesAssignID = p.ID
		case "secrets.delete":
			secretsDeleteID = p.ID
		}
	}
	require.NotZero(t, rolesAssignID, "roles.assign must be seeded")
	require.NotZero(t, secretsDeleteID, "secrets.delete must be seeded")

	roleAName, err := identity.NewFoldedName("sod-group-race-role-a")
	require.NoError(t, err)
	roleA, err := setupCore.Storage().CreateRole(ctx, roleAName, "grants roles.assign")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleA.ID, rolesAssignID, false))
	roleBName, err := identity.NewFoldedName("sod-group-race-role-b")
	require.NoError(t, err)
	roleB, err := setupCore.Storage().CreateRole(ctx, roleBName, "grants secrets.delete")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleB.ID, secretsDeleteID, false))

	_, err = setupCore.CreateSoDPolicy(ctx, bootRes.User.ID, "group-race-policy", "roles.assign + secrets.delete is toxic", "roles.assign", "secrets.delete")
	require.NoError(t, err)

	// Target U is a member of group G. Group G will receive roleA; U will
	// separately receive roleB directly.
	target, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "sod-group-target", Email: "sod-group-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	group, err := setupCore.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "sod-race-group"})
	require.NoError(t, err)
	require.NoError(t, setupCore.AddUserToGroup(ctx, bootRes.User.ID, false, target.ID, group.ID, 0))

	// Two independent replicas, own connections into the SAME schema.
	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))

	var wg sync.WaitGroup
	start := make(chan struct{})
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		// Replica A: grant roleA (roles.assign) to the GROUP.
		errA = coreA.AssignRoleToGroup(ctx, bootRes.User.ID, group.ID, roleA.ID, Scope{}, false)
	}()
	go func() {
		defer wg.Done()
		<-start
		// Replica B: grant roleB (secrets.delete) directly to the MEMBER.
		errB = coreB.AssignUserRole(ctx, bootRes.User.ID, target.ID, roleB.ID, Scope{}, false)
	}()
	close(start)
	wg.Wait()

	t.Logf("grant A (group roleA/roles.assign) result: %v", errA)
	t.Logf("grant B (direct roleB/secrets.delete) result: %v", errB)

	// Verify from a fresh connection, independent of either racing replica.
	// The target's EFFECTIVE permission set includes roleA only via group
	// membership, so check both the direct grant (roleB) and the group's own
	// role (roleA) -- GetUserRoleIDsAt only returns direct grants, so read the
	// group's role set separately to determine whether roleA actually landed.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)

	directGrants, err := verifier.GetUserRoleIDsAt(ctx, target.ID, storage.Scope{})
	require.NoError(t, err)
	hasB := false
	for _, rid := range directGrants {
		if rid == roleB.ID {
			hasB = true
		}
	}

	groupRoles, err := verifier.GetGroupRoles(ctx, group.ID)
	require.NoError(t, err)
	hasA := false
	for _, r := range groupRoles {
		if r.ID == roleA.ID {
			hasA = true
		}
	}

	t.Logf("target effectively holds roleA(via group)=%v roleB(direct)=%v", hasA, hasB)

	if hasA && hasB {
		t.Errorf("SoD BYPASS CONFIRMED (issue #1780): target effectively holds BOTH roleA "+
			"(roles.assign, via group membership) and roleB (secrets.delete, direct) -- the "+
			"toxic combination the preventive gate exists to block, granted by two racing "+
			"replicas that each passed an individually-clean check (errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, hasA && hasB, "at most one of the two toxic-pair roles may be live on the target, whether held directly or via group membership")
	assert.True(t, hasA || hasB, "at least one of the two racing grants should have succeeded")
}

// TestConcurrency_TwoGroupGrants_SharedMember_NoDeadlock is the deadlock-safety
// check for #1780's fix: withGroupMemberSoDLocks (rbac_management.go) acquires
// every member's sodGrantLockKey("user", ...) lock, sorted ascending, so that
// two concurrent group-role grants locking an OVERLAPPING member set always
// acquire in the same relative order and can only ever contend, never cycle.
// Two groups sharing a member, each granted a non-toxic role concurrently,
// must both complete -- this test hangs (caught by go test's own timeout, not
// a custom one, so a real deadlock fails loudly rather than silently) if the
// lock-ordering discipline is ever broken.
func TestConcurrency_TwoGroupGrants_SharedMember_NoDeadlock(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(sodGrantModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("sod-deadlock-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "sod-deadlock-token",
	})
	require.NoError(t, err)

	perms, err := setupCore.ListPermissions(ctx)
	require.NoError(t, err)
	var secretsReadID uint
	for _, p := range perms {
		if p.Name == "secrets.read" {
			secretsReadID = p.ID
		}
	}
	require.NotZero(t, secretsReadID, "secrets.read must be seeded")

	// No SoD policy at all -- this test is purely about lock ordering, not
	// about the SoD check's own outcome.
	roleName, err := identity.NewFoldedName("sod-deadlock-role")
	require.NoError(t, err)
	role, err := setupCore.Storage().CreateRole(ctx, roleName, "grants secrets.read")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, role.ID, secretsReadID, false))

	// Two users, M1 (the shared member) and M2/M3. Group1 = {M1, M2}, sorted
	// ascending would visit M1 before M2 if M1.ID < M2.ID. Group2 = {M3, M1} --
	// deliberately listed in an order that would visit M1 SECOND if this
	// function didn't sort, to actually exercise the sort rather than
	// coincidentally pass because storage happens to return members in ID order.
	m1, err := setupCore.CreateUser(ctx, &CreateUserRequest{Username: "shared-member", Email: "shared@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	m2, err := setupCore.CreateUser(ctx, &CreateUserRequest{Username: "group1-only", Email: "g1only@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	m3, err := setupCore.CreateUser(ctx, &CreateUserRequest{Username: "group2-only", Email: "g2only@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)

	group1, err := setupCore.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "deadlock-group-1"})
	require.NoError(t, err)
	require.NoError(t, setupCore.AddUserToGroup(ctx, bootRes.User.ID, false, m1.ID, group1.ID, 0))
	require.NoError(t, setupCore.AddUserToGroup(ctx, bootRes.User.ID, false, m2.ID, group1.ID, 0))

	group2, err := setupCore.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "deadlock-group-2"})
	require.NoError(t, err)
	require.NoError(t, setupCore.AddUserToGroup(ctx, bootRes.User.ID, false, m3.ID, group2.ID, 0))
	require.NoError(t, setupCore.AddUserToGroup(ctx, bootRes.User.ID, false, m1.ID, group2.ID, 0))

	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))

	done := make(chan struct{})
	var errA, errB error
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errA = coreA.AssignRoleToGroup(ctx, bootRes.User.ID, group1.ID, role.ID, Scope{}, false)
		}()
		go func() {
			defer wg.Done()
			<-start
			errB = coreB.AssignGroupRoleWithExpiry(ctx, bootRes.User.ID, group2.ID, role.ID, Scope{}, time.Now().Add(time.Hour), false)
		}()
		close(start)
		wg.Wait()
	}()

	select {
	case <-done:
		require.NoError(t, errA, "group1 grant must succeed -- no SoD policy exists to block it")
		require.NoError(t, errB, "group2 grant must succeed -- no SoD policy exists to block it")
	case <-time.After(15 * time.Second):
		t.Fatal("DEADLOCK: two group-role grants sharing member M1 never completed within 15s -- " +
			"withGroupMemberSoDLocks's lock-ordering discipline is broken")
	}
}
