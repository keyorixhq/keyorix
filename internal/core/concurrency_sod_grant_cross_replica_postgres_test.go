package core

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_AssignUserRole_CrossReplicaPostgres_NeverCreatesSoDViolation is
// the genuine multi-replica counterpart to TestAssignUserRole_BlocksNewSoDViolation
// and friends (rbac_management_test.go/sod_test.go). Those tests — like every
// other SoD-preventive-gate test in this package — drive a single *KeyorixCore
// backed by one storage.Storage instance, so they all serialize through ONE
// process-local mutex (the former sodGrantMu) regardless of whether the
// underlying cross-replica primitive works at all: they would pass identically
// even if WithSoDGrantLock's pg_advisory_lock call were deleted outright,
// because the shared in-process mutex alone already serializes every goroutine
// in the test. They also never run on Postgres (in-memory SQLite), so the
// advisory-lock branch in local_sod_grant_lock.go never even executes.
//
// This test instead gives each simulated replica its OWN *gorm.DB connection
// (own LocalStorage, own KeyorixCore) into the SAME real Postgres schema — the
// only thing left that can serialize AssignUserRole's preventive
// check-then-write sequence across them is pg_advisory_lock. If it's missing or
// broken, two replicas granting the two individually-clean halves of a toxic
// permission pair to the SAME user can each read "no violation yet" before
// either write commits, both pass the check, and together hand that user both
// sides of a combination a separation-of-duties policy exists specifically to
// forbid.
//
// The assertion that actually matters is NOT "one call succeeds and one
// fails" in isolation (a coincidental ordering could produce that outcome even
// under a broken lock, e.g. if replica B's read happens to run before
// replica A's write commits due to scheduling, then both would still race with
// a real chance of BOTH passing) — it's the structural invariant checked at
// the end, from a THIRD, independent connection: the user must never hold
// both toxic-pair roles at once, only ever one or the other.
func TestConcurrency_AssignUserRole_CrossReplicaPostgres_NeverCreatesSoDViolation(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.SoDPolicy{}, &models.AuditEvent{},
	))

	const (
		userID   = uint(1)
		roleAID  = uint(1)
		roleBID  = uint(2)
		permAID  = uint(1)
		permBID  = uint(2)
		policyID = uint(1)
	)
	require.NoError(t, setupDB.Create(&models.User{ID: userID, Username: "target", Email: "target@example.com"}).Error)
	require.NoError(t, setupDB.Create(&models.Role{ID: roleAID, Name: "role_toxic_a"}).Error)
	require.NoError(t, setupDB.Create(&models.Role{ID: roleBID, Name: "role_toxic_b"}).Error)
	require.NoError(t, setupDB.Create(&models.Permission{ID: permAID, Name: "perm_toxic_a", Resource: "res", Action: "a"}).Error)
	require.NoError(t, setupDB.Create(&models.Permission{ID: permBID, Name: "perm_toxic_b", Resource: "res", Action: "b"}).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: roleAID, PermissionID: permAID}).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: roleBID, PermissionID: permBID}).Error)
	// A policy forbidding perm_toxic_a + perm_toxic_b together — role_toxic_a and
	// role_toxic_b are each individually clean; only holding BOTH violates it.
	require.NoError(t, setupDB.Create(&models.SoDPolicy{
		ID: policyID, Name: "toxic-pair", PermissionA: "perm_toxic_a", PermissionB: "perm_toxic_b",
	}).Error)

	replicaA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	replicaB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		// actorID 0 = unauthenticated/local-CLI exemption from the grant-ceiling
		// check (requireGranterHoldsRolePermissions) — this test is about the SoD
		// preventive gate specifically, not the ceiling check.
		results <- replicaA.AssignUserRole(context.Background(), 0, userID, roleAID, Scope{})
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- replicaB.AssignUserRole(context.Background(), 0, userID, roleBID, Scope{})
	}()
	close(start) // release both replicas' grants at once
	wg.Wait()
	close(results)

	succeeded, blocked := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "separation-of-duties violation"):
			blocked++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one of the two concurrent grants may succeed")
	assert.Equal(t, 1, blocked, "the other must be refused as a separation-of-duties violation, not silently applied")

	// The invariant that actually matters: verified from a THIRD, independent
	// connection into the same schema, the user must never end up holding both
	// sides of the toxic pair — only ever one of the two roles.
	verifier := localstore.NewLocalStorage(pgOpen(t, dsn))
	roles, err := verifier.GetUserRoles(context.Background(), userID)
	require.NoError(t, err)
	assert.Len(t, roles, 1, "the user must hold exactly one of the two toxic-pair roles, never both and never neither")
}
