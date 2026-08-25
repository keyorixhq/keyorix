package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestConcurrency_RemoveGlobalAdminRoleGuarded_MultiInstancePostgres_NeverStrandsZeroAdmins
// exercises local_rbac.go:375's ListGlobalAdminAssignmentsForUpdate FOR UPDATE
// lock — the same TOCTOU class the G80 campaign has been closing, one layer
// down: the "does removing this role leave the install with zero admins?"
// check and the removal itself must be atomic, or two concurrent removals of
// two DIFFERENT admins can each observe "the other one still exists" before
// either write commits, and both proceed — stranding the install with zero
// admins, able to authorize no one, including itself out of fixing the
// problem (#340/#525).
//
// Genuinely independent connections (own LocalStorage, own transaction) are
// required: a single connection racing itself would just serialize through
// its own transaction anyway.
func TestConcurrency_RemoveGlobalAdminRoleGuarded_MultiInstancePostgres_NeverStrandsZeroAdmins(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	const adminRoleID = uint(1)
	require.NoError(t, setupDB.Create(&models.Role{ID: adminRoleID, Name: "admin"}).Error)
	require.NoError(t, setupDB.Create(&models.User{ID: 1, Username: "admin-1", Email: "admin1@example.com"}).Error)
	require.NoError(t, setupDB.Create(&models.User{ID: 2, Username: "admin-2", Email: "admin2@example.com"}).Error)
	// Exactly two global-scope admin grants — removing either alone is fine;
	// removing BOTH concurrently must leave exactly one standing.
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: 1, RoleID: adminRoleID, ProjectID: 0, EnvironmentID: 0}).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: 2, RoleID: adminRoleID, ProjectID: 0, EnvironmentID: 0}).Error)

	replicaA := NewLocalStorage(pgOpen(t, dsn))
	replicaB := NewLocalStorage(pgOpen(t, dsn))
	adminIDs := []uint{adminRoleID}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		results <- replicaA.RemoveGlobalAdminRoleGuarded(context.Background(), 1, adminRoleID, adminIDs)
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- replicaB.RemoveGlobalAdminRoleGuarded(context.Background(), 2, adminRoleID, adminIDs)
	}()
	close(start) // release both replicas' removal attempts at once
	wg.Wait()
	close(results)

	succeeded, refused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, storage.ErrWouldStrandLastAdmin):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one of the two concurrent removals may succeed")
	assert.Equal(t, 1, refused, "the other must be refused as it would strand the install with zero admins")

	// Structural check, independent of which replica "won": the install must
	// end up with exactly one global admin assignment, never zero.
	verifier := pgOpen(t, dsn)
	var remaining int64
	require.NoError(t, verifier.Model(&models.UserRole{}).
		Where("role_id = ? AND project_id = 0 AND environment_id = 0", adminRoleID).
		Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining, "exactly one global admin assignment must remain — never zero, never two")
}
