package core

// rbac_reconcile_lock_postgres_test.go — REVIEW-4542-M1 item 3 across two
// replicas: two KeyorixCores on separate connection pools to one PostgreSQL
// schema, so only the rbac-permission-reconcile advisory lock (not the
// per-process named-lock queue) can keep the second reconcile out while the
// first holds its debt.

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestReconcileRBAC_ConcurrentRunsSerialised_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
	if err := dbA.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{}, &models.AuditEvent{},
		&models.UserRole{}, &models.Project{}, &models.Environment{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}); err != nil {
		t.Fatal(err)
	}
	storeA, storeB := localstore.NewLocalStorage(dbA), localstore.NewLocalStorage(dbB)
	c := &KeyorixCore{storage: storeA}
	seedOldCatalog(t, c, dbA)
	requireReconcilesSerialised(t, c, storeA, storeB, dbA)
}
