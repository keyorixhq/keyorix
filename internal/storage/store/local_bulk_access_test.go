// local_bulk_access_test.go — store-level tests for the bulk-access-request
// storage functions added in the bulk-approve/reject feature (ADR-024 extension).
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newBulkAccessStore returns a LocalStorage backed by an in-memory SQLite DB
// migrated with the tables required for bulk-access operations.
func newBulkAccessStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := "file:" + t.Name() + "_bulkaccess?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.AuditEvent{},
		&models.SystemMetadata{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.RejectionReasonTemplate{},
	))
	return NewLocalStorage(db)
}

// newBulkAccessBrokenStore returns a LocalStorage with NO tables migrated,
// so every call returns "no such table" errors.
func newBulkAccessBrokenStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := "file:" + t.Name() + "_bulkbroken?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	return NewLocalStorage(db)
}

// ── RejectionReasonTemplate CRUD ─────────────────────────────────────────────

func TestCreateRejectionReasonTemplate_Store(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	tmpl := &models.RejectionReasonTemplate{
		Name:      "not-qualified",
		Reason:    "Does not meet the requirements.",
		CreatedBy: 1,
	}
	err := ls.CreateRejectionReasonTemplate(ctx, tmpl)
	require.NoError(t, err)
	assert.NotZero(t, tmpl.ID)
}

func TestCreateRejectionReasonTemplate_StoreBroken(t *testing.T) {
	ls := newBulkAccessBrokenStore(t)
	ctx := context.Background()

	err := ls.CreateRejectionReasonTemplate(ctx, &models.RejectionReasonTemplate{
		Name:   "x",
		Reason: "y",
	})
	require.Error(t, err)
}

func TestListRejectionReasonTemplates_StoreEmpty(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	templates, err := ls.ListRejectionReasonTemplates(ctx)
	require.NoError(t, err)
	assert.Empty(t, templates)
}

func TestListRejectionReasonTemplates_StoreWithData(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	require.NoError(t, ls.CreateRejectionReasonTemplate(ctx, &models.RejectionReasonTemplate{
		Name: "a", Reason: "reason-a",
	}))
	require.NoError(t, ls.CreateRejectionReasonTemplate(ctx, &models.RejectionReasonTemplate{
		Name: "b", Reason: "reason-b",
	}))

	templates, err := ls.ListRejectionReasonTemplates(ctx)
	require.NoError(t, err)
	assert.Len(t, templates, 2)
}

func TestListRejectionReasonTemplates_StoreBroken(t *testing.T) {
	ls := newBulkAccessBrokenStore(t)
	ctx := context.Background()

	_, err := ls.ListRejectionReasonTemplates(ctx)
	require.Error(t, err)
}

func TestDeleteRejectionReasonTemplate_Store(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	tmpl := &models.RejectionReasonTemplate{Name: "to-del", Reason: "gone"}
	require.NoError(t, ls.CreateRejectionReasonTemplate(ctx, tmpl))

	err := ls.DeleteRejectionReasonTemplate(ctx, tmpl.ID)
	require.NoError(t, err)

	// Confirm it's gone.
	templates, err := ls.ListRejectionReasonTemplates(ctx)
	require.NoError(t, err)
	assert.Empty(t, templates)
}

func TestDeleteRejectionReasonTemplate_StoreNotFound(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	err := ls.DeleteRejectionReasonTemplate(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteRejectionReasonTemplate_StoreBroken(t *testing.T) {
	ls := newBulkAccessBrokenStore(t)
	ctx := context.Background()

	err := ls.DeleteRejectionReasonTemplate(ctx, 1)
	require.Error(t, err)
}

// ── ListAccessRequestsByIDs ───────────────────────────────────────────────────

func TestListAccessRequestsByIDs_StoreNilIDs(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	// Nil/empty slice → short-circuit, no DB call, nil result.
	results, err := ls.ListAccessRequestsByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, results)

	results, err = ls.ListAccessRequestsByIDs(ctx, []uint{})
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestListAccessRequestsByIDs_StoreEmpty(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	// Query for IDs that don't exist → should return an empty slice, not error.
	results, err := ls.ListAccessRequestsByIDs(ctx, []uint{1, 2, 3})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListAccessRequestsByIDs_StoreWithData(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	// Seed two access requests directly via CreateAccessRequest.
	ar1, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID:     1,
		UserID:        10,
		SuggestedRole: "editor",
		State:         "pending",
	})
	require.NoError(t, err)
	ar2, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID:     1,
		UserID:        11,
		SuggestedRole: "editor",
		State:         "pending",
	})
	require.NoError(t, err)

	results, err := ls.ListAccessRequestsByIDs(ctx, []uint{ar1.ID, ar2.ID})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestListAccessRequestsByIDs_StorePartialMatch(t *testing.T) {
	ls := newBulkAccessStore(t)
	ctx := context.Background()

	ar, err := ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID:     1,
		UserID:        10,
		SuggestedRole: "editor",
		State:         "pending",
	})
	require.NoError(t, err)

	// Ask for ar.ID + 9999 (non-existent): only ar should be returned.
	results, err := ls.ListAccessRequestsByIDs(ctx, []uint{ar.ID, 9999})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, ar.ID, results[0].ID)
}

func TestListAccessRequestsByIDs_StoreBroken(t *testing.T) {
	ls := newBulkAccessBrokenStore(t)
	ctx := context.Background()

	_, err := ls.ListAccessRequestsByIDs(ctx, []uint{1})
	require.Error(t, err)
}
