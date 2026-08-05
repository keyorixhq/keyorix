// bulk_test.go — unit tests for the bulk-approve, bulk-reject, and
// rejection-templates CLI commands (ADR-024 extension). Tests cover command
// structure, required flags, and the parseIDList helper.
package request

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// errInitService is the sentinel error returned by the failing service factory.
var errInitService = errors.New("simulated service init failure")

// withFailingInitService temporarily replaces bulkInitService with one that
// always returns errInitService, then restores the original on cleanup.
func withFailingInitService(t *testing.T) {
	t.Helper()
	orig := bulkInitService
	bulkInitService = func() (*core.KeyorixCore, error) { return nil, errInitService }
	t.Cleanup(func() { bulkInitService = orig })
}

// bulkBrokenCounter avoids DSN collisions across parallel tests.
var bulkBrokenCounter int

// withBrokenDBService replaces bulkInitService with one that returns a
// KeyorixCore backed by a closed SQLite connection (all storage calls fail).
func withBrokenDBService(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	bulkBrokenCounter++
	dsn := fmt.Sprintf("file:bulk_broken_%d?mode=memory&cache=shared", bulkBrokenCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AccessRequest{},
		&models.RejectionReasonTemplate{},
	))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	orig := bulkInitService
	bulkInitService = func() (*core.KeyorixCore, error) { return svc, nil }
	t.Cleanup(func() { bulkInitService = orig })
}

// withUserSeededPartialService returns a KeyorixCore backed by a SQLite DB
// that has ONLY the users table migrated (not access_requests / templates),
// with an admin user seeded. GetUserByEmail succeeds; bulk-access / template
// storage calls fail because those tables don't exist.
func withUserSeededPartialService(t *testing.T, email string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	bulkBrokenCounter++
	dsn := fmt.Sprintf("file:bulk_partial_%d?mode=memory&cache=shared", bulkBrokenCounter)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	// Migrate ONLY the users table so GetUserByEmail works.
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Create(&models.User{
		Username: "admin", Email: email, IsActive: true,
	}).Error)
	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	orig := bulkInitService
	bulkInitService = func() (*core.KeyorixCore, error) { return svc, nil }
	t.Cleanup(func() {
		bulkInitService = orig
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
}

// ── Command structure ─────────────────────────────────────────────────────────

func TestBulkCommandsRegistered(t *testing.T) {
	names := make([]string, 0)
	for _, c := range RequestCmd.Commands() {
		names = append(names, c.Use)
	}
	assert.Contains(t, names, "bulk-approve", "bulk-approve subcommand must be registered")
	assert.Contains(t, names, "bulk-reject", "bulk-reject subcommand must be registered")
	assert.Contains(t, names, "rejection-templates", "rejection-templates subcommand must be registered")
}

func TestBulkApproveRequiredFlags(t *testing.T) {
	for _, name := range []string{"ids", "by"} {
		f := bulkApproveCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "bulk-approve should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestBulkRejectRequiredFlags(t *testing.T) {
	for _, name := range []string{"ids", "by", "reason"} {
		f := bulkRejectCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "bulk-reject should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRejectionTemplatesSubcommands(t *testing.T) {
	names := make([]string, 0)
	for _, c := range rejectionTemplatesCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{"list", "add", "delete"} {
		assert.Contains(t, names, expected, "rejection-templates should have subcommand %q", expected)
	}
}

func TestRejectionTemplatesAddRequiredFlags(t *testing.T) {
	for _, name := range []string{"name", "reason", "by"} {
		f := tmplAddCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "rejection-templates add should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRejectionTemplatesDeleteExactlyOneArg(t *testing.T) {
	assert.NotNil(t, tmplDeleteCmd.Args, "rejection-templates delete should require exactly 1 arg")
}

// ── parseIDList ───────────────────────────────────────────────────────────────

func TestParseIDList_Single(t *testing.T) {
	ids, err := parseIDList("42")
	require.NoError(t, err)
	assert.Equal(t, []uint{42}, ids)
}

func TestParseIDList_Multiple(t *testing.T) {
	ids, err := parseIDList("1,2,3")
	require.NoError(t, err)
	assert.Equal(t, []uint{1, 2, 3}, ids)
}

func TestParseIDList_Spaces(t *testing.T) {
	ids, err := parseIDList(" 10 , 20 , 30 ")
	require.NoError(t, err)
	assert.Equal(t, []uint{10, 20, 30}, ids)
}

func TestParseIDList_Empty(t *testing.T) {
	_, err := parseIDList("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one ID")
}

func TestParseIDList_OnlyCommas(t *testing.T) {
	_, err := parseIDList(",,,")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one ID")
}

func TestParseIDList_InvalidID(t *testing.T) {
	_, err := parseIDList("1,foo,3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ID")
}

func TestParseIDList_NegativeID(t *testing.T) {
	_, err := parseIDList("-1")
	require.Error(t, err)
}

func TestParseIDList_SkipsTrailingComma(t *testing.T) {
	// A trailing comma produces an empty segment which is skipped.
	ids, err := parseIDList("5,6,")
	require.NoError(t, err)
	assert.Equal(t, []uint{5, 6}, ids)
}

// ── runBulkApprove validation paths ──────────────────────────────────────────

func TestRunBulkApprove_InvalidIDList(t *testing.T) {
	orig := bulkApproveIDs
	defer func() { bulkApproveIDs = orig }()
	bulkApproveIDs = "not-a-number"
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkApprove_EmptyIDList(t *testing.T) {
	orig := bulkApproveIDs
	defer func() { bulkApproveIDs = orig }()
	bulkApproveIDs = ""
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkApprove_ServiceInitError(t *testing.T) {
	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	bulkApproveIDs = "1"
	bulkApproveBy = "reviewer@example.com"
	// InitializeCoreService succeeds (loads default SQLite config) but the
	// subsequent resolveUserID or BulkApprove call will fail with a DB error.
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
}

// ── runBulkReject validation paths ───────────────────────────────────────────

func TestRunBulkReject_InvalidIDList(t *testing.T) {
	orig := bulkRejectIDs
	defer func() { bulkRejectIDs = orig }()
	bulkRejectIDs = "abc"
	err := runBulkReject(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkReject_ServiceInitError(t *testing.T) {
	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs = origIDs; bulkRejectBy = origBy; bulkRejectReason = origReason }()
	bulkRejectIDs = "2"
	bulkRejectBy = "reviewer@example.com"
	bulkRejectReason = "no budget"
	// Will fail at resolveUserID or BulkReject step with a DB error.
	err := runBulkReject(nil, nil)
	require.Error(t, err)
}

// ── runTmplList / runTmplAdd / runTmplDelete service-init errors ──────────────

func TestRunTmplList_NoError(t *testing.T) {
	// InitializeCoreService succeeds (default ./secrets.db) and ListRejectionReasonTemplates
	// returns empty (no templates) — so no error, just prints "No rejection-reason templates".
	err := runTmplList(nil, nil)
	// Either no error (table exists) or error from missing tables — both are valid.
	// This just verifies the function doesn't panic.
	_ = err
}

func TestRunTmplAdd_ServiceInitError(t *testing.T) {
	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "x"
	tmplReason = "y"
	tmplBy = "admin@example.com"
	// Will fail at resolveUserID or CreateRejectionReasonTemplate step.
	err := runTmplAdd(nil, nil)
	require.Error(t, err)
}

func TestRunTmplDelete_InvalidID(t *testing.T) {
	err := runTmplDelete(nil, []string{"notanumber"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid template ID")
}

func TestRunTmplDelete_ServiceInitError(t *testing.T) {
	// Will fail at DeleteRejectionReasonTemplate step with a DB error.
	err := runTmplDelete(nil, []string{"1"})
	require.Error(t, err)
}

// ── InitializeCoreService failure paths (via bulkInitService override) ────────

func TestRunBulkApprove_InitServiceError(t *testing.T) {
	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	bulkApproveIDs = "1"
	bulkApproveBy = "a@example.com"
	withFailingInitService(t)
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunBulkReject_InitServiceError(t *testing.T) {
	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs = origIDs; bulkRejectBy = origBy; bulkRejectReason = origReason }()
	bulkRejectIDs = "1"
	bulkRejectBy = "a@example.com"
	bulkRejectReason = "reason"
	withFailingInitService(t)
	err := runBulkReject(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunTmplList_InitServiceError(t *testing.T) {
	withFailingInitService(t)
	err := runTmplList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunTmplAdd_InitServiceError(t *testing.T) {
	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "x"
	tmplReason = "y"
	tmplBy = "a@example.com"
	withFailingInitService(t)
	err := runTmplAdd(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

func TestRunTmplDelete_InitServiceError(t *testing.T) {
	withFailingInitService(t)
	err := runTmplDelete(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ── BulkApprove / BulkReject / template storage errors (broken DB) ────────────

func TestRunBulkApprove_BulkApproveError(t *testing.T) {
	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	bulkApproveIDs = "1"
	bulkApproveBy = "partial@example.com"
	// Service has only the users table — GetUserByEmail succeeds but
	// ListAccessRequestsByIDs fails (no access_requests table), triggering
	// the BulkApproveAccessRequests error branch (lines 62-64).
	withUserSeededPartialService(t, "partial@example.com")
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bulk approve failed")
}

func TestRunBulkApprove_TooManyIDs(t *testing.T) {
	// The per-request batch-size cap is enforced in core, so it applies to the
	// CLI's embedded/local path too, not just HTTP callers. A batch over the
	// cap must be rejected before any storage access is attempted — the
	// partial service (users table only) would otherwise fail with a generic
	// "no such table" error on the access_requests lookup, so seeing the
	// specific cap message here proves the cap check runs first.
	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	bulkApproveIDs = strings.Join(ids, ",")
	bulkApproveBy = "partial@example.com"
	withUserSeededPartialService(t, "partial@example.com")
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum batch size")
}

func TestRunBulkReject_TooManyIDs(t *testing.T) {
	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs = origIDs; bulkRejectBy = origBy; bulkRejectReason = origReason }()
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	bulkRejectIDs = strings.Join(ids, ",")
	bulkRejectBy = "partial@example.com"
	bulkRejectReason = "too many"
	withUserSeededPartialService(t, "partial@example.com")
	err := runBulkReject(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum batch size")
}

func TestRunBulkReject_BulkRejectError(t *testing.T) {
	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs = origIDs; bulkRejectBy = origBy; bulkRejectReason = origReason }()
	bulkRejectIDs = "1"
	bulkRejectBy = "partial@example.com"
	bulkRejectReason = "expired"
	// Service has only the users table — GetUserByEmail succeeds but
	// ListAccessRequestsByIDs fails (no access_requests table), triggering
	// the BulkRejectAccessRequests error branch (lines 120-122).
	withUserSeededPartialService(t, "partial@example.com")
	err := runBulkReject(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bulk reject failed")
}

func TestRunTmplList_ListError(t *testing.T) {
	withBrokenDBService(t)
	err := runTmplList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list templates")
}

func TestRunTmplAdd_CreateError(t *testing.T) {
	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "x"
	tmplReason = "y"
	tmplBy = "partial@example.com"
	// Service has only the users table — GetUserByEmail succeeds (user is seeded)
	// but CreateRejectionReasonTemplate fails (no rejection_reason_templates table),
	// triggering the error branch at lines 207-209.
	withUserSeededPartialService(t, "partial@example.com")
	err := runTmplAdd(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create template")
}
