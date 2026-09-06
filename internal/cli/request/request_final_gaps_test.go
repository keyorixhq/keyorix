// request_final_gaps_test.go — closes a statement-coverage gap left in the
// package: runList's "ListAccessRequests returned an error" branch.
//
// runReview's sibling "dual control still pending" branch (req.State !=
// "approved" after an approve) is NOT covered here: it can only be reached
// when the core service's in-process dualControlRequiredApprovals field is
// >1, and that field is set exclusively via KeyorixCore.SetDualControlPolicy,
// which only server/main.go calls (from config) — common.InitializeCoreService,
// the CLI's own service constructor that runReview calls internally, never
// calls it. review.go has no injectable service factory (unlike bulk.go's
// bulkInitService), so a test cannot swap in a pre-configured *core.KeyorixCore
// for runReview's internal call either. Reaching that branch from this
// package's tests as written is not possible without changing production
// code, which is out of scope for a test-only change.
package request

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ──────────────────────────── runList — storage error ──────────────────────

// TestRunList_ListAccessRequestsFails exercises the
// "failed to list access requests" branch. Dropping the access_requests table
// doesn't work here — every InitializeCoreService() call (including runList's
// own) re-runs the storage factory's AutoMigrate, which silently recreates
// any missing table. Instead this poisons a single ROW's data: user_id is
// stored as non-numeric text (SQLite's dynamic typing allows writing a TEXT
// value into an INTEGER-affinity column when it can't be coerced to a
// number), so the SELECT that maps rows back into models.AccessRequest fails
// to scan that column into its uint field — a real storage-layer failure, not
// a fabricated mock error.
func TestRunList_ListAccessRequestsFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate HOME/XDG_CONFIG_HOME too: a leftover ~/.keyorix/cli.yaml in client
	// mode on the machine running this test would otherwise still be picked up by
	// common.ResolveRemote, making this "run in embedded/local mode" test
	// intermittently take the remote branch instead. Mirrors
	// cli_remote_mode_behavior_test.go's identical isolation for the same reason.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, projectID, svc := seedRequestDB(t)
	ctx := context.Background()

	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "listfailreq", Email: "listfailreq@example.com", IsActive: true,
	})
	require.NoError(t, err)
	req, err := svc.RequestProjectAccess(ctx, projectID, requester.ID, "viewer", "need")
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("secrets.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(
		"UPDATE access_requests SET user_id = 'not-a-number' WHERE id = ?", req.ID,
	).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	origProject, origBy := listProject, listBy
	defer func() {
		listProject = origProject
		listBy = origBy
	}()
	listProject = "testproj"
	listBy = "admin@example.com"

	err = runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list access requests")
}
