// bulk_s1_test.go — SQLite-backed success-path and error-path tests for the
// bulk-approve, bulk-reject, and rejection-templates CLI commands.
//
// Strategy: t.Chdir(t.TempDir()) + KEYORIX_SERVER="" → InitializeCoreService
// falls back to ./secrets.db in the temp dir. seedRequestDB (from
// request_s3_test.go) seeds admin + project so the core is usable.
package request

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// seedBulkApproveDB seeds a pending access request for the editor role and
// returns the request ID along with the approver's user ID.
func seedBulkApproveDB(t *testing.T) (reqID, approverID uint, svc *core.KeyorixCore) {
	t.Helper()
	var err error
	svc, err = common.InitializeCoreService()
	require.NoError(t, err)

	svc.SetBootstrapToken("bulk-s1-token")
	ctx := context.Background()
	_, err = svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "bulk-s1-token",
	})
	require.NoError(t, err)

	u, err := svc.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	approverID = u.ID

	proj, err := svc.CreateProject(ctx, "bulk-proj", "")
	require.NoError(t, err)

	// Create a requester user directly via storage (no password-strength validation).
	requester, err := svc.Storage().CreateUser(ctx, &models.User{
		Username: "requester", Email: "requester@example.com", IsActive: true,
	})
	require.NoError(t, err)

	// Seed a pending access request.
	ar, err := svc.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID:     proj.ID,
		UserID:        requester.ID,
		SuggestedRole: "editor",
		State:         "pending",
		CreatedAt:     time.Now(),
	})
	require.NoError(t, err)
	reqID = ar.ID
	return
}

// ── runBulkApprove success path ───────────────────────────────────────────────

func TestRunBulkApprove_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	reqID, _, _ := seedBulkApproveDB(t)

	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	bulkApproveIDs = fmt.Sprintf("%d", reqID)
	bulkApproveBy = "admin@example.com"

	require.NoError(t, runBulkApprove(nil, nil))
}

// ── runBulkApprove failure path (request not found) ──────────────────────────

func TestRunBulkApprove_FailurePath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedBulkApproveDB(t)

	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	// Use a non-existent request ID → BulkApprove succeeds but records a failure.
	bulkApproveIDs = "99999"
	bulkApproveBy = "admin@example.com"

	// Returns nil (not an error) — failures are in result.Failed.
	require.NoError(t, runBulkApprove(nil, nil))
}

// ── runBulkReject success path ────────────────────────────────────────────────

func TestRunBulkReject_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	reqID, _, _ := seedBulkApproveDB(t)

	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() {
		bulkRejectIDs = origIDs
		bulkRejectBy = origBy
		bulkRejectReason = origReason
	}()
	bulkRejectIDs = fmt.Sprintf("%d", reqID)
	bulkRejectBy = "admin@example.com"
	bulkRejectReason = "does not meet requirements"

	require.NoError(t, runBulkReject(nil, nil))
}

// ── runBulkReject failure path (request not found) ───────────────────────────

func TestRunBulkReject_FailurePath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedBulkApproveDB(t)

	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() {
		bulkRejectIDs = origIDs
		bulkRejectBy = origBy
		bulkRejectReason = origReason
	}()
	bulkRejectIDs = "99999"
	bulkRejectBy = "admin@example.com"
	bulkRejectReason = "not qualified"

	require.NoError(t, runBulkReject(nil, nil))
}

// ── runTmplList success paths ─────────────────────────────────────────────────

func TestRunTmplList_EmptySuccess(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, svc := seedBulkApproveDB(t)
	_ = svc // DB is seeded; RejectionReasonTemplate table exists

	require.NoError(t, runTmplList(nil, nil))
}

func TestRunTmplList_WithData(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, svc := seedBulkApproveDB(t)
	ctx := context.Background()

	err := svc.Storage().CreateRejectionReasonTemplate(ctx, &models.RejectionReasonTemplate{
		Name: "not-qualified", Reason: "Does not meet requirements.",
	})
	require.NoError(t, err)

	require.NoError(t, runTmplList(nil, nil))
}

// ── runTmplAdd success path ───────────────────────────────────────────────────

func TestRunTmplAdd_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedBulkApproveDB(t)

	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "not-qualified"
	tmplReason = "Does not meet requirements."
	tmplBy = "admin@example.com"

	require.NoError(t, runTmplAdd(nil, nil))
}

// ── runTmplDelete success path ────────────────────────────────────────────────

func TestRunTmplDelete_SuccessPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, svc := seedBulkApproveDB(t)
	ctx := context.Background()

	tmpl := &models.RejectionReasonTemplate{Name: "to-del", Reason: "gone"}
	err := svc.Storage().CreateRejectionReasonTemplate(ctx, tmpl)
	require.NoError(t, err)

	err = runTmplDelete(nil, []string{strconv.FormatUint(uint64(tmpl.ID), 10)})
	require.NoError(t, err)
}

// ── runTmplDelete not-found path ──────────────────────────────────────────────

func TestRunTmplDelete_NotFoundError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	_, _, _ = seedBulkApproveDB(t)

	err := runTmplDelete(nil, []string{"9999"})
	require.Error(t, err)
}
