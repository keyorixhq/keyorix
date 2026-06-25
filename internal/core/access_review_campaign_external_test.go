package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func migrateCampaignTables(t *testing.T, h *testhelper.RBACTestHelper) {
	require.NoError(t, h.DB.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.AuditEvent{}))
}

// Opening a campaign snapshots the current access review into pending items.
func TestOpenAccessReviewCampaign_SnapshotsEntries(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → one role entry

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "Q4 2026")
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateOpen, res.Campaign.State)
	assert.Equal(t, "Q4 2026", res.Campaign.Name)
	assert.Equal(t, 1, res.Progress.Total)
	assert.Equal(t, 1, res.Progress.Pending)

	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	assert.Equal(t, core.ReviewItemPending, detail.Items[0].Decision)
	assert.Equal(t, "alice", detail.Items[0].PrincipalName)
}

// Attesting an item marks it kept; revoking removes the underlying grant.
func TestDecideAccessReviewItem_AttestAndRevoke(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // alice editor
	h.AssignUserRole(t, 11, 4, uptr(proj)) // bob viewer

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 2)

	// Identify alice's and bob's items.
	var aliceItem, bobItem uint
	for _, it := range detail.Items {
		if it.PrincipalID == 10 {
			aliceItem = it.ID
		} else if it.PrincipalID == 11 {
			bobItem = it.ID
		}
	}
	require.NotZero(t, aliceItem)
	require.NotZero(t, bobItem)

	// Attest alice (kept), revoke bob (removed).
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, aliceItem, "attest", ""))
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, bobItem, "revoke", "left team"))

	after, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, after.Progress.Attested)
	assert.Equal(t, 1, after.Progress.Revoked)
	assert.Equal(t, 0, after.Progress.Pending)

	// bob's editor/viewer grant is actually gone from the live review; alice's stays.
	review, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	var names []string
	for _, e := range review {
		names = append(names, e.PrincipalName)
	}
	assert.Contains(t, names, "alice")
	assert.NotContains(t, names, "bob")
}

// A reviewer must not certify their OWN access (ISO 27001 A.5.18 independence).
func TestDecideAccessReviewItem_RejectsSelfCertification(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	require.Len(t, detail.Items, 1)
	item := detail.Items[0].ID

	// Alice (user 10) deciding her own item is rejected...
	err = h.CoreService.DecideAccessReviewItem(ctx, 10, proj, res.Campaign.ID, item, "attest", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "your own access")

	// ...but an independent reviewer can.
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "attest", ""))
}

// Independence extends to GROUP-conferred access: a reviewer who belongs to a group
// must not certify that group's review item (self-certification via a group grant).
func TestDecideAccessReviewItem_RejectsGroupSelfCertification(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "carol", 20)
	g := h.CreateTestGroup(t, "team", "", 5)
	h.AssignGroupRole(t, g.ID, 3, uptr(proj)) // the group holds a role in the project
	h.AssignUserToGroup(t, 20, g.ID)          // carol is a member

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)

	var groupItem uint
	for _, it := range detail.Items {
		if it.PrincipalType == "group" && it.PrincipalID == g.ID {
			groupItem = it.ID
		}
	}
	require.NotZero(t, groupItem, "expected a group-source review item")

	// Carol (a member of the group) cannot self-certify the group's access...
	err = h.CoreService.DecideAccessReviewItem(ctx, 20, proj, res.Campaign.ID, groupItem, "attest", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group you belong to")

	// ...but an independent reviewer (not a member) can.
	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, groupItem, "attest", ""))
}

// An item is decided once: a decided item can't be flipped, so the recorded decision
// can't drift from the real grant state (false certification evidence).
func TestDecideAccessReviewItem_RejectsDoubleDecision(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "review")
	require.NoError(t, err)
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	item := detail.Items[0].ID

	require.NoError(t, h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "attest", ""))
	// A second decision (flip to revoke) is rejected, and the original stands.
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, item, "revoke", "flip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already been decided")

	after, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemAttested, after.Items[0].Decision, "the original decision is preserved")
}

// Closing refuses while items are pending unless forced; a closed campaign rejects
// further decisions.
func TestCloseAccessReviewCampaign_PendingGuardAndForce(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "review")
	require.NoError(t, err)

	// One pending item → close without force fails.
	_, err = h.CoreService.CloseAccessReviewCampaign(ctx, 1, proj, res.Campaign.ID, false)
	require.Error(t, err)

	// Force-close succeeds and freezes the campaign.
	closed, err := h.CoreService.CloseAccessReviewCampaign(ctx, 1, proj, res.Campaign.ID, true)
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateClosed, closed.Campaign.State)

	// A closed campaign rejects further decisions.
	detail, err := h.CoreService.GetAccessReviewCampaign(ctx, proj, res.Campaign.ID)
	require.NoError(t, err)
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, proj, res.Campaign.ID, detail.Items[0].ID, "attest", "")
	require.Error(t, err)

	// Re-closing is rejected.
	_, err = h.CoreService.CloseAccessReviewCampaign(ctx, 1, proj, res.Campaign.ID, true)
	require.Error(t, err)
}

// A campaign id from another project is not reachable through this project's scope.
func TestAccessReviewCampaign_CrossProjectGuard(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(uint(2)))

	res, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 2, "p2")
	require.NoError(t, err)

	// Reaching campaign (project 2) through project 3 must fail.
	_, err = h.CoreService.GetAccessReviewCampaign(ctx, 3, res.Campaign.ID)
	require.Error(t, err)
	err = h.CoreService.DecideAccessReviewItem(ctx, 1, 3, res.Campaign.ID, 1, "attest", "")
	require.Error(t, err)
}

func TestOpenAccessReviewCampaign_RequiresProject(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	_, err := h.CoreService.OpenAccessReviewCampaign(context.Background(), 1, 0, "x")
	require.Error(t, err)
}
