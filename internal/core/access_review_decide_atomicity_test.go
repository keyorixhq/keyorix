package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// access_review_decide_atomicity_test.go — #2676.
//
// #2570 fixed the ATTEST half of DecideAccessReviewItem by moving its (read-only)
// verification ahead of the claim, so a reported error always means the item is
// still pending. The REVOKE half could not be fixed that way: claim-before-act is
// what closes #1646's cross-replica attest/revoke race, so the revoke genuinely
// has to act AFTER its claim has committed. That left a window the code itself
// documented and logged loudly but did not close — if the grant removal failed
// after the claim committed, the item stayed stamped `revoked` while the grant
// was still live.
//
// That is a false compliance record in the dangerous direction: an auditor
// reading the campaign sees "access revoked, by this reviewer, at this time" for
// access that still exists. ISO 27001 A.5.18 / SOC 2 CC6.2-6.3 evidence is the
// whole point of the feature.
//
// The fix runs claim + apply + audit in ONE transaction, so a failed apply rolls
// the claim back. These tests assert the EFFECT (the persisted rows), never the
// return value — a partial-state bug reports an error at every layer either way,
// so only the rows distinguish "rolled back" from "committed the claim anyway".
// Faults are injected at the storage interface (internal/faultstorage), which is
// the layer that can fail in production for reasons a caller cannot anticipate.

// newReviewRevokeWorld builds a campaign with one pending `revoke`-able item
// for a user's project-scoped role grant, plus the reviewer. Returns the core
// (storage-faulted), the raw DB for unfaulted verification reads, the wrapper,
// and the campaign/item IDs.
func newReviewRevokeWorld(t *testing.T) (*KeyorixCore, *gorm.DB, *faultstorage.FaultyStorage, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Project{}, &models.Permission{}, &models.RolePermission{},
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
	))
	const proj = reviewRevokeProject
	// "editor" bundles no permissions here, so guardLastProjectAdmin has nothing
	// to refuse — this test is about atomicity, not the last-admin guard (which
	// has its own coverage, and its own test below).
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor", NameFolded: "editor"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: proj, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reviewer", UsernameFolded: "reviewer", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 10, Username: "alice", UsernameFolded: "alice", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 3, ProjectID: proj}).Error)

	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "q4", State: CampaignStateOpen, CreatedBy: 1}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 10, PrincipalName: "alice",
		Source: "role", RoleID: 3, Decision: ReviewItemPending,
	}
	require.NoError(t, db.Create(item).Error)

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return NewKeyorixCore(faulty), db, faulty, campaign.ID, item.ID
}

const reviewRevokeProject = uint(2)

// requireItemPendingAndGrantIntact is the whole invariant in one place: a
// reported failure must leave NOTHING behind — the item still pending with no
// reviewer stamped, the grant still present, and no `access_review.revoked`
// evidence recorded.
func requireItemPendingAndGrantIntact(t *testing.T, db *gorm.DB, itemID uint) {
	t.Helper()
	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, itemID).Error)
	assert.Equal(t, ReviewItemPending, after.Decision,
		"a reported revoke failure must leave the item PENDING: stamping it `revoked` while the grant "+
			"is still live records access as removed when it is not")
	assert.Zero(t, after.DecidedBy, "no reviewer may be attributed to a decision that did not take effect")
	assert.Nil(t, after.DecidedAt)

	var grants int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, reviewRevokeProject).
		Count(&grants).Error)
	assert.Equal(t, int64(1), grants, "the grant must still exist — this is the state the item must agree with")

	var revoked int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventAccessReviewRevoked).Count(&revoked).Error)
	assert.Zero(t, revoked, "no revocation evidence may be recorded for a revoke that did not happen")
}

// The core case: the grant removal itself fails. Before #2676 the claim had
// already committed, so the item read `revoked` while alice kept her role.
func TestDecideAccessReviewItem_RevokeRemovalFails_ItemStaysPending(t *testing.T) {
	t.Parallel()
	c, db, faulty, campaignID, itemID := newReviewRevokeWorld(t)

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	err := c.DecideAccessReviewItem(context.Background(), 1, reviewRevokeProject, campaignID, itemID, "revoke", "no longer needed")

	require.Error(t, err, "a failed grant removal must be reported")
	require.True(t, faulty.Fired(), "the fault must actually have been reached — otherwise this test proves nothing")
	requireItemPendingAndGrantIntact(t, db, itemID)
}

// The same invariant when the fault lands on the AUDIT write rather than the
// grant removal. Audit writes are best-effort by design (emitAudit swallows
// errors so a logging failure cannot fail the primary action), so this asserts
// the OPPOSITE of the test above: the revoke must SUCCEED and stay committed.
// Rolling the revoke back because its audit row failed would turn a logging
// problem into a silently-undone security decision.
func TestDecideAccessReviewItem_RevokeAuditWriteFails_DecisionStillCommits(t *testing.T) {
	t.Parallel()
	c, db, faulty, campaignID, itemID := newReviewRevokeWorld(t)

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	err := c.DecideAccessReviewItem(context.Background(), 1, reviewRevokeProject, campaignID, itemID, "revoke", "no longer needed")

	require.NoError(t, err, "an audit-write failure is best-effort (emitAudit) and must not fail the revoke")
	require.True(t, faulty.Fired())

	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, itemID).Error)
	assert.Equal(t, ReviewItemRevoked, after.Decision, "the decision must stay committed")
	var grants int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, reviewRevokeProject).Count(&grants).Error)
	assert.Zero(t, grants, "the grant must actually have been removed")
}

// Retryability, which is the user-visible point of rolling back: once the fault
// clears, the SAME decision must succeed. A claim left stamped `revoked` made
// the item un-decidable ("this item has already been decided"), so the reviewer
// could not complete the action they had been told failed.
func TestDecideAccessReviewItem_RevokeIsRetryableAfterTheFaultClears(t *testing.T) {
	t.Parallel()
	c, db, faulty, campaignID, itemID := newReviewRevokeWorld(t)
	ctx := context.Background()

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	require.Error(t, c.DecideAccessReviewItem(ctx, 1, reviewRevokeProject, campaignID, itemID, "revoke", "no longer needed"))

	faulty.Arm(nil)
	require.NoError(t, c.DecideAccessReviewItem(ctx, 1, reviewRevokeProject, campaignID, itemID, "revoke", "no longer needed"),
		"the reviewer must be able to retry the decision they were told had failed")

	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, itemID).Error)
	assert.Equal(t, ReviewItemRevoked, after.Decision)
	assert.Equal(t, uint(1), after.DecidedBy)
	var grants int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, reviewRevokeProject).Count(&grants).Error)
	assert.Zero(t, grants, "the retry must actually have removed the grant")
	var revoked int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventAccessReviewRevoked).Count(&revoked).Error)
	assert.Equal(t, int64(1), revoked, "exactly one revocation event — the failed attempt must not have left one")
}

// Calibration: the unfaulted happy path. Without this, a change that made every
// revoke fail would pass every assertion above.
func TestDecideAccessReviewItem_RevokeHappyPath_RemovesGrantAndRecordsEvidence(t *testing.T) {
	t.Parallel()
	c, db, _, campaignID, itemID := newReviewRevokeWorld(t)

	require.NoError(t, c.DecideAccessReviewItem(context.Background(), 1, reviewRevokeProject, campaignID, itemID, "revoke", "no longer needed"))

	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, itemID).Error)
	assert.Equal(t, ReviewItemRevoked, after.Decision)
	assert.Equal(t, uint(1), after.DecidedBy)
	assert.NotNil(t, after.DecidedAt)
	var grants int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, reviewRevokeProject).Count(&grants).Error)
	assert.Zero(t, grants)
	var revoked int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventAccessReviewRevoked).Count(&revoked).Error)
	assert.Equal(t, int64(1), revoked)
	var roleRemoved int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventRoleRemoved).Count(&roleRemoved).Error)
	assert.Equal(t, int64(1), roleRemoved,
		"the underlying removal's own audit event must still be written, from inside the same transaction")
}

// Calibration, the guard direction: wrapping the apply in a transaction must not
// drop the last-project-admin guard that the public RemoveUserRole path applies
// for this same removal. If the access-review path re-implemented the removal
// instead of reusing that guarded wrapper, this is what would go unnoticed —
// the exact "second, separately-maintained implementation" shape.
func TestDecideAccessReviewItem_RevokeStillRefusedByLastProjectAdminGuard(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Project{}, &models.Permission{}, &models.RolePermission{},
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
	))
	const proj = reviewRevokeProject
	// A role that DOES bundle roles.assign: alice is the project's only holder,
	// so removing it would leave the project with no one able to administer it.
	require.NoError(t, db.Create(&models.Role{ID: 4, Name: "project_admin", NameFolded: "project_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 13, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 4, PermissionID: 13}).Error)
	require.NoError(t, db.Create(&models.Project{ID: proj, Name: "p2"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reviewer", UsernameFolded: "reviewer", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 10, Username: "alice", UsernameFolded: "alice", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 4, ProjectID: proj}).Error)

	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "q4", State: CampaignStateOpen, CreatedBy: 1}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 10, PrincipalName: "alice",
		Source: "role", RoleID: 4, Decision: ReviewItemPending,
	}
	require.NoError(t, db.Create(item).Error)

	c := NewKeyorixCore(store.NewLocalStorage(db))
	err = c.DecideAccessReviewItem(context.Background(), 1, proj, campaign.ID, item.ID, "revoke", "no longer needed")

	require.Error(t, err, "removing the project's last roles.assign holder must still be refused on this path")
	assert.Contains(t, err.Error(), "administrator")

	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, item.ID).Error)
	assert.Equal(t, ReviewItemPending, after.Decision, "a guard refusal must leave the item pending too")
	var grants int64
	require.NoError(t, db.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 4, proj).Count(&grants).Error)
	assert.Equal(t, int64(1), grants, "the refused removal must not have happened")
}
