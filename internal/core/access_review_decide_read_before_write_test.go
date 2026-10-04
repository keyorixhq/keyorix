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

// TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending is the
// regression test for #2570 (FuzzStorageFaultOperations: op="REST POST
// /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide",
// fault=(method=ListProjectRoleAssignments, NthCall=1, kind=error), oracle (a),
// differing tables [AccessReviewItem]). DecideAccessReviewItem used to claim the
// item (commit Decision=attested) and only THEN re-verify the grant via
// ListProjectRoleAssignments, so a storage error there reported failure while the
// item stayed attested. The attestation's reads now run before the claim: a
// reported error must mean the item is still pending, and a retry once the fault
// clears must succeed.
func TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Project{}, &models.AuditEvent{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{},
	))
	const proj = uint(2)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reviewer", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 10, Username: "alice", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 10, RoleID: 3, ProjectID: proj}).Error)
	campaign := &models.AccessReviewCampaign{ProjectID: proj, Name: "q4", State: CampaignStateOpen, CreatedBy: 1}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 10, PrincipalName: "alice",
		Source: "role", RoleID: 3, Decision: ReviewItemPending,
	}
	require.NoError(t, db.Create(item).Error)

	real := store.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, nil)
	c := NewKeyorixCore(faulty)
	ctx := context.Background()

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "ListProjectRoleAssignments", NthCall: 1, Kind: faultstorage.KindError,
		Err: assert.AnError,
	})
	err = c.DecideAccessReviewItem(ctx, 1, proj, campaign.ID, item.ID, "attest", "kept")
	require.Error(t, err, "a grant-lookup storage error must be reported")
	require.True(t, faulty.Fired(), "the fault must actually have been reached")

	// Effect, not return value: read the row directly. A reported error must
	// mean nothing changed.
	var after models.AccessReviewItem
	require.NoError(t, db.First(&after, item.ID).Error)
	assert.Equal(t, ReviewItemPending, after.Decision, "a reported error must leave the item pending")
	assert.Zero(t, after.DecidedBy)
	assert.Nil(t, after.DecidedAt)
	var attested int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAccessReviewAttested).Count(&attested).Error)
	assert.Zero(t, attested, "no attestation evidence may be recorded for a failed decision")

	// The fault cleared: the same decision now succeeds (it was not consumed).
	faulty.Arm(nil)
	require.NoError(t, c.DecideAccessReviewItem(ctx, 1, proj, campaign.ID, item.ID, "attest", "kept"))
	require.NoError(t, db.First(&after, item.ID).Error)
	assert.Equal(t, ReviewItemAttested, after.Decision)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAccessReviewAttested).Count(&attested).Error)
	assert.Equal(t, int64(1), attested)
}
