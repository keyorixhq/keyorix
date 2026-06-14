package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The compliance posture counts secrets per data-classification level (A.5.12),
// with "unclassified" for the empty label.
func TestCompliancePosture_ClassificationCounts(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.SecretNode{}, &models.AuditEvent{}, &models.AccessReviewCampaign{},
		&models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{}, &models.SoDPolicy{},
	))

	ctx := context.Background()
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 1, ProjectID: 2, Name: "a", Status: "active", IsSecret: true, Classification: "restricted"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 2, ProjectID: 2, Name: "b", Status: "active", IsSecret: true, Classification: "internal"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 3, ProjectID: 2, Name: "c", Status: "active", IsSecret: true, Classification: "internal"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 4, ProjectID: 2, Name: "d", Status: "active", IsSecret: true, Classification: ""}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)

	assert.Equal(t, 4, p.Classification.TotalSecrets)
	assert.Equal(t, 1, p.Classification.Restricted)
	assert.Equal(t, 2, p.Classification.Internal)
	assert.Equal(t, 1, p.Classification.Unclassified)
	assert.Equal(t, 0, p.Classification.Confidential)
}
