package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strptr(s string) *string { return &s }

// ClassifySecret sets a valid label, rejects an invalid one, and clears with "".
func TestClassifySecret(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.AuditEvent{}))

	ctx := context.Background()
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 500, ProjectID: 2, EnvironmentID: 20, Name: "db-pw", Type: "password", Status: "active", IsSecret: true,
	}).Error)

	// Invalid level is rejected.
	_, err := h.CoreService.ClassifySecret(ctx, 1, "admin", 500, "top-secret")
	require.Error(t, err)

	// A valid level is set.
	s, err := h.CoreService.ClassifySecret(ctx, 1, "admin", 500, core.ClassificationRestricted)
	require.NoError(t, err)
	assert.Equal(t, "restricted", s.Classification)

	// Empty clears it.
	s, err = h.CoreService.ClassifySecret(ctx, 1, "admin", 500, "")
	require.NoError(t, err)
	assert.Equal(t, "", s.Classification)
}

// The classification filter on ListSecrets matches a level, and "unclassified"
// matches the empty label.
func TestListSecrets_ClassificationFilter(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}))

	ctx := context.Background()
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 1, ProjectID: 2, Name: "a", Status: "active", IsSecret: true, Classification: "restricted"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 2, ProjectID: 2, Name: "b", Status: "active", IsSecret: true, Classification: "internal"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{ID: 3, ProjectID: 2, Name: "c", Status: "active", IsSecret: true, Classification: ""}).Error)

	restricted, _, err := h.Storage.ListSecrets(ctx, &storage.SecretFilter{Classification: strptr("restricted"), Page: 1, PageSize: 50})
	require.NoError(t, err)
	require.Len(t, restricted, 1)
	assert.Equal(t, "a", restricted[0].Name)

	unclassified, _, err := h.Storage.ListSecrets(ctx, &storage.SecretFilter{Classification: strptr("unclassified"), Page: 1, PageSize: 50})
	require.NoError(t, err)
	require.Len(t, unclassified, 1)
	assert.Equal(t, "c", unclassified[0].Name)
}

func TestIsValidClassification(t *testing.T) {
	assert.True(t, core.IsValidClassification(""))
	assert.True(t, core.IsValidClassification("confidential"))
	assert.False(t, core.IsValidClassification("secret"))
}
