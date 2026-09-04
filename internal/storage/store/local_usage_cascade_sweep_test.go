// local_usage_cascade_sweep_test.go — partial-coverage sweep for
// local_usage.go's GetProjectUsageStats: each of its 3 sequential queries'
// own DB-error branch, plus the real-logic branch where a project has read
// activity but zero active secrets (so it's only ever seen via readRows, not
// secretRows).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProjectUsageStats_SecretCountsQueryFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetProjectUsageStats(context.Background(), nil, 30)
	require.Error(t, err)
}

func TestGetProjectUsageStats_ReadCountsQueryFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{})
	_, err := ls.GetProjectUsageStats(context.Background(), nil, 30)
	require.Error(t, err)
}

func TestGetProjectUsageStats_ProjectNamesQueryFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.AuditEvent{})
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "active-secret", IsSecret: true,
	}).Error)

	_, err := ls.GetProjectUsageStats(context.Background(), nil, 30)
	require.Error(t, err)
}

func TestGetProjectUsageStats_ReadOnlyProjectWithNoActiveSecrets(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretNode{}, &models.AuditEvent{}, &models.Project{})
	ctx := context.Background()
	p, err := ls.CreateProject(ctx, &models.Project{Name: "read-only-proj"})
	require.NoError(t, err)

	success := true
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", ProjectID: &p.ID, Success: &success, EventTime: time.Now(),
	}).Error)

	stats, err := ls.GetProjectUsageStats(ctx, nil, 30)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, p.ID, stats[0].ProjectID)
	assert.Equal(t, int64(0), stats[0].SecretCount)
	assert.Equal(t, int64(1), stats[0].ReadsInWindow)
}
