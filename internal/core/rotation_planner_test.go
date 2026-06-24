package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// --- pure helpers ---

func TestRotationUrgency(t *testing.T) {
	// Overdue always outranks due-soon, regardless of risk.
	overdue := rotationUrgency(RotationStatusOverdue, 0, 0)
	dueSoon := rotationUrgency(RotationStatusDueSoon, -1, 100)
	assert.Greater(t, overdue, dueSoon, "any overdue beats any due-soon")

	// Within overdue, more days past due and higher risk raise the score.
	assert.Greater(t, rotationUrgency(RotationStatusOverdue, 30, 50), rotationUrgency(RotationStatusOverdue, 5, 50))
	assert.Greater(t, rotationUrgency(RotationStatusOverdue, 10, 80), rotationUrgency(RotationStatusOverdue, 10, 10))

	// Within due-soon, closer to due (less negative) ranks higher.
	assert.Greater(t, rotationUrgency(RotationStatusDueSoon, -2, 0), rotationUrgency(RotationStatusDueSoon, -10, 0))

	// The overdue cap prevents one ancient secret from dwarfing everything.
	assert.Equal(t, rotationUrgency(RotationStatusOverdue, 9999, 0), rotationUrgency(RotationStatusOverdue, 365, 0))
}

func TestMoreUrgentEntry(t *testing.T) {
	od := &RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 5}
	ds := &RotationStatusEntry{Status: RotationStatusDueSoon, DaysOverdue: -2}
	assert.True(t, moreUrgentEntry(od, ds))
	assert.False(t, moreUrgentEntry(ds, od))
	assert.True(t, moreUrgentEntry(
		&RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 40},
		&RotationStatusEntry{Status: RotationStatusOverdue, DaysOverdue: 10},
	))
}

func TestRotationWaves(t *testing.T) {
	// 1 depends on 2; 3 stands alone. Wave 0 = {2,3}, wave 1 = {1}.
	edges := []*models.SecretDependency{edge(1, 2)}
	candidates := map[uint]bool{1: true, 2: true, 3: true}
	waves, ok := rotationWaves(edges, candidates)
	require.True(t, ok)
	require.Len(t, waves, 2)
	assert.Equal(t, []uint{2, 3}, waves[0], "no-dependency candidates rotate first")
	assert.Equal(t, []uint{1}, waves[1], "the dependent rotates after its dependency")
}

func TestRotationWavesIgnoresNonCandidateEdges(t *testing.T) {
	// 1 depends on 2, but 2 is not in the plan → 1 has no in-plan dependency.
	edges := []*models.SecretDependency{edge(1, 2)}
	candidates := map[uint]bool{1: true}
	waves, ok := rotationWaves(edges, candidates)
	require.True(t, ok)
	require.Len(t, waves, 1)
	assert.Equal(t, []uint{1}, waves[0])
}

func TestRotationWavesDetectsCycle(t *testing.T) {
	edges := []*models.SecretDependency{edge(1, 2), edge(2, 1)}
	_, ok := rotationWaves(edges, map[uint]bool{1: true, 2: true})
	assert.False(t, ok)
}

// --- integration against a real in-memory store ---

func newPlannerCore(t *testing.T, now time.Time) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.SecretDependency{}, &models.ShareRecord{}, &models.SecretAccessLog{}, &models.AuditEvent{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db
}

func TestGenerateRotationPlan(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	projectID := uint(1)
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	require.NoError(t, db.Create(&models.Project{ID: projectID, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: projectID, Name: "production"}).Error)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projectID, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)

	mk := func(id uint, name string, last *time.Time) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projectID, EnvironmentID: 1, IsSecret: true, Status: "active",
			OwnerID: 1, LastRotatedAt: last,
		}).Error)
	}
	mk(1, "overdue-app", daysAgo(120)) // 30 days overdue
	mk(2, "overdue-db", daysAgo(200))  // 110 days overdue (more urgent)
	mk(3, "due-soon-key", daysAgo(80)) // 10 days remaining → due_soon
	mk(4, "healthy-key", daysAgo(5))   // ok → excluded from the plan

	// overdue-app depends on overdue-db → it must rotate in a later wave.
	_, err := c.AddSecretDependency(ctx, 1, 1, 2, "app token derives from db password")
	require.NoError(t, err)

	plan, err := c.GenerateRotationPlan(ctx, projectID)
	require.NoError(t, err)

	assert.Equal(t, 3, plan.TotalSecrets)
	assert.Equal(t, 2, plan.OverdueCount)
	assert.Equal(t, 1, plan.DueSoonCount)
	require.Len(t, plan.Waves, 2, "the dependency forces a second wave")

	// Wave 0: overdue-db (dependency, most urgent) before due-soon-key; overdue-app is NOT here.
	w0 := plan.Waves[0].Secrets
	require.Len(t, w0, 2)
	assert.Equal(t, "overdue-db", w0[0].SecretName)
	assert.Equal(t, "due-soon-key", w0[1].SecretName)
	assert.Greater(t, w0[0].Urgency, w0[1].Urgency)

	// Wave 1: overdue-app, which must follow overdue-db.
	w1 := plan.Waves[1].Secrets
	require.Len(t, w1, 1)
	assert.Equal(t, "overdue-app", w1[0].SecretName)
	assert.Equal(t, []uint{2}, w1[0].AfterSecretIDs)

	// Rationale is present and specific.
	assert.Contains(t, joinReasons(w1[0].Reasons), "30 days overdue")
	assert.Contains(t, joinReasons(w1[0].Reasons), "rotate after overdue-db")
	assert.Contains(t, joinReasons(w0[1].Reasons), "due in 10 days")
}

func TestGenerateRotationPlanEmptyWhenNothingDue(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	projectID := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projectID, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	tt := now.Add(-5 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "healthy", ProjectID: projectID, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &tt}).Error)

	plan, err := c.GenerateRotationPlan(ctx, projectID)
	require.NoError(t, err)
	assert.Equal(t, 0, plan.TotalSecrets)
	assert.Empty(t, plan.Waves)
}

func joinReasons(rs []string) string {
	out := ""
	for _, r := range rs {
		out += r + " | "
	}
	return out
}

func TestGenerateDeploymentRotationPlan(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	daysAgo := func(d int) *time.Time { tt := now.Add(-time.Duration(d) * 24 * time.Hour); return &tt }

	mkProject := func(id uint, name string) {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: id, ProjectID: id, Name: name + "-env"}).Error)
		pid := id
		require.NoError(t, db.Create(&models.RotationPolicy{
			Name: name + "-90d", Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
		}).Error)
	}
	mkSecret := func(id, projID, envID uint, name string, last *time.Time) {
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projID, EnvironmentID: envID, IsSecret: true, Status: "active",
			OwnerID: 1, LastRotatedAt: last,
		}).Error)
	}

	mkProject(1, "prod")
	mkSecret(1, 1, 1, "prod-db", daysAgo(200))  // 110 days overdue
	mkSecret(2, 1, 1, "prod-app", daysAgo(120)) // 30 days overdue

	mkProject(2, "staging")
	mkSecret(3, 2, 2, "stg-key", daysAgo(80)) // 10 days remaining → due_soon

	mkProject(3, "sandbox")
	mkSecret(4, 3, 3, "sbx-healthy", daysAgo(5)) // ok → no work

	dp, err := c.GenerateDeploymentRotationPlan(ctx)
	require.NoError(t, err)

	assert.Equal(t, 3, dp.ProjectsScanned)
	assert.Equal(t, 2, dp.ProjectsWithWork, "sandbox has nothing due → excluded from the list")
	assert.Equal(t, 3, dp.TotalSecrets, "2 in prod + 1 in staging")
	assert.Equal(t, 2, dp.OverdueCount)
	assert.Equal(t, 1, dp.DueSoonCount)

	// Only projects with work are listed, most-overdue first: prod (2 overdue) before staging (0).
	require.Len(t, dp.Projects, 2)
	assert.Equal(t, uint(1), dp.Projects[0].ProjectID)
	assert.Equal(t, 2, dp.Projects[0].OverdueCount)
	assert.Equal(t, uint(2), dp.Projects[1].ProjectID)
	assert.Equal(t, 0, dp.Projects[1].OverdueCount)
	assert.Equal(t, 1, dp.Projects[1].DueSoonCount)
}

func TestGenerateDeploymentRotationPlan_NothingDueAnywhere(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	c, db := newPlannerCore(t, now)
	healthy := now.Add(-5 * 24 * time.Hour)

	for _, p := range []struct {
		id   uint
		name string
	}{{1, "alpha"}, {2, "beta"}} {
		require.NoError(t, db.Create(&models.Project{ID: p.id, Name: p.name}).Error)
		require.NoError(t, db.Create(&models.Environment{ID: p.id, ProjectID: p.id, Name: p.name + "-env"}).Error)
		pid := p.id
		require.NoError(t, db.Create(&models.RotationPolicy{
			Name: "90d-" + p.name, Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
		}).Error)
		require.NoError(t, db.Create(&models.SecretNode{
			ID: p.id, Name: "healthy-" + p.name, ProjectID: p.id, EnvironmentID: p.id, IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &healthy,
		}).Error)
	}

	dp, err := c.GenerateDeploymentRotationPlan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, dp.ProjectsScanned)
	assert.Equal(t, 0, dp.ProjectsWithWork)
	assert.Equal(t, 0, dp.TotalSecrets)
	assert.Empty(t, dp.Projects)
}
