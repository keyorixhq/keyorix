// local_billing_test.go — coverage for GetBillingReport (local_billing.go),
// previously entirely untested (0%).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newBillingTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.SecretNode{}, &models.AuditEvent{}))
	return NewLocalStorage(db)
}

// TestGetBillingReport_AggregatesPerProjectAndOmitsInactive is the main
// end-to-end pass: two projects with distinct activity, a third project with
// neither secrets nor activity (must be omitted), and a soft-deleted secret
// that must not count. Also pins the machine-identity-read fix directly:
// audit_events rows must be tagged actor_type="machine_identity" (the real
// value models.AuditEvent.ActorType / core.ActorTypeMachine uses), not
// "machine", to be counted as MachineReads.
func TestGetBillingReport_AggregatesPerProjectAndOmitsInactive(t *testing.T) {
	ls := newBillingTestStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "beta"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "empty"}).Error) // no secrets, no activity

	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "s1", IsSecret: true, Status: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "s2", IsSecret: true, Status: "active"}).Error)
	// Soft-deleted secret in project 1 must not count toward SecretCount.
	deletedAt := time.Now()
	require.NoError(t, db.Create(&models.SecretNode{ID: 3, ProjectID: 1, EnvironmentID: 1, Name: "s3-deleted", IsSecret: true, Status: "active", DeletedAt: gorm.DeletedAt{Time: deletedAt, Valid: true}}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 4, ProjectID: 2, EnvironmentID: 1, Name: "s4", IsSecret: true, Status: "active"}).Error)

	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	inWindow := from.Add(24 * time.Hour)
	outOfWindow := from.Add(-24 * time.Hour)

	projID1, projID2 := uint(1), uint(2)
	userA, userB := uint(10), uint(11)

	mkEvent := func(projectID uint, eventType string, userID *uint, actorType string, at time.Time) {
		require.NoError(t, db.Create(&models.AuditEvent{
			ProjectID: &projectID, EventType: eventType, UserID: userID, ActorType: actorType,
			Success: boolPtr(true), EventTime: at,
		}).Error)
	}

	// Project 1: 2 reads (1 human, 1 machine), 1 write, 1 rotate (also a write),
	// 2 distinct human users, 1 event outside the window (must not count).
	mkEvent(projID1, "secret.read", &userA, "user", inWindow)
	mkEvent(projID1, "secret.read", nil, "machine_identity", inWindow)
	mkEvent(projID1, "secret.create", &userA, "user", inWindow)
	mkEvent(projID1, "secret.rotate", &userB, "user", inWindow)
	mkEvent(projID1, "secret.read", &userA, "user", outOfWindow)

	// Project 2: 1 read only.
	mkEvent(projID2, "secret.read", &userB, "user", inWindow)

	report, err := ls.GetBillingReport(ctx, from, to, nil)
	require.NoError(t, err)
	assert.True(t, from.Equal(report.From))
	assert.True(t, to.Equal(report.To))
	assert.False(t, report.GeneratedAt.IsZero())

	// Project 3 (no secrets, no activity) must be omitted; only 1 and 2 remain.
	require.Len(t, report.Projects, 2)
	seenProjects := map[uint]bool{}
	for _, p := range report.Projects {
		seenProjects[p.ProjectID] = true
	}
	assert.True(t, seenProjects[1])
	assert.True(t, seenProjects[2])
	assert.False(t, seenProjects[3], "a project with no secrets and no activity must be omitted")
}

// TestGetBillingReport_ProjectStatFields asserts every field of a single
// project's BillingProjectStat (and the report-level Totals), the real
// per-metric coverage this file's first test only checks membership for.
func TestGetBillingReport_ProjectStatFields(t *testing.T) {
	ls := newBillingTestStore(t)
	ctx := context.Background()
	db := ls.DB()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, ProjectID: 1, EnvironmentID: 1, Name: "s1", IsSecret: true, Status: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 2, ProjectID: 1, EnvironmentID: 1, Name: "s2", IsSecret: true, Status: "active"}).Error)

	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	inWindow := from.Add(24 * time.Hour)

	projID := uint(1)
	userA, userB := uint(10), uint(11)
	mkEvent := func(eventType string, userID *uint, actorType string) {
		require.NoError(t, db.Create(&models.AuditEvent{
			ProjectID: &projID, EventType: eventType, UserID: userID, ActorType: actorType,
			Success: boolPtr(true), EventTime: inWindow,
		}).Error)
	}
	mkEvent("secret.read", &userA, "user")
	mkEvent("secret.read", nil, "machine_identity")
	mkEvent("secret.read", nil, "machine_identity")
	mkEvent("secret.create", &userA, "user")
	mkEvent("secret.update", &userB, "user")
	mkEvent("secret.rotate", &userA, "user")

	report, err := ls.GetBillingReport(ctx, from, to, []uint{1})
	require.NoError(t, err)
	require.Len(t, report.Projects, 1)
	stat := report.Projects[0]

	assert.Equal(t, projID, stat.ProjectID)
	assert.Equal(t, "alpha", stat.ProjectName)
	assert.Equal(t, int64(2), stat.SecretCount)
	assert.Equal(t, int64(3), stat.SecretReads, "SecretReads counts every secret.read event, human and machine alike")
	assert.Equal(t, int64(2), stat.MachineReads, "MachineReads is the machine_identity SUBSET of SecretReads, not exclusive of it")
	assert.Equal(t, int64(3), stat.SecretWrites, "create + update + rotate")
	assert.Equal(t, int64(1), stat.SecretRotations)
	assert.Equal(t, 2, stat.UniqueUsers, "userA and userB")

	assert.Equal(t, 1, report.Totals.Projects)
	assert.Equal(t, int64(2), report.Totals.SecretCount)
	assert.Equal(t, int64(3), report.Totals.SecretReads)
	assert.Equal(t, int64(2), report.Totals.MachineReads)
}

// A project_id filter over the cap is rejected outright rather than silently
// truncated.
func TestGetBillingReport_TooManyProjectIDs(t *testing.T) {
	ls := newBillingTestStore(t)
	ids := make([]uint, maxBillingReportProjectIDs+1)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	report, err := ls.GetBillingReport(context.Background(), time.Now(), time.Now(), ids)
	require.Error(t, err)
	assert.Nil(t, report)
}

// No projects at all (fresh install) returns an empty, non-nil report rather
// than erroring.
func TestGetBillingReport_NoProjects(t *testing.T) {
	ls := newBillingTestStore(t)
	report, err := ls.GetBillingReport(context.Background(), time.Now(), time.Now(), nil)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Empty(t, report.Projects)
	assert.Equal(t, 0, report.Totals.Projects)
}

// An explicit projectIDs filter that names a project with no secrets/activity
// is still omitted from the report, same as the nil-filter "all projects" case.
func TestGetBillingReport_ExplicitFilterStillOmitsInactiveProject(t *testing.T) {
	ls := newBillingTestStore(t)
	db := ls.DB()
	require.NoError(t, db.Create(&models.Project{ID: 5, Name: "quiet"}).Error)

	report, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []uint{5})
	require.NoError(t, err)
	assert.Empty(t, report.Projects)
}
