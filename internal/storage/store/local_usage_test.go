package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newUsageStore opens a unique named in-memory SQLite DB, migrates the
// tables needed for GetProjectUsageStats, and returns a LocalStorage.
func newUsageStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := "file:" + t.Name() + "_usage?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.SecretNode{},
		&models.AuditEvent{},
	))
	return NewLocalStorage(db)
}

// seed inserts two projects and several secrets + audit events:
//
//	proj1 (id=1): 2 secrets, 3 reads in window by 2 distinct users
//	proj2 (id=2): 1 secret,  1 read  in window by 1 user
func seedUsageData(t *testing.T, ls *LocalStorage, now time.Time) {
	t.Helper()
	ctx := context.Background()
	tr := true

	// Projects
	p1 := &models.Project{Name: "proj1"}
	p2 := &models.Project{Name: "proj2"}
	require.NoError(t, ls.db.WithContext(ctx).Create(p1).Error)
	require.NoError(t, ls.db.WithContext(ctx).Create(p2).Error)

	// Secrets: 2 in proj1, 1 in proj2
	uid1, uid2 := uint(1), uint(2)
	sn1a := &models.SecretNode{ProjectID: p1.ID, Name: "sec1a", IsSecret: true}
	sn1b := &models.SecretNode{ProjectID: p1.ID, Name: "sec1b", IsSecret: true}
	sn2a := &models.SecretNode{ProjectID: p2.ID, Name: "sec2a", IsSecret: true}
	for _, sn := range []*models.SecretNode{sn1a, sn1b, sn2a} {
		require.NoError(t, ls.db.WithContext(ctx).Create(sn).Error)
	}

	// Audit events: 3 reads for proj1 (2 unique users), 1 read for proj2 (1 user)
	inWindow := now.Add(-24 * time.Hour)
	outOfWindow := now.Add(-40 * 24 * time.Hour) // 40 days ago — outside a 30-day window

	events := []*models.AuditEvent{
		// proj1 in-window reads
		{EventType: "secret.read", ProjectID: &p1.ID, UserID: &uid1, EventTime: inWindow, Success: &tr, ActorType: "user"},
		{EventType: "secret.read", ProjectID: &p1.ID, UserID: &uid1, EventTime: inWindow, Success: &tr, ActorType: "user"},
		{EventType: "secret.read", ProjectID: &p1.ID, UserID: &uid2, EventTime: inWindow, Success: &tr, ActorType: "user"},
		// proj2 in-window read
		{EventType: "secret.read", ProjectID: &p2.ID, UserID: &uid1, EventTime: inWindow, Success: &tr, ActorType: "user"},
		// proj1 out-of-window read — must NOT be counted for a 30-day window
		{EventType: "secret.read", ProjectID: &p1.ID, UserID: &uid1, EventTime: outOfWindow, Success: &tr, ActorType: "user"},
	}
	for _, e := range events {
		require.NoError(t, ls.db.WithContext(ctx).Create(e).Error)
	}
}

// TestGetProjectUsageStats_SecretCounts verifies that active-secret counts are
// correct per project and that soft-deleted secrets are excluded.
func TestGetProjectUsageStats_SecretCounts(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedUsageData(t, ls, now)

	// Add a soft-deleted secret to proj1 — should NOT be counted
	deleted := &models.SecretNode{ProjectID: 1, Name: "deleted", IsSecret: true}
	require.NoError(t, ls.db.WithContext(ctx).Create(deleted).Error)
	require.NoError(t, ls.db.WithContext(ctx).Delete(deleted).Error)

	// Also add a non-leaf (folder) node — IsSecret=false, should be excluded
	folder := &models.SecretNode{ProjectID: 1, Name: "folder", IsSecret: false}
	require.NoError(t, ls.db.WithContext(ctx).Create(folder).Error)

	stats, err := ls.GetProjectUsageStats(ctx, nil, 30)
	require.NoError(t, err)

	byProject := make(map[uint]int64)
	for _, s := range stats {
		byProject[s.ProjectID] = s.SecretCount
	}
	assert.Equal(t, int64(2), byProject[1], "proj1 should have 2 active secrets")
	assert.Equal(t, int64(1), byProject[2], "proj2 should have 1 active secret")
}

// TestGetProjectUsageStats_ReadCounts verifies read counts and out-of-window
// exclusion.
func TestGetProjectUsageStats_ReadCounts(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedUsageData(t, ls, now)

	stats, err := ls.GetProjectUsageStats(ctx, nil, 30)
	require.NoError(t, err)

	byProject := make(map[uint]int64)
	for _, s := range stats {
		byProject[s.ProjectID] = s.ReadsInWindow
	}
	// proj1: 3 in-window reads (the 4th is 40 days ago, outside window)
	assert.Equal(t, int64(3), byProject[1], "proj1 should have 3 reads in 30d window")
	// proj2: 1 in-window read
	assert.Equal(t, int64(1), byProject[2], "proj2 should have 1 read in 30d window")
}

// TestGetProjectUsageStats_UniqueReaders verifies that distinct user counts are
// computed correctly.
func TestGetProjectUsageStats_UniqueReaders(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedUsageData(t, ls, now)

	stats, err := ls.GetProjectUsageStats(ctx, nil, 30)
	require.NoError(t, err)

	byProject := make(map[uint]int)
	for _, s := range stats {
		byProject[s.ProjectID] = s.UniqueReaders
	}
	assert.Equal(t, 2, byProject[1], "proj1 should have 2 unique readers")
	assert.Equal(t, 1, byProject[2], "proj2 should have 1 unique reader")
}

// TestGetProjectUsageStats_ProjectFilter verifies that passing a specific
// project ID filters the result to that project only.
func TestGetProjectUsageStats_ProjectFilter(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedUsageData(t, ls, now)

	stats, err := ls.GetProjectUsageStats(ctx, []uint{1}, 30)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, uint(1), stats[0].ProjectID)
	assert.Equal(t, "proj1", stats[0].ProjectName)
}

// TestGetProjectUsageStats_NoAuditEvents verifies that a project with secrets
// but no reads still appears when queried directly.
func TestGetProjectUsageStats_NoAuditEvents(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()

	// A project with no reads at all
	p := &models.Project{Name: "silent"}
	require.NoError(t, ls.db.WithContext(ctx).Create(p).Error)
	sn := &models.SecretNode{ProjectID: p.ID, Name: "top-secret", IsSecret: true}
	require.NoError(t, ls.db.WithContext(ctx).Create(sn).Error)

	stats, err := ls.GetProjectUsageStats(ctx, []uint{p.ID}, 30)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, int64(1), stats[0].SecretCount)
	assert.Equal(t, int64(0), stats[0].ReadsInWindow)
	assert.Equal(t, 0, stats[0].UniqueReaders)
}

// TestGetProjectUsageStats_EmptyDB verifies that an empty database returns nil
// without error.
func TestGetProjectUsageStats_EmptyDB(t *testing.T) {
	ls := newUsageStore(t)
	ctx := context.Background()

	stats, err := ls.GetProjectUsageStats(ctx, nil, 30)
	require.NoError(t, err)
	assert.Nil(t, stats)
}
