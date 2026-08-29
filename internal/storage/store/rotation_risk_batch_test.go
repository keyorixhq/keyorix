// rotation_risk_batch_test.go — LocalStorage tests for the batched storage methods
// added to fix #409 (GenerateDeploymentRotationPlan's per-candidate-secret risk
// score fan-out): GetSecretsByIDs, CountSecretReadsBySecretIDs,
// ListSharesBySecretIDs, ListGroupMembersByGroupIDs.
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

func newRotationRiskBatchTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{},
		&models.SecretAccessLog{}, &models.User{}, &models.Group{}, &models.UserGroup{},
	))
	return NewLocalStorage(db)
}

func TestGetSecretsByIDs(t *testing.T) {
	ls := newRotationRiskBatchTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 1, Name: "a", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 2, Name: "b", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 3, Name: "c", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}).Error)

	got, err := ls.GetSecretsByIDs(ctx, []uint{1, 3, 999})
	require.NoError(t, err)
	names := map[uint]string{}
	for _, s := range got {
		names[s.ID] = s.Name
	}
	assert.Equal(t, map[uint]string{1: "a", 3: "c"}, names, "returns only the matching IDs, silently omitting the nonexistent one")

	empty, err := ls.GetSecretsByIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestCountSecretReadsBySecretIDs(t *testing.T) {
	ls := newRotationRiskBatchTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	since := now.Add(-30 * 24 * time.Hour)

	mkLog := func(secretID uint, action string, at time.Time) {
		require.NoError(t, ls.db.Create(&models.SecretAccessLog{
			SecretNodeID: secretID, Action: action, AccessTime: at, AccessedBy: "u",
		}).Error)
	}
	// Secret 1: 3 reads in-window, 1 out-of-window read, 1 in-window update (not counted).
	mkLog(1, "read", now.Add(-time.Hour))
	mkLog(1, "read", now.Add(-2*time.Hour))
	mkLog(1, "read", now.Add(-3*time.Hour))
	mkLog(1, "read", now.Add(-40*24*time.Hour)) // before the window
	mkLog(1, "update", now.Add(-time.Hour))
	// Secret 2: no reads at all.
	mkLog(2, "update", now.Add(-time.Hour))
	// Secret 3: 1 read in-window.
	mkLog(3, "read", now.Add(-time.Hour))

	got, err := ls.CountSecretReadsBySecretIDs(ctx, []uint{1, 2, 3, 999}, since)
	require.NoError(t, err)
	assert.Equal(t, 3, got[1])
	assert.NotContains(t, got, uint(2), "a secret with zero qualifying reads is absent, not a zero entry")
	assert.Equal(t, 1, got[3])
	assert.NotContains(t, got, uint(999))
}

func TestListSharesBySecretIDs(t *testing.T) {
	ls := newRotationRiskBatchTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 9, Username: "owner", Email: "owner@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 2, Username: "u2", Email: "u2@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 3, Username: "u3", Email: "u3@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 4, Username: "u4", Email: "u4@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 1, Name: "a", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 9}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{ID: 2, Name: "b", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 9}).Error)

	_, err := ls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: 1, OwnerID: 9, RecipientID: 2, IsGroup: false})
	require.NoError(t, err)
	_, err = ls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: 2, OwnerID: 9, RecipientID: 3, IsGroup: false})
	require.NoError(t, err)
	// UTC explicitly: the raw db.Model(...).Update("expires_at", past) below bypasses
	// ShareRecord.BeforeSave's UTC normalization (the hook only fires on a full-struct
	// Save/Create, not a raw column Update) — see TestListShares_ExcludeExpiredIncludeActive's
	// identical comment in local_sharing_test.go for the full reasoning.
	past := time.Now().UTC().Add(-time.Hour)
	expired, err := ls.CreateShareRecord(ctx, &models.ShareRecord{SecretID: 1, OwnerID: 9, RecipientID: 4, IsGroup: false})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.ShareRecord{}).Where("id = ?", expired.ID).Update("expires_at", past).Error)

	got, err := ls.ListSharesBySecretIDs(ctx, []uint{1, 2})
	require.NoError(t, err)
	bySecret := map[uint][]uint{}
	for _, sh := range got {
		bySecret[sh.SecretID] = append(bySecret[sh.SecretID], sh.RecipientID)
	}
	assert.ElementsMatch(t, []uint{2}, bySecret[1], "excludes the expired share")
	assert.ElementsMatch(t, []uint{3}, bySecret[2])
}

func TestListGroupMembersByGroupIDs(t *testing.T) {
	ls := newRotationRiskBatchTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Group{ID: 1, Name: "team-a"}).Error)
	require.NoError(t, ls.db.Create(&models.Group{ID: 2, Name: "team-b"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 10, Username: "alice", Email: "a@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 11, Username: "bob", Email: "b@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.User{ID: 12, Username: "carol", Email: "c@x.io"}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 10, GroupID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 11, GroupID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 12, GroupID: 2}).Error)

	got, err := ls.ListGroupMembersByGroupIDs(ctx, []uint{1, 2})
	require.NoError(t, err)

	idsOf := func(users []*models.User) []uint {
		ids := make([]uint, len(users))
		for i, u := range users {
			ids[i] = u.ID
		}
		return ids
	}
	assert.ElementsMatch(t, []uint{10, 11}, idsOf(got[1]))
	assert.ElementsMatch(t, []uint{12}, idsOf(got[2]))

	empty, err := ls.ListGroupMembersByGroupIDs(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}
