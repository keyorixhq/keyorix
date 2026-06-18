package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestListSecretAccessors(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{},
		&models.Group{}, &models.UserGroup{},
	))
	// Users: 1 owner, 2 direct recipient, 3 & 4 group members, 5 expired-share recipient.
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@t.com"},
		{ID: 2, Username: "alice", Email: "a@t.com"},
		{ID: 3, Username: "bob", Email: "b@t.com"},
		{ID: 4, Username: "carol", Email: "c@t.com"},
		{ID: 5, Username: "dave", Email: "d@t.com"},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 3, GroupID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 4, GroupID: 10}).Error)

	now := time.Now()
	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: func() time.Time { return now }}
	ctx := context.Background()

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	// Direct share to alice (write); group share to platform (read); expired share to dave.
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "write", SharedBy: 1})
	require.NoError(t, err)
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "read", SharedBy: 1})
	require.NoError(t, err)
	past := now.Add(-time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 5, Permission: "read", ExpiresAt: &past}).Error)

	accessors, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)

	byName := map[string]SecretAccessor{}
	for _, a := range accessors {
		byName[a.Username] = a
	}
	// owner, alice (direct), bob + carol (group). dave is excluded (expired share).
	assert.Len(t, accessors, 4)
	assert.Equal(t, "owner", byName["owner"].Permission)
	assert.Equal(t, "direct_share", byName["alice"].Source)
	assert.Equal(t, "write", byName["alice"].Permission)
	assert.Equal(t, "read", byName["bob"].Permission)
	assert.Contains(t, byName["bob"].Source, "group_share:platform")
	assert.Contains(t, byName, "carol")
	assert.NotContains(t, byName, "dave", "an expired share must not grant access")

	// Sorted by username.
	for i := 1; i < len(accessors); i++ {
		assert.LessOrEqual(t, accessors[i-1].Username, accessors[i].Username)
	}
}

func TestListSecretAccessors_StrongestGrantWins(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.ShareRecord{},
		&models.Group{}, &models.UserGroup{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "alice", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "g"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 2, GroupID: 10}).Error)

	now := time.Now()
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{Name: "s", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true, CreatedAt: now, UpdatedAt: now})
	require.NoError(t, err)
	// alice gets a group read share AND a direct write share — write should win.
	_, err = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{SecretID: secret.ID, GroupID: 10, Permission: "read", SharedBy: 1})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &ShareSecretRequest{SecretID: secret.ID, RecipientID: 2, Permission: "write", SharedBy: 1})
	require.NoError(t, err)

	accessors, err := c.ListSecretAccessors(ctx, secret.ID, 1)
	require.NoError(t, err)
	for _, a := range accessors {
		if a.Username == "alice" {
			assert.Equal(t, "write", a.Permission, "the stronger (write) grant wins over the group read")
		}
	}
}
