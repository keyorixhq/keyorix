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

func newMachineStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}))
	return NewLocalStorage(db)
}

func TestMachineIdentity_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 1, Name: "ci-runner", IdentityType: "ci", State: "active",
		CreatedBy: 9, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	got, err := ls.GetMachineIdentity(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "ci", got.IdentityType)
	assert.Equal(t, "active", got.State)

	got.State = "suspended"
	matched, err := ls.TransitionMachineIdentityState(ctx, got, "active")
	require.NoError(t, err)
	require.True(t, matched)
	reloaded, err := ls.GetMachineIdentity(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", reloaded.State)
}

func TestListMachineIdentities_ScopedToProject(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	now := time.Now().UTC()
	mk := func(projectID uint, name string) {
		_, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
			ProjectID: projectID, Name: name, IdentityType: "service", State: "active",
			CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
	}
	mk(1, "a")
	mk(1, "b")
	mk(2, "c")

	got, err := ls.ListMachineIdentities(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, got, 2, "only project 1's identities")
}
