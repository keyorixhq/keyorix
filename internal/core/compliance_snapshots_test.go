package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// complianceSnapDBSeq makes each in-memory DB unique within the process.
var complianceSnapDBSeq atomic.Int64

func newSnapshotCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	dsn := fmt.Sprintf("file:kx_snap_core_%d?mode=memory&cache=shared&_timeout=30000", complianceSnapDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.AuditEvent{},
		&models.CompliancePostureSnapshot{},
		&models.RotationPolicy{},
		&models.User{},
		&models.Role{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TakeComplianceSnapshot on an empty DB should succeed and return a snapshot.
func TestTakeComplianceSnapshot_Success(t *testing.T) {
	c, _ := newSnapshotCore(t)

	snap, err := c.TakeComplianceSnapshot(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.False(t, snap.SnapshotDate.IsZero())
}

// TakeComplianceSnapshot propagates GetCompliancePosture errors.
// GetCompliancePosture fails at the top level only when ListProjects fails.
func TestTakeComplianceSnapshot_PropagatesError(t *testing.T) {
	c, db := newSnapshotCore(t)
	// Drop the projects table to force ListProjects (the first call inside
	// buildComplianceSnapshot) to fail, making GetCompliancePosture return an error.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS projects").Error)

	_, err := c.TakeComplianceSnapshot(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "TakeComplianceSnapshot")
}

// ListComplianceSnapshots propagates a storage error.
func TestListComplianceSnapshots_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListCompliancePostureSnapshots", mock.Anything, 0).
		Return(nil, errors.New("db down"))

	c := NewKeyorixCore(ms)
	_, err := c.ListComplianceSnapshots(context.Background(), 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "db down")
}

// ListComplianceSnapshots returns the slices from storage unmodified.
func TestListComplianceSnapshots_ReturnsSnapshots(t *testing.T) {
	fixed := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	snaps := []*models.CompliancePostureSnapshot{
		{ID: 1, SnapshotDate: fixed, PassedControls: 10},
		{ID: 2, SnapshotDate: fixed.AddDate(0, 0, -1), PassedControls: 8},
	}

	ms := new(MockStorage)
	ms.On("ListCompliancePostureSnapshots", mock.Anything, 90).Return(snaps, nil)

	c := NewKeyorixCore(ms)
	got, err := c.ListComplianceSnapshots(context.Background(), 90)
	require.NoError(t, err)
	require.Equal(t, snaps, got)
}

// ListComplianceSnapshots with limit=0 passes 0 to storage (default handled there).
func TestListComplianceSnapshots_ZeroLimitPassedThrough(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListCompliancePostureSnapshots", mock.Anything, 0).Return([]*models.CompliancePostureSnapshot{}, nil)

	c := NewKeyorixCore(ms)
	got, err := c.ListComplianceSnapshots(context.Background(), 0)
	require.NoError(t, err)
	require.Empty(t, got)
	ms.AssertCalled(t, "ListCompliancePostureSnapshots", mock.Anything, 0)
}
