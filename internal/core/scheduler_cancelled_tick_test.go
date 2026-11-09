package core

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// errTickLockLost stands in for store.ErrAdvisoryLockLost, the cause a scheduler
// tick's context is cancelled with when its lock connection dies.
var errTickLockLost = errors.New("advisory lock lost")

// cancellingExecutor cancels the tick during its first upstream call, the way a lost
// scheduler lock does, and fails on a dead context like every real executor (each
// passes ctx to its driver or HTTP client).
type cancellingExecutor struct {
	cancel context.CancelCauseFunc
	refs   []string
}

func (e *cancellingExecutor) Name() string { return "pg" }
func (e *cancellingExecutor) Type() string { return "fake" }
func (e *cancellingExecutor) Rotate(ctx context.Context, ref, _ string) error {
	e.refs = append(e.refs, ref)
	if err := ctx.Err(); err != nil {
		return err
	}
	e.cancel(errTickLockLost)
	return ctx.Err()
}

// recordingSink counts the deployment-wide rotation-failure alerts.
type recordingSink struct{ events []NotificationEvent }

func (s *recordingSink) Deliver(ev NotificationEvent) bool {
	s.events = append(s.events, ev)
	return true
}

func seedNamedBackendSecret(t *testing.T, db *gorm.DB, id uint, name, ref string, lastRotated time.Time) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: name, ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationBackend: "pg", RotationRef: ref, LastRotatedAt: &lastRotated, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

// A tick cancelled part-way through must leave the secrets it had not reached alone:
// no upstream attempt, no audit rows and no failure alert naming them. They stay due
// for the next tick.
func TestRunAutoRotation_CancelledTickDoesNotTouchRemainingSecrets(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30, IsActive: true, CreatedBy: "admin",
	}).Error)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	exec := &cancellingExecutor{cancel: cancel}
	c.SetRotationManager(rotation.NewManager([]rotation.Executor{exec}))
	sink := &recordingSink{}
	c.SetNotificationSink(sink)
	overdue := fixed.Add(-60 * 24 * time.Hour)
	seedNamedBackendSecret(t, db, 1, "first", "app_one", overdue)
	seedNamedBackendSecret(t, db, 2, "second", "app_two", overdue)

	n, err := c.RunAutoRotation(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, []string{"app_one"}, exec.refs, "the secret after the cancellation is not attempted upstream")

	var rows int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("secret_node_id = ?", 2).Count(&rows).Error)
	assert.Zero(t, rows, "no audit row for a secret that was never tried")

	require.Len(t, sink.events, 1, "the secret that really failed is still alerted")
	assert.Contains(t, sink.events[0].Message, `"first"`)
	assert.NotContains(t, sink.events[0].Message, `"second"`)

	var second models.SecretNode
	require.NoError(t, db.First(&second, 2).Error)
	require.NotNil(t, second.LastRotatedAt)
	assert.True(t, second.LastRotatedAt.Equal(overdue), "still due for the next tick")
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber)
}

// A tick cancelled during collection must not publish the partial pack: a section's
// read failure only marks the pack degraded, so without the check it would be signed,
// written and audited as an export.
func TestExportComplianceEvidence_CancelledDuringCollectionDeliversNothing(t *testing.T) {
	c, db, _ := newEvidenceExportCore(t)
	dir := t.TempDir()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	// Cancel once the project list has been read: it is the snapshot's only fatal
	// read, so every section after it degrades instead of failing the export.
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("cancel_after_projects", func(tx *gorm.DB) {
		if tx.Statement.Table == "projects" {
			cancel(errTickLockLost)
		}
	}))

	res, err := c.ExportComplianceEvidence(ctx, dir)
	require.ErrorIs(t, err, errTickLockLost)
	assert.Nil(t, res)

	// The export dir is a t.TempDir(), not core sources: walk it rather than list it
	// (TestNoAdHocCoreDirListing).
	var onDisk []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ fs.DirEntry, werr error) error {
		if werr == nil && p != dir {
			onDisk = append(onDisk, p)
		}
		return werr
	}))
	assert.Empty(t, onDisk, "no pack and no signature on disk")

	var rows int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "compliance.evidence_exported").Count(&rows).Error)
	assert.Zero(t, rows, "no export is recorded")
}
