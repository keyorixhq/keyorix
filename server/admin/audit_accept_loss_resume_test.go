package admin

// #3803: a resume of an unfinished acceptance (here a completed one whose
// later rows, checkpoint, mark, state and witness were put back from before
// it) writes nothing on --confirm alone; it completes only with --resume-seal
// naming the record digest the plan prints.

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func acceptLossWrites(t *testing.T, db *gorm.DB, dbPath string) []any {
	t.Helper()
	var meta []models.SystemMetadata
	require.NoError(t, db.Where("key IN ?", []string{"audit_seals", "audit_checkpoint_highwater", "audit_verification_state"}).Order("key").Find(&meta).Error)
	var events, cps int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Count(&events).Error)
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&cps).Error)
	w, _ := os.ReadFile(auditverify.WitnessPath(dbPath)) // #nosec G304 -- test temp dir
	out := []any{events, cps, string(w)}
	for _, m := range meta {
		out = append(out, m.Key, m.Value)
	}
	return out
}

func TestAcceptLoss_ResumeNeedsResumeSeal(t *testing.T) {
	resetAcceptLossFlags(t)
	cfg, st, db, dbPath := acceptLossFixture(t)
	ctx := context.Background()
	var head, cp int64
	require.NoError(t, db.Raw("SELECT MAX(id) FROM audit_events").Scan(&head).Error)
	require.NoError(t, db.Raw("SELECT MAX(id) FROM audit_checkpoints").Scan(&cp).Error)
	var saved []models.SystemMetadata
	require.NoError(t, db.Where("key IN ?", []string{"audit_checkpoint_highwater", "audit_verification_state"}).Find(&saved).Error)

	acceptLossFlags(5)
	acceptLossConfirm = true
	req, err := acceptLossRequest()
	require.NoError(t, err)
	require.NoError(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req))

	// Put back everything after the seal record, as the issue describes.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > ?", head).Error)
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints WHERE id > ?", cp).Error)
	require.NoError(t, db.Where("key IN ?", []string{"audit_checkpoint_highwater", "audit_verification_state"}).Delete(&models.SystemMetadata{}).Error)
	for _, m := range saved {
		require.NoError(t, db.Create(&models.SystemMetadata{Key: m.Key, Value: m.Value}).Error)
	}
	require.NoError(t, os.Remove(auditverify.WitnessPath(dbPath)))

	acceptLossBrokenIDs = nil
	req, err = acceptLossRequest()
	require.NoError(t, err)
	before := acceptLossWrites(t, db, dbPath)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.Error(t, err, "a resume on --confirm alone must exit non-zero")
	assert.Contains(t, err.Error(), "nothing was written")
	digest := regexp.MustCompile(`--resume-seal ([0-9a-f]{64})`).FindStringSubmatch(err.Error())
	require.Len(t, digest, 2, "the refusal names the digest to pass: %s", err)
	assert.Equal(t, before, acceptLossWrites(t, db, dbPath), "nothing is written")

	acceptLossResumeSeal = "nothex"
	_, err = acceptLossRequest()
	require.Error(t, err)

	acceptLossResumeSeal = digest[1]
	req, err = acceptLossRequest()
	require.NoError(t, err)
	require.NoError(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req))

	adb, err := auditverify.OpenSQLiteReadOnly(dbPath)
	require.NoError(t, err)
	defer adb.Close() //nolint:errcheck
	r, err := auditverify.Verify(ctx, adb, auditverify.Options{CheckpointKey: acceptLossTestKey})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)

	// The same flags again: nothing is unfinished, the digest is refused.
	req, err = acceptLossRequest()
	require.NoError(t, err)
	require.ErrorIs(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req), core.ErrAuditLossRefused)
}
