package admin

// #3803: an accept-loss that stops part way names the record it was writing,
// and a re-run still writes only when --resume-seal names that record. Driven
// through acceptLoss with a real failure of the in-chain event write.

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var acceptLossDigestRE = regexp.MustCompile(`--resume-seal ([0-9a-f]{64})`)

func TestAcceptLoss_CrashErrorNamesRecordDigest(t *testing.T) {
	resetAcceptLossFlags(t)
	cfg, st, db, dbPath := acceptLossFixture(t)
	ctx := context.Background()
	require.NoError(t, db.Exec(`CREATE TRIGGER accept_loss_crash BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected crash'); END`).Error)

	acceptLossFlags(5)
	acceptLossConfirm = true
	req, err := acceptLossRequest()
	require.NoError(t, err)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.Error(t, err, "the seal event could not be written")
	assert.Contains(t, err.Error(), "without --confirm")
	crash := acceptLossDigestRE.FindStringSubmatch(err.Error())
	require.Len(t, crash, 2, "the error names the record it was writing: %s", err)

	require.NoError(t, db.Exec(`DROP TRIGGER accept_loss_crash`).Error)

	// The habitual re-run: --confirm alone still writes nothing.
	acceptLossBrokenIDs = nil
	req, err = acceptLossRequest()
	require.NoError(t, err)
	before := acceptLossWrites(t, db, dbPath)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nothing was written")
	assert.Equal(t, crash[0], acceptLossDigestRE.FindString(err.Error()), "the plan offers the record the crash named")
	assert.Equal(t, before, acceptLossWrites(t, db, dbPath), "nothing is written")

	acceptLossResumeSeal = crash[1]
	req, err = acceptLossRequest()
	require.NoError(t, err)
	require.NoError(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req))

	adb, err := auditverify.OpenSQLiteReadOnly(dbPath)
	require.NoError(t, err)
	defer adb.Close() //nolint:errcheck
	r, err := auditverify.Verify(ctx, adb, auditverify.Options{CheckpointKey: acceptLossTestKey})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
}

// The #3803 tamper scenario with a digest that names no record: --confirm and
// a well-formed but wrong --resume-seal exit non-zero and write nothing.
func TestAcceptLoss_RolledBackSealWrongDigestWritesNothing(t *testing.T) {
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

	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id > ?", head).Error)
	require.NoError(t, db.Exec("DELETE FROM audit_checkpoints WHERE id > ?", cp).Error)
	require.NoError(t, db.Where("key IN ?", []string{"audit_checkpoint_highwater", "audit_verification_state"}).Delete(&models.SystemMetadata{}).Error)
	for _, m := range saved {
		require.NoError(t, db.Create(&models.SystemMetadata{Key: m.Key, Value: m.Value}).Error)
	}
	require.NoError(t, os.Remove(auditverify.WitnessPath(dbPath)))

	acceptLossBrokenIDs = nil
	acceptLossResumeSeal = strings.Repeat("ab", 32)
	req, err = acceptLossRequest()
	require.NoError(t, err)
	before := acceptLossWrites(t, db, dbPath)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.ErrorIs(t, err, core.ErrAuditLossRefused)
	assert.Contains(t, err.Error(), "does not name the unfinished seal")
	assert.Equal(t, before, acceptLossWrites(t, db, dbPath), "nothing is written")
}
