package admin

// `admin audit accept-loss` (audit_accept_loss.go) driven the way the command
// drives internal/core, against a real file-backed SQLite store: nothing is
// written without --confirm, the confirmed run seals the gap, the offline
// verifier then exits 4 (SEALED), the witness file carries the sealed mark, and
// a restore of a pre-seal archive is refused as a rollback.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	storelib "github.com/keyorixhq/keyorix/internal/storage/store"
)

var acceptLossTestKey = bytes.Repeat([]byte{0x5a}, 32)

func resetAcceptLossFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		acceptLossBrokenIDs, acceptLossOperator, acceptLossReason, acceptLossEvidence = nil, "", "", ""
		acceptLossAnchorFile, acceptLossAnchorSHA256, acceptLossConfirm = "", "", false
		acceptLossResumeSeal = ""
	}
	reset()
	t.Cleanup(reset)
}

// acceptLossFixture is a checkpointed 10-row chain in a SQLite file with row 4
// deleted; it returns the config, the store and the gorm handle.
func acceptLossFixture(t *testing.T) (*config.Config, *storelib.LocalStorage, *gorm.DB, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	t.Cleanup(func() {
		if s, e := db.DB(); e == nil {
			_ = s.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))
	st := storelib.NewLocalStorage(db)
	ok := true
	for range 10 {
		require.NoError(t, st.LogAuditEvent(context.Background(), &models.AuditEvent{EventType: "secret.read", Description: "read",
			Success: &ok, ActorType: "test", EventTime: time.Now().UTC()}))
	}
	c := core.NewKeyorixCore(st)
	c.SetAuditCheckpointKey(acceptLossTestKey, "v1")
	_, _, err = c.WriteAuditCheckpoint(context.Background())
	require.NoError(t, err)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id = 4").Error)
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath
	return cfg, st, db, dbPath
}

func acceptLossFlags(id uint) {
	acceptLossBrokenIDs = []uint{id}
	acceptLossOperator = "ops-oncall"
	acceptLossReason = "INC-42"
	acceptLossEvidence = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func TestAcceptLoss_RequiresConfirmThenSeals(t *testing.T) {
	resetAcceptLossFlags(t)
	cfg, st, _, dbPath := acceptLossFixture(t)
	ctx := context.Background()

	acceptLossFlags(5)
	req, err := acceptLossRequest()
	require.NoError(t, err)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nothing was written")
	_, found, err := st.GetSystemMetadata(ctx, "audit_seals")
	require.NoError(t, err)
	assert.False(t, found, "without --confirm nothing is written")

	// The wrong id is refused before anything is written.
	acceptLossBrokenIDs = []uint{6}
	acceptLossConfirm = true
	req, err = acceptLossRequest()
	require.NoError(t, err)
	err = acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req)
	require.ErrorIs(t, err, core.ErrAuditLossRefused)

	acceptLossBrokenIDs = []uint{5}
	req, err = acceptLossRequest()
	require.NoError(t, err)
	require.NoError(t, acceptLoss(ctx, cfg, st, acceptLossTestKey, "v1", req))

	db, err := auditverify.OpenSQLiteReadOnly(dbPath)
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck
	r, err := auditverify.Verify(ctx, db, auditverify.Options{CheckpointKey: acceptLossTestKey})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	assert.Equal(t, 4, r.ExitCode())

	witness, _, found, err := auditverify.ReadWitness(auditverify.WitnessPath(dbPath))
	require.NoError(t, err)
	require.True(t, found, "the witness file is written with the sealed mark")
	assert.Equal(t, 1, witness.Seals)
}

func TestAcceptLoss_FlagValidation(t *testing.T) {
	resetAcceptLossFlags(t)
	_, err := acceptLossRequest()
	assert.ErrorContains(t, err, "--operator")
	acceptLossFlags(5)
	acceptLossEvidence = "not-a-digest"
	_, err = acceptLossRequest()
	assert.ErrorContains(t, err, "--evidence-sha256")
	acceptLossFlags(5)
	acceptLossOperator = "ops\nseal #2 accepted by root"
	_, err = acceptLossRequest()
	assert.ErrorContains(t, err, "--operator contains a control")
	acceptLossFlags(5)
	acceptLossReason = "INC-42 \x1b[2K"
	_, err = acceptLossRequest()
	assert.ErrorContains(t, err, "--reason contains a control")
	acceptLossFlags(5)
	acceptLossReason = strings.Repeat("r", core.AuditLossReasonMaxLen+1)
	_, err = acceptLossRequest()
	assert.ErrorContains(t, err, "--reason is longer than")
	acceptLossFlags(5)
	acceptLossOperator = strings.Repeat("o", core.AuditLossOperatorMaxLen)
	acceptLossReason = strings.Repeat("r", core.AuditLossReasonMaxLen)
	_, err = acceptLossRequest()
	assert.NoError(t, err, "values at the limit are accepted")
	acceptLossFlags(5)
	acceptLossAnchorSHA256 = "zz"
	_, err = acceptLossRequest()
	assert.ErrorContains(t, err, "--anchor-sha256")
}

// Restore understands sealed marks: an archive from before a seal this host
// accepted is a rollback even though its count is higher; one from after a
// seal the witness has not seen is not.
func TestCheckRollbackProtection_SealedMarks(t *testing.T) {
	resetBackupRestoreFlags(t)
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	pre := auditverify.EncodeHighWater(&auditverify.Checkpoint{ChainedEvents: 100, HeadID: 100, HeadHash: "aa", KeyVersion: "v1"}, "sig")
	sealed := auditverify.EncodeHighWater(&auditverify.Checkpoint{ChainedEvents: 90, HeadID: 101, HeadHash: "bb", KeyVersion: "v1",
		Seals: 1, SealDigest: "cc"}, "sig")

	wrote, err := auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), pre)
	require.NoError(t, err)
	require.True(t, wrote)
	wrote, err = auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), sealed)
	require.NoError(t, err)
	assert.True(t, wrote, "a sealed mark is newer than a higher pre-seal count")
	wrote, err = auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), pre)
	require.NoError(t, err)
	assert.False(t, wrote, "the witness never goes back before a seal")

	restoreAllowRollback = false
	_, err = checkRollbackProtection(pre, dbPath, 0, 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "before audit loss acceptance #1")
	restoreAllowRollback = true
	out, err := checkRollbackProtection(pre, dbPath, 0, 0, 0)
	require.NoError(t, err)
	assert.True(t, out.overrodeRollback)

	restoreAllowRollback = false
	out, err = checkRollbackProtection(sealed, dbPath, 0, 0, 0)
	require.NoError(t, err)
	assert.False(t, out.overrodeRollback, "the sealed archive is current")

	require.NoError(t, os.Remove(auditverify.WitnessPath(dbPath)))
	_, err = auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), pre)
	require.NoError(t, err)
	out, err = checkRollbackProtection(sealed, dbPath, 0, 0, 0)
	require.NoError(t, err, "an archive from after a seal the witness has not seen is not a rollback")
	assert.False(t, out.overrodeRollback)
}
