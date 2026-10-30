// audit_seal_witness_before_test.go — the host's high-water witness (SQLite
// installs) in a first acceptance (AUDIT-SEAL-TAILS-1, REVIEW-3757-DEEP-3
// finding 2). After an in-database rollback of the metadata the witness is
// the one certification that still counts the lost rows: it counts in the
// plan's Before, the plan names it, and the apply never lowers a witness the
// confirmed plan did not show. A witness under a seal list the database does
// not hold proves the database, seal record included, was rolled back.
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL (the
// witness is a file next to the core either way).
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// witnessRollbackEnv: a certified SQLite-style deployment with a witness;
// three more events are certified by a checkpoint (the witness follows it),
// then the database metadata is put back to before that checkpoint, the two
// newest rows are cut and row 3 is deleted. Only the witness still certifies
// the cut tail. It returns the core, the gap's resume id, the witness head
// and the witness value.
func witnessRollbackEnv(t *testing.T, e *fcEnv, w string) (*KeyorixCore, uint, *models.AuditCheckpoint, string) {
	t.Helper()
	ctx := context.Background()
	withWitness(e.c, w)
	fcCertify(t, e)
	hwCopy, ok, err := e.c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	require.NoError(t, err)
	require.True(t, ok)
	stCopy := fcStateValue(t, e.db)
	old, err := e.c.storage.LatestAuditCheckpoint(ctx)
	require.NoError(t, err)

	e.clk.advance()
	logIncrEvents(t, e.c, e.clk, 3)
	cp, _, err := e.c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	witness := readWitnessFile(t, w)
	wcp, _, _, parsed := parseAuditHighWaterSealed(witness)
	require.True(t, parsed)
	require.Equal(t, cp.ChainedEvents, wcp.ChainedEvents, "precondition: the witness follows the checkpoint")

	require.NoError(t, e.db.Where("id > ?", old.ID).Delete(&models.AuditCheckpoint{}).Error)
	require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", hwCopy).Error)
	fcSetStateValue(t, e.db, stCopy)
	require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", wcp.HeadID-1).Error)
	c := withWitness(e.restart(), w)
	resume := sealDeleteRow(t, e, c, 3)
	return c, resume, wcp, witness
}

// The witness counts in Before and the plan names it; a plan that leaves the
// witness's missing head out of the named loss is refused.
func TestAuditSeal_WitnessAboveDatabaseCountsInPlan(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		c, resume, wcp, witness := witnessRollbackEnv(t, e, w)

		_, err := c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.ErrorIs(t, err, ErrAuditLossRefused, "the witness's head is gone and not named")
		assert.Contains(t, err.Error(), "witness")
		assert.Equal(t, witness, readWitnessFile(t, w))

		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq(resume, wcp.HeadID))
		require.NoError(t, err)
		require.NotNil(t, plan.Before)
		assert.Equal(t, wcp.ChainedEvents, plan.Before.Events, "Before is the witness")
		assert.Contains(t, plan.Before.Source, "witness")
		assert.Equal(t, int64(3), plan.LostEvents, "row 3 and the two cut rows")
		text := strings.Join(plan.Describe(), "\n")
		assert.Contains(t, text, "host witness file")
		assert.Contains(t, text, "LOWERS")

		res, err := c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assert.Equal(t, res.HighWater, readWitnessFile(t, w), "lowered to what survives, as the confirmed plan said")
	})
}

// A witness raised between the plan and the apply (more than the plan named)
// is not lowered: the apply refuses before writing anything.
func TestAuditSeal_ApplyRefusesUnnamedHigherWitness(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		withWitness(e.c, w)
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		c := withWitness(e.restart(), w)
		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)

		// An authentic witness certifying more than the plan's Before.
		wcp, _, _, parsed := parseAuditHighWaterSealed(readWitnessFile(t, w))
		require.True(t, parsed)
		higher := &models.AuditCheckpoint{ChainedEvents: wcp.ChainedEvents + 5, HeadID: wcp.HeadID + 5, HeadHash: strings.Repeat("f", 64), KeyVersion: wcp.KeyVersion}
		mac := hmac.New(sha256.New, c.auditCkptKey)
		mac.Write([]byte(checkpointCanonicalSealed(higher.ChainedEvents, higher.HeadID, higher.HeadHash, higher.KeyVersion, auditSealBinding{})))
		val := auditHighWaterValue(higher, hex.EncodeToString(mac.Sum(nil)))
		require.NoError(t, os.WriteFile(w, []byte(val), 0o600))

		_, err = c.AcceptAuditLoss(ctx, plan)
		require.Error(t, err, "the apply must not lower a witness the plan did not name")
		assert.Contains(t, err.Error(), "witness")
		assert.Equal(t, val, readWitnessFile(t, w), "the witness is not lowered")
		_, found, err := c.storage.GetSystemMetadata(ctx, auditSealsKey)
		require.NoError(t, err)
		assert.False(t, found, "nothing is written: no seal record")
	})
}

// A whole-trail rollback inside the database to before a completed
// acceptance (seal record, its event and every later row, checkpoint, mark
// and state put back) reads as a fresh, unsealed loss; the witness, written
// under the seal, proves the rollback and a second acceptance is refused.
func TestAuditSeal_WitnessUnderRolledBackSealRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		withWitness(e.c, w)
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		hwCopy, ok, err := e.c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
		require.NoError(t, err)
		require.True(t, ok)
		stCopy := fcStateValue(t, e.db)
		old, err := e.c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		var maxID uint
		require.NoError(t, e.db.Raw("SELECT MAX(id) FROM audit_events").Scan(&maxID).Error)

		sealAccept(t, e.c, sealReq(resume))
		witness := readWitnessFile(t, w)
		_, b, _, parsed := parseAuditHighWaterSealed(witness)
		require.True(t, parsed)
		require.Equal(t, 1, b.N, "precondition: the witness is under the seal")

		require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditSealsKey}).Delete(&models.SystemMetadata{}).Error)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id > ?", maxID).Error)
		require.NoError(t, e.db.Where("id > ?", old.ID).Delete(&models.AuditCheckpoint{}).Error)
		require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", hwCopy).Error)
		fcSetStateValue(t, e.db, stCopy)

		c := withWitness(e.restart(), w)
		_, err = c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.ErrorIs(t, err, ErrAuditLossRefused, "the witness proves the seal list was rolled back")
		assert.Contains(t, err.Error(), "rolled back")
		assert.Equal(t, witness, readWitnessFile(t, w))
	})
}
