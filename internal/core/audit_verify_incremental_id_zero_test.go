package core

// AUDIT-VERIFY-ONLINE-1 item 1 (#3808, the incremental path): with incremental
// verification on, GET /audit/verify and gRPC VerifyAuditChain check only the
// tail after the latest checkpoint. An id 0 row (outside every keyset walk) was
// counted only by a walk from the chain start, so it read valid until the
// rolling cycle came round to its first segment again. The request now reports
// it broken, and the next tick refuses to extend the checkpoint.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func insertIDZeroAuditRow(t *testing.T, db *gorm.DB, at time.Time) {
	t.Helper()
	require.NoError(t, db.Exec(`INSERT INTO audit_events (id, event_type, description, event_time, actor_type, prev_hash, entry_hash, ip_address, diff, impersonation)
		VALUES (0, 'secret.read', 'forged', ?, 'user', 'x', 'y', '', '', false)`, at).Error)
}

// assertIncrementalSeesIDZero proves the chain with one rolling cycle, inserts
// an id 0 row and expects the very next request to read broken.
func assertIncrementalSeesIDZero(t *testing.T, c *KeyorixCore, db *gorm.DB, clk *incrClock, segments int) {
	t.Helper()
	logIncrEvents(t, c, clk, 20)
	_, _, err := c.WriteAuditCheckpoint(context.Background())
	require.NoError(t, err)
	for range segments {
		clk.advance()
		logIncrEvents(t, c, clk, 2)
		tickOK(t, c)
	}
	r := incrVerify(t, c)
	require.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)

	insertIDZeroAuditRow(t, db, clk.t)
	r = incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status, "an id 0 row must not read valid until the rolling cycle comes round")
	assert.Contains(t, r.Reason, "outside the chain")

	clk.advance()
	res, err := c.RunAuditVerificationTick(context.Background())
	if err == nil {
		assert.False(t, res.Written, "the next tick must not extend the checkpoint over a chain with a row outside it")
	}
	assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status)
}

func TestIncrementalVerify_IDZeroRowCaughtByNextRequest(t *testing.T) {
	t.Parallel()
	c, db, clk := newIncrementalTestCore(t, 3)
	assertIncrementalSeesIDZero(t, c, db, clk, 3)
}

func TestIncrementalVerify_IDZeroRowCaughtByNextRequest_Postgres(t *testing.T) {
	t.Parallel()
	dsn := pgJobLockDSN(t)
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	clk := &incrClock{t: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
	assertIncrementalSeesIDZero(t, newIncrementalPGReplica(t, dsn, clk), db, clk, 3)
}
