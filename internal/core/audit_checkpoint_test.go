package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newCheckpointCore builds a real-SQLite core with a fixed checkpoint signing key.
func newCheckpointCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	return c, db
}

func logEvents(t *testing.T, c *KeyorixCore, n int) {
	t.Helper()
	// A fixed, second-aligned UTC base so EventTime round-trips through SQLite
	// exactly (sub-microsecond precision from time.Now() would not, making the
	// recomputed entry hash flaky).
	base := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	tr := true
	for i := 0; i < n; i++ {
		require.NoError(t, c.storage.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType:   "secret.read",
			Description: fmt.Sprintf("event %d", i),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			// Set explicitly: the column defaults to "user", and the hash binds
			// ActorType raw, so an unset field would hash "" but store "user".
			ActorType: "user",
		}))
	}
}

func TestAuditCheckpoint_HappyPath(t *testing.T) {
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 5)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, int64(5), cp.ChainedEvents)
	assert.Equal(t, "v1", cp.KeyVersion)
	assert.NotEmpty(t, cp.Signature)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.True(t, v.Checkpointed)
	assert.Empty(t, v.CheckpointReason)
}

func TestAuditCheckpoint_DetectsTailTruncation(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // certifies 5
	require.NoError(t, err)

	// Drop the tail → a self-consistent SHORTER chain. The bare re-walk passes;
	// only the signed checkpoint catches the drop.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)

	raw, err := c.storage.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, raw.Valid, "the bare chain walk cannot catch tail-truncation on its own")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "the checkpoint catches it")
	assert.True(t, v.Checkpointed)
	assert.Contains(t, v.CheckpointReason, "truncated below signed checkpoint")
}

func TestAuditCheckpoint_DetectsForgedCheckpoint(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// A DB-level actor lowers the certified count to mask a planned truncation,
	// but cannot re-sign without the key → signature no longer recomputes.
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET chained_events = 1").Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid)
	assert.Contains(t, v.CheckpointReason, "signature is invalid")
}

func TestAuditCheckpoint_NoKeyIsNoOp(t *testing.T) {
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	c.SetAuditCheckpointKey(nil, "") // simulate encryption disabled
	logEvents(t, c, 3)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Nil(t, cp)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.False(t, v.Checkpointed, "no key → no on-box checkpoint enforcement")
}

func TestAuditCheckpoint_KeyVersionMismatchNotEnforced(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // signed under "v1"
	require.NoError(t, err)

	// Simulate a DEK rotation: the in-memory key version moves on.
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v2")
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "a checkpoint signed under a superseded key version is not enforced")
	assert.False(t, v.Checkpointed)
	assert.Contains(t, v.CheckpointReason, "not enforced")
}

func TestAuditCheckpoint_RefusesBrokenChain(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)

	// Delete a MIDDLE row → linkage breaks; the chain does not verify.
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id = 3").Error)

	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.Error(t, err)
	assert.False(t, written)
	assert.Contains(t, err.Error(), "refusing to checkpoint")
}

func TestAuditCheckpoint_NoRebaselineOverTruncation(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // certifies 5
	require.NoError(t, err)

	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error) // truncate to 3

	// A subsequent scheduled checkpoint must NOT silently re-baseline to the
	// shorter chain (which would erase the tamper evidence going forward).
	_, written, err := c.WriteAuditCheckpoint(ctx)
	require.Error(t, err)
	assert.False(t, written)
	assert.Contains(t, err.Error(), "does not verify")

	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no new checkpoint papered over the truncation")
}

func TestAuditCheckpoint_SignDeterministicAndBinding(t *testing.T) {
	c := &KeyorixCore{}
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x1}, 32), "v1")
	cp := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "abc", KeyVersion: "v1"}
	sig := c.signCheckpoint(cp)
	require.NotEmpty(t, sig)
	assert.Equal(t, sig, c.signCheckpoint(cp), "deterministic for fixed inputs")

	cp.Signature = sig
	assert.True(t, c.checkpointSignatureValid(cp))

	for _, mut := range []func(){
		func() { cp.ChainedEvents = 4 },
		func() { cp.HeadID = 6 },
		func() { cp.HeadHash = "abd" },
		func() { cp.KeyVersion = "v2" },
	} {
		fresh := &models.AuditCheckpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "abc", KeyVersion: "v1", Signature: sig}
		cp = fresh
		mut()
		assert.False(t, c.checkpointSignatureValid(cp), "every signed field is bound")
	}
}
