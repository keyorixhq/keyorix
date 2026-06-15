package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/notary"
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

// fakeNotary is a stand-in external authority for the anchoring wiring tests
// (the real RFC 3161 verify path is covered by the notary package round-trip).
type fakeNotary struct {
	token   []byte
	at      time.Time
	err     error
	calls   int
	lastMsg []byte
}

func (f *fakeNotary) Anchor(_ context.Context, msg []byte) (*notary.Receipt, error) {
	f.calls++
	f.lastMsg = append([]byte(nil), msg...)
	if f.err != nil {
		return nil, f.err
	}
	return &notary.Receipt{Token: f.token, Time: f.at, Provider: "fake"}, nil
}
func (f *fakeNotary) Provider() string { return "fake" }

func TestAuditCheckpoint_AnchorsWhenNotarySet(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 3)
	fn := &fakeNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	c.SetCheckpointNotary(fn)

	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)

	// The receipt is reflected on the returned checkpoint...
	require.Equal(t, 1, fn.calls)
	require.NotNil(t, cp.AnchoredAt)
	assert.Equal(t, "fake", cp.AnchorProvider)
	assert.Equal(t, []byte("opaque-tsa-token"), cp.AnchorToken)
	// ...the notary saw exactly the checkpoint's canonical bytes...
	assert.Equal(t, []byte(checkpointCanonical(cp)), fn.lastMsg)
	// ...and the receipt was persisted on the row.
	var row models.AuditCheckpoint
	require.NoError(t, db.First(&row, cp.ID).Error)
	assert.Equal(t, []byte("opaque-tsa-token"), row.AnchorToken)
	require.NotNil(t, row.AnchoredAt)
	assert.Equal(t, "fake", row.AnchorProvider)
}

func TestAuditCheckpoint_AnchorIsBestEffort(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 2)
	c.SetCheckpointNotary(&fakeNotary{err: fmt.Errorf("tsa unreachable")})

	// A notary failure must NOT fail the checkpoint write.
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Nil(t, cp.AnchoredAt)

	var row models.AuditCheckpoint
	require.NoError(t, db.First(&row, cp.ID).Error)
	assert.Empty(t, row.AnchorToken, "an un-anchored checkpoint is still a valid checkpoint")
}

func TestVerifyCheckpointAnchor_NoAnchor(t *testing.T) {
	c, _ := newCheckpointCore(t)
	at, ok, err := c.VerifyCheckpointAnchor(&models.AuditCheckpoint{ID: 1})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.True(t, at.IsZero())
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
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")
}

// A DB-level actor must not be able to disable enforcement by editing the
// unauthenticated key_version column — the HMAC binds key_version, so the edit
// fails the signature check (regression guard for the pre-merge security finding).
func TestAuditCheckpoint_TamperedKeyVersionDetected(t *testing.T) {
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)

	// Attacker flips key_version to force the (old) "not enforced" branch, then
	// truncates. The signature now fails, so enforcement is NOT skipped.
	require.NoError(t, db.Exec("UPDATE audit_checkpoints SET key_version = 'forged'").Error)
	require.NoError(t, db.Exec("DELETE FROM audit_events WHERE id >= 4").Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a tampered key_version must not disable enforcement")
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")
}

// After a genuine DEK rotation the prior checkpoint cannot be re-verified, so
// verify reports invalid until the next checkpoint write re-baselines under the
// new key — and that write must succeed (no deadlock).
func TestAuditCheckpoint_RotationRebaselines(t *testing.T) {
	ctx := context.Background()
	c, _ := newCheckpointCore(t)
	logEvents(t, c, 5)
	_, _, err := c.WriteAuditCheckpoint(ctx) // signed under "v1"
	require.NoError(t, err)

	// Rotate the DEK → a new signing key + version.
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0x9}, 32), "v2")

	// The stale "v1" checkpoint no longer verifies → flagged (fail closed).
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "a stale checkpoint after rotation is not silently trusted")
	assert.Contains(t, v.CheckpointReason, "does not verify under the current signing key")

	// A fresh checkpoint re-baselines under the new key (no deadlock).
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, "v2", cp.KeyVersion)

	v, err = c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "recovered after re-baseline")
	assert.True(t, v.Checkpointed)
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

// A checkpoint written over an empty chain (HeadID=0) must not later false-alarm
// once events accumulate — there is no head row 0 to "go missing".
func TestAuditCheckpoint_GenesisCheckpointNoFalsePositive(t *testing.T) {
	ctx := context.Background()
	c, _ := newCheckpointCore(t)

	cp, written, err := c.WriteAuditCheckpoint(ctx) // empty chain → certifies 0
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, int64(0), cp.ChainedEvents)
	assert.Equal(t, uint(0), cp.HeadID)

	logEvents(t, c, 4) // chain grows past the genesis checkpoint

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "a growing chain is not a truncation of the genesis checkpoint")
	assert.True(t, v.Checkpointed)
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
	assert.Contains(t, err.Error(), "truncated below signed checkpoint")

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
