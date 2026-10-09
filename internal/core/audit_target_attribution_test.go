package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// audit_target_attribution_test.go — the claim auditAttributionAllowlist makes
// about emitAuditOn (#2676).
//
// g80_1530_machine_actor_attribution_guard_test.go sweeps the repository for
// direct storage.LogAuditEvent callers that bypass emitAudit, because emitAudit
// is where a machine-typed event gets its MachineIdentityID stamped and its
// UserID cleared (#1530: a machine principal's ID must never occupy UserID).
// emitAuditOn is such a caller, and its allowlist entry asserts it is safe
// because it runs the same prepareAuditEventForEmit before writing.
//
// An allowlist entry is prose. This is the check. Without it the entry would be
// exactly what CLAUDE.md warns about — a comment that happens to sit in a
// guard's data structure, read as if it were enforcement.

// auditTargetTestWorld returns a core over real storage plus the raw DB for
// unfaulted verification reads.
func auditTargetTestWorld(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	return NewKeyorixCore(localstore.NewLocalStorage(db)), db
}

// TestEmitAuditOn_StampsMachineAttributionLikeEmitAudit: a machine-typed event
// written through the TRANSACTIONAL path must come out with MachineIdentityID
// set from the context and UserID cleared — identical to emitAudit.
func TestEmitAuditOn_StampsMachineAttributionLikeEmitAudit(t *testing.T) {
	t.Parallel()
	c, db := auditTargetTestWorld(t)

	const machineID = uint(77)
	userID := uint(5) // deliberately non-nil: the stamp must CLEAR it
	ctx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), machineID)

	sink := &auditForwardSink{}
	require.NoError(t, c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		ok := c.emitAuditOn(ctx, auditInto(tx, sink), &models.AuditEvent{
			EventType:   "test.machine_typed",
			UserID:      &userID,
			Description: "written through a transaction-scoped audit target",
			ActorType:   ActorTypeMachine,
		})
		require.True(t, ok, "the transactional write must report persisted")
		return nil
	}))

	var row models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "test.machine_typed").First(&row).Error)
	require.NotNil(t, row.MachineIdentityID,
		"#1530's stamp must be applied on the transactional path too: a machine-typed event with no "+
			"machine identity is an unattributable mutation")
	assert.Equal(t, machineID, *row.MachineIdentityID)
	assert.Nil(t, row.UserID,
		"a machine principal's ID must never occupy UserID — emitAuditOn must clear it exactly as emitAudit does")
}

// The off-box side effects must be DEFERRED, not skipped: after a successful
// commit the sink holds the event, and Flush delivers it. (emitAudit's own
// contract — "do NOT forward a phantom event ... the off-box mirror must
// reflect the durable chain" — is what makes deferral the right behaviour
// rather than immediate forwarding.)
func TestEmitAuditOn_DefersForwardingUntilFlush(t *testing.T) {
	t.Parallel()
	c, _ := auditTargetTestWorld(t)
	forwarded := &countingAuditForwarder{}
	c.auditForwarder = forwarded
	ctx := context.Background()

	sink := &auditForwardSink{}
	require.NoError(t, c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		require.True(t, c.emitAuditOn(ctx, auditInto(tx, sink), &models.AuditEvent{
			EventType: "test.deferred", Description: "deferred",
		}))
		assert.Zero(t, forwarded.n, "nothing may be forwarded while the transaction is still open — "+
			"it might yet roll back")
		return nil
	}))
	assert.Zero(t, forwarded.n, "still nothing until the caller flushes")

	sink.Flush(c)
	assert.Equal(t, 1, forwarded.n, "the committed event must be forwarded exactly once")

	sink.Flush(c)
	assert.Equal(t, 1, forwarded.n, "Flush must be idempotent — a second call must not re-forward")
}

// Rollback: an event written inside a transaction that rolls back must leave no
// row AND must never be forwarded. Dropping the sink unflushed is what delivers
// the second half, so this pins that the sink is not flushed on the error path.
func TestEmitAuditOn_RolledBackEventIsNeitherStoredNorForwarded(t *testing.T) {
	t.Parallel()
	c, db := auditTargetTestWorld(t)
	forwarded := &countingAuditForwarder{}
	c.auditForwarder = forwarded
	ctx := context.Background()

	sink := &auditForwardSink{}
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		require.True(t, c.emitAuditOn(ctx, auditInto(tx, sink), &models.AuditEvent{
			EventType: "test.rolled_back", Description: "rolled back",
		}))
		return assert.AnError // force a rollback
	})
	require.Error(t, err)
	// The caller does NOT flush on this path — mirroring
	// decideReviewItemRevokeAtomically, which flushes only after a nil error.

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "test.rolled_back").Count(&count).Error)
	assert.Zero(t, count, "the row must have rolled back with the transaction")
	assert.Zero(t, forwarded.n, "a rolled-back event must never reach the off-box mirror")
}

// Non-transactional calls must be byte-for-byte the old behaviour: emitAuditOn
// with no sink delegates to emitAudit, forwarding inline.
func TestEmitAuditOn_WithoutSinkForwardsInline(t *testing.T) {
	t.Parallel()
	c, db := auditTargetTestWorld(t)
	forwarded := &countingAuditForwarder{}
	c.auditForwarder = forwarded

	require.True(t, c.emitAuditOn(context.Background(), c.auditNow(), &models.AuditEvent{
		EventType: "test.inline", Description: "inline",
	}))
	assert.Equal(t, 1, forwarded.n, "with no sink there is no transaction to wait for — forward immediately")
	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "test.inline").Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// countingAuditForwarder counts Forward calls.
type countingAuditForwarder struct{ n int }

func (f *countingAuditForwarder) Forward(*models.AuditEvent) { f.n++ }
