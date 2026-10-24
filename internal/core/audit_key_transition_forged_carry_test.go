// audit_key_transition_forged_carry_test.go — a key change must not launder a
// forged artifact (AUDIT-ROTATE-TRANSITION-2, review of #3648 at 9db14dfe).
//
// The transition record names the digests of the stored state, high-water mark,
// retention anchor and latest checkpoint, and completion re-signs the anchor and
// the high-water mark under the new key when their digest matches. A DB-write
// actor without any key can plant a forged value labelled with the old key
// version before the rotation: under the old key it is ignored (anchor) or reads
// as tampering (high-water), but if prepare names its digest, completion stamps
// it with a valid new-key signature. Prepare must name only artifacts that
// authenticate under the old key; anything else is not carried over.
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const aktForgedSig = "00000000000000000000000000000000000000000000000000000000deadbeef"

// A forged retention anchor (label v1, junk signature) claims rows below a
// surviving event were purged. Before the rotation it is ignored; after it, it
// must still not authenticate, so deleting the rows below it is not a
// sanctioned purge and the walk does not read valid.
func TestAuditKeyTransition_ForgedAnchorNotLaundered(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		var evs []models.AuditEvent
		require.NoError(t, e.db.Where("entry_hash <> ''").Order("id").Find(&evs).Error)
		require.Greater(t, len(evs), 4, "precondition: a chained trail")
		cut := evs[3]
		forged := auditRetentionAnchorValueV2(cut.ID, cut.PrevHash, cut.EntryHash, 3, "v1", aktForgedSig)
		require.NoError(t, e.c.storage.SetSystemMetadata(ctx, auditRetentionAnchorKey, forged))
		a, err := e.c.loadAuditRetentionAnchor(ctx)
		require.NoError(t, err)
		require.Nil(t, a, "precondition: the forged anchor does not authenticate under the old key")

		c2 := aktRotate(t, e)

		a, err = c2.loadAuditRetentionAnchor(ctx)
		require.NoError(t, err)
		assert.Nil(t, a, "completion re-signed a forged retention anchor under the new key")
		require.NoError(t, e.db.Where("id < ?", cut.ID).Delete(&models.AuditEvent{}).Error)
		v, err := c2.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.False(t, v.Valid, "rows deleted below a forged anchor must not verify as a sanctioned purge")
	})
}

// A forged high-water mark (label v1, junk signature) lowers the certified
// count to 1. Before the rotation it reads as tampering; after it, it must
// still not authenticate, so the anti-rollback floor is not lowered.
func TestAuditKeyTransition_ForgedHighWaterNotLaundered(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		val, ok, err := e.c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
		require.NoError(t, err)
		require.True(t, ok, "precondition: a high-water mark exists")
		hw, _, parsed := parseAuditHighWater(val)
		require.True(t, parsed)
		require.Greater(t, hw.ChainedEvents, int64(1))
		hw.ChainedEvents = 1
		require.NoError(t, e.c.storage.SetSystemMetadata(ctx, auditHighWaterKey, auditHighWaterValue(hw, aktForgedSig)))

		c2 := aktRotate(t, e)

		val, ok, err = c2.storage.GetSystemMetadata(ctx, auditHighWaterKey)
		require.NoError(t, err)
		require.True(t, ok)
		got, sig, parsed := parseAuditHighWater(val)
		require.True(t, parsed)
		assert.False(t, got.ChainedEvents == 1 && c2.checkpointSigMatches(got, sig),
			"completion re-signed a forged high-water mark (count 1) under the new key")
	})
}
