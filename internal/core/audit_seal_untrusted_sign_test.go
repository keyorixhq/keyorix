// audit_seal_untrusted_sign_test.go — nothing is signed against a seal list
// that cannot be trusted (binding N < 0, audit_seal.go), and a key transition
// does not complete while the seals are untrusted (AUDIT-SEAL-TAILS-1,
// REVIEW-3757-DEEP-3 finding 1). Before, completion re-signed the carried
// high-water mark over the "v2\x00-1\x00\x00..." form, which then verified
// whenever the binding was untrusted again.
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func untrustedMeta(t *testing.T, db *gorm.DB, key string) string {
	t.Helper()
	var row models.SystemMetadata
	require.NoError(t, db.Where(&models.SystemMetadata{Key: key}).First(&row).Error)
	return row.Value
}

func untrustedCheckpoints(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditCheckpoint{}).Count(&n).Error)
	return n
}

// untrustedTampers make the seal row untrusted without deleting it (a deleted
// row is "no seals", caught by the walk, the bound artifacts and the state).
var untrustedTampers = []struct {
	name   string
	tamper func(t *testing.T, db *gorm.DB)
}{
	{"garbled", func(t *testing.T, db *gorm.DB) { setSealsValue(t, db, "garbage") }},
	{"forged MAC", func(t *testing.T, db *gorm.DB) {
		parts := strings.Split(sealsValue(t, db), auditVerifyStateSep)
		parts[3] = strings.Repeat("0", len(parts[3]))
		setSealsValue(t, db, strings.Join(parts, auditVerifyStateSep))
	}},
}

// A key transition prepared over an authentic seal row, whose row is then
// garbled or forged before completion, stops with a named error: no mark is
// re-signed, no checkpoint is written, and the transition stays open.
func TestAuditSeal_UntrustedSealsBlockKeyTransitionCompletion(t *testing.T) {
	for _, tc := range untrustedTampers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				c, _ := sealedEnv(t, e)
				assertSealed(t, e, c, 1)
				require.NoError(t, c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
				tc.tamper(t, e.db)
				hw, cps := untrustedMeta(t, e.db, auditHighWaterKey), untrustedCheckpoints(t, e.db)

				p := e.restart()
				p.SetAuditCheckpointKey(aktNewKey, "v2")
				_, err := p.CompleteAuditKeyTransition(ctx)
				require.Error(t, err, "completion must stop while the seal record cannot be trusted")
				assert.Contains(t, err.Error(), "cannot be trusted")
				assert.Equal(t, hw, untrustedMeta(t, e.db, auditHighWaterKey), "the high-water mark is not re-signed against an untrusted seal list")
				assert.Equal(t, cps, untrustedCheckpoints(t, e.db), "no checkpoint is written")
				assert.Zero(t, countEvents(t, e.db, auditKeyTransitionEvent), "the transition stays open")

				// A retry (the next server start) refuses the same way.
				p2 := e.restart()
				p2.SetAuditCheckpointKey(aktNewKey, "v2")
				_, err = p2.CompleteAuditKeyTransition(ctx)
				require.ErrorContains(t, err, "cannot be trusted")
				assertBroken(t, e, p)
			})
		})
	}
}

// With the seal row untrusted, the high-water writer signs nothing: the mark
// (and the witness it mirrors) stays as it was.
func TestAuditSeal_UntrustedSealsSignNoHighWater(t *testing.T) {
	for _, tc := range untrustedTampers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				_, _ = sealedEnv(t, e)
				tc.tamper(t, e.db)
				p := e.restart()
				set, err := p.loadAuditSeals(ctx)
				require.NoError(t, err)
				require.NotEmpty(t, set.problem, "precondition: the seal record is untrusted")
				hw := untrustedMeta(t, e.db, auditHighWaterKey)
				cur, _, ok := parseAuditHighWater(hw)
				require.True(t, ok)
				p.advanceAuditHighWater(ctx, &models.AuditCheckpoint{ChainedEvents: cur.ChainedEvents + 50, HeadID: cur.HeadID + 50, HeadHash: cur.HeadHash, KeyVersion: cur.KeyVersion})
				assert.Equal(t, hw, untrustedMeta(t, e.db, auditHighWaterKey), "no mark is signed against an untrusted seal list")
			})
		})
	}
}

// With the seal row untrusted, neither the scheduled tick nor an explicit
// checkpoint write produces a new signed checkpoint.
func TestAuditSeal_UntrustedSealsSignNoCheckpoint(t *testing.T) {
	for _, tc := range untrustedTampers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				_, _ = sealedEnv(t, e)
				tc.tamper(t, e.db)
				cps := untrustedCheckpoints(t, e.db)
				p := e.restart()
				fcTick(t, e, p)
				_, _, err := p.WriteAuditCheckpoint(ctx)
				require.ErrorIs(t, err, ErrAuditCheckpointRefused)
				assert.Equal(t, cps, untrustedCheckpoints(t, e.db), "no checkpoint is signed against an untrusted seal list")
			})
		})
	}
}
