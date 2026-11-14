// cta_review_legal_hold_lift_cases_test.go — STORE-STALE-NOV-2 item 1 (#4210).
//
// Two replicas lift the same legal hold. Replica A reads the active hold with no
// lock (LiftLegalHold's GetActiveLegalHold), replica B's complete lift commits on
// its own connection, then A writes. Before #4210 A's write was an unconditional
// Save of the struct it read: it reported success, overwrote B's release_reason
// and released_by, and audited a second lift. Now the write is a conditional
// UPDATE on released=false, so A matches no row and is refused with
// ErrLegalHoldAlreadyReleased, writing no audit row. Run on both backends by
// cta_review_legal_hold_lift_postgres_test.go and
// cta_review_legal_hold_lift_sqlite_test.go.
//
// The assertions use only symbols that existed before the fix (the error is
// matched by its text), so the same test compiles against the pre-fix tree and
// is red there for the behaviour, not for a missing symbol.
package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// afterAUnlockedLegalHoldRead runs concurrent once, right after replica A's
// first query that loaded a legal hold outside a transaction. Returns whether it
// fired, so the case fails loudly if A never made that read.
func (f *ctaReview) afterAUnlockedLegalHoldRead(concurrent func()) (fired func() bool) {
	f.t.Helper()
	hit := false
	fn := func(tx *gorm.DB) {
		if hit || tx.Error != nil {
			return
		}
		if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); inTx {
			return
		}
		if _, ok := tx.Statement.Dest.(*models.LegalHold); !ok {
			return
		}
		hit = true
		concurrent()
	}
	require.NoError(f.t, f.dbA.Callback().Query().After("gorm:query").Register("legal-hold-lift:after-read", fn))
	return func() bool { return hit }
}

func runLegalHoldLiftRace(t *testing.T, f *ctaReview) {
	hold, err := f.setup.PlaceLegalHold(f.ctx, f.adminID, "litigation INC-42")
	require.NoError(t, err)

	var errB error
	fired := f.afterAUnlockedLegalHoldRead(func() {
		errB = f.coreB.LiftLegalHold(f.ctx, f.adminID, "B: INC-42 settled")
	})
	errA := f.coreA.LiftLegalHold(f.ctx, f.adminID, "A: INC-42 dropped")
	require.True(t, fired(), "the hook never fired: A made no unlocked legal-hold read, the case is vacuous")
	require.NoError(t, errB, "B's lift, which ran first, must succeed")

	require.Error(t, errA, "A's lift, built on a pre-lift read, reported success over B's lift")
	assert.Contains(t, errA.Error(), "already released", "A must get the typed already-released refusal")

	var got models.LegalHold
	require.NoError(t, f.setupDB.First(&got, hold.ID).Error)
	assert.True(t, got.Released)
	assert.Equal(t, "B: INC-42 settled", got.ReleaseReason, "A's losing lift overwrote the first lifter's reason")

	var lifts []models.AuditEvent
	require.NoError(t, f.setupDB.Where("event_type = ?", EventLegalHoldLifted).Find(&lifts).Error)
	n := 0
	for _, e := range lifts {
		if strings.Contains(e.Description, "lifted by") {
			n++
		}
	}
	assert.Equal(t, 1, n, "a refused lift must not write a second lift audit row")
}
