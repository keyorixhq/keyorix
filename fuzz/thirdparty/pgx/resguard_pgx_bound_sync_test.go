package pgxhostile

import (
	"math"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"
)

// TestCommittedBudgetsCarryTheCurrentProductBound closes a gap the fuzz runs cannot:
// they load the committed JSON snapshot and never re-derive it from pgxlimits, so
// changing pgxlimits.MaxProtocolMessageBodyLen without recalibrating would leave
// the oracle at the old bound without any failure. For every length-prefixed pgx
// budget, abs_max must equal floor*factor + the product bound. It does NOT check
// that floor itself is current (RESGUARD_CALIBRATE=1 does that) and does not apply
// to the SSL target, which has no claimed length.
func TestCommittedBudgetsCarryTheCurrentProductBound(t *testing.T) {
	for _, path := range []string{pgxBudgetCopy, pgxBudgetExtended, pgxBudgetHandshake, pgxBudgetSimpleQuery} {
		b, err := resguard.LoadBudget(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		m, ok := b.Meters["alloc_bytes"]
		if !ok {
			t.Fatalf("%s: no alloc_bytes meter", path)
		}
		want := m.Floor*b.Factor + float64(pgxlimits.MaxProtocolMessageBodyLen)
		if m.Mode != resguard.ModeAbsolute || math.Abs(m.AbsMax-want) > 1 {
			t.Errorf("%s: alloc_bytes abs_max=%v mode=%q, want %v in absolute mode (floor %v * factor %v + bound %d): "+
				"recalibrate with RESGUARD_CALIBRATE=1", path, m.AbsMax, m.Mode, want, m.Floor, b.Factor, pgxlimits.MaxProtocolMessageBodyLen)
		}
	}
}
