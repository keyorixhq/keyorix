package mysqlhostile

import (
	"math"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// TestCommittedBudgetsCarryTheProtocolBound: the MySQL twin of the pgx check. The
// fuzz runs load the committed JSON and never re-derive it, so abs_max must be
// floor*factor + the protocol's per-packet maximum, or a recalibration that changed
// the formula would pass unnoticed. Does not check that floor itself is current.
func TestCommittedBudgetsCarryTheProtocolBound(t *testing.T) {
	for _, path := range []string{"testdata/resguard-mysql-handshake.json", "testdata/resguard-mysql-query.json", "testdata/resguard-mysql-prepared.json"} {
		b, err := resguard.LoadBudget(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		m, ok := b.Meters["alloc_bytes"]
		if !ok {
			t.Fatalf("%s: no alloc_bytes meter", path)
		}
		want := m.Floor*b.Factor + float64(mysqlMaxPacket)
		if m.Mode != resguard.ModeAbsolute || math.Abs(m.AbsMax-want) > 1 {
			t.Errorf("%s: alloc_bytes abs_max=%v mode=%q, want %v in absolute mode: recalibrate with RESGUARD_CALIBRATE=1", path, m.AbsMax, m.Mode, want)
		}
	}
}
