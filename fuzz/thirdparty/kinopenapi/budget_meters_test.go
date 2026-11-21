package kinhostile

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// TestKinBudgets_LiveHeapNotMetered guards INV-FUZZKIN-liveheap-not-metered:
// both committed budgets meter the input-attributable alloc_bytes and mallocs
// and leave out the whole-process live_heap reading.
func TestKinBudgets_LiveHeapNotMetered(t *testing.T) {
	for _, p := range []string{budgetPath, loaderBudgetPath} {
		b, err := resguard.LoadBudget(p)
		if err != nil {
			t.Fatalf("committed budget %s: %v", p, err)
		}
		for _, m := range []string{"alloc_bytes", "mallocs"} {
			if _, ok := b.Meters[m]; !ok {
				t.Errorf("%s has no %s ceiling; meters=%v", p, m, b.Summary())
			}
		}
		if _, ok := b.Meters["live_heap"]; ok {
			t.Errorf("%s meters live_heap, which is dominated by the fuzz engine's own heap; meters=%v", p, b.Summary())
		}
	}
}
