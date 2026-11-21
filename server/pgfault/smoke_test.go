package pgfault

import (
	"context"
	"testing"
	"time"
)

// TestPGFault_Smoke proves the whole rig works end to end against a real server
// with NO fault armed: a burst of commits through the proxy all land and the
// audit chain verifies. If this skips, no DSN was provided.
func TestPGFault_Smoke(t *testing.T) {
	w := newPGWorld(t)
	w.truncate(t)

	ls := openProxiedStorage(t, w)
	defer func() { _ = ls.Close() }()

	ctx := context.Background()
	acked := commitBurst(ctx, ls, 10, 5*time.Second)
	if len(acked) != 10 {
		t.Fatalf("unfaulted burst: want 10 acked, got %d", len(acked))
	}

	present := w.presentIndices(t)
	for _, i := range acked {
		if !present[i] {
			t.Fatalf("acked commit %d missing with no fault armed", i)
		}
	}
	res, err := w.verifyStorage().VerifyAuditChain(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res == nil || !res.Valid {
		t.Fatalf("audit chain invalid with no fault: %+v", res)
	}
	t.Logf("smoke ok: acked=%d present=%d chained=%d", len(acked), len(present), res.ChainedEvents)
}
