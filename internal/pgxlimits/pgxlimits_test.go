package pgxlimits

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestApplySetsTheBoundAndOverridesAnyLooserValue(t *testing.T) {
	cfg, err := pgx.ParseConfig("host=127.0.0.1 port=5432 user=u dbname=d sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxProtocolMessageBodyLen = 1 << 30 // pgx's own default ceiling, or something looser
	Apply(cfg)
	if cfg.MaxProtocolMessageBodyLen != MaxProtocolMessageBodyLen {
		t.Fatalf("Apply left MaxProtocolMessageBodyLen=%d, want %d", cfg.MaxProtocolMessageBodyLen, MaxProtocolMessageBodyLen)
	}
	if MaxProtocolMessageBodyLen <= 0 || MaxProtocolMessageBodyLen >= 1<<30 {
		t.Fatalf("bound %d must be positive and tighter than pgx's ~1 GiB default", MaxProtocolMessageBodyLen)
	}
	// The fuzz alloc ceilings for the length-prefixed pgx targets are derived from
	// this constant (INV-RES-bounded-absolute-from-product-cap), so raising it
	// loosens that oracle in step. Make that a deliberate edit of this test.
	if MaxProtocolMessageBodyLen > 1<<20 {
		t.Fatalf("bound %d > 1 MiB: also the per-connection allocation a rogue server can force and the pgx fuzz ceiling; raise only deliberately", MaxProtocolMessageBodyLen)
	}
}
