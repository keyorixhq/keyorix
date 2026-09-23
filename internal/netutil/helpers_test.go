package netutil

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// testTimeout bounds every netutil unit-test context (#1948): a regression
// that sends a test down an unexpected network path must fail fast, not hang
// until go test's global timeout.
const testTimeout = 5 * time.Second

// testCtx returns a context bounded by testTimeout, cancelled at test end.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// noDNS is a Resolver for tests that must never resolve a name — they dial
// or validate IP literals only. Without it a Dialer falls back to
// DefaultResolver, i.e. live DNS: a regression (e.g. in the SplitHostPort or
// literal-IP guards) would then silently hit the network — hanging, or
// breaking in air-gapped CI — instead of failing here (#1948).
func noDNS(t *testing.T) Resolver {
	return func(_ context.Context, host string) ([]net.IPAddr, error) {
		t.Errorf("unexpected DNS lookup for %q: this test must not resolve names", host)
		return nil, fmt.Errorf("netutil test: DNS disabled (lookup %q)", host)
	}
}
