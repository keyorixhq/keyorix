package dsn

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseDSNHostFromURL — PROMOTED from autotarget_parser_parseDSNHostFromURL.txt
// (sink: internal/core/dynamic_secrets.go, before this Session M move; now
// internal/core/dsn/dsn.go). NEVER-PANIC: a thin wrapper over net/url.Parse +
// net.SplitHostPort, both already hardened stdlib parsers with no internal
// loop/recursion of their own — the invariant worth stating explicitly is that
// composing them here introduces no NEW panic surface, not a claim about the
// stdlib functions themselves.
//
// #2197 (SSRF guard differential) renamed the target to ParseDSNHostsFromURL
// (multi-host DSNs, plus a manual-authority fallback when url.Parse fails), so
// this now fuzzes that function, which has more hand-written parsing than the
// original and makes a better target. The Fuzz name is kept so targets.conf and any
// saved corpus stay valid.
func FuzzParseDSNHostFromURL(f *testing.F) {
	f.Add("")
	f.Add("postgres://user:pass@host:5432/db")
	f.Add("mysql://user@[::1]:3306/db")
	f.Fuzz(func(t *testing.T, dsn string) {
		fuzzutil.Guard(t.Fatalf, "dsn.ParseDSNHostsFromURL", func() {
			_, _ = ParseDSNHostsFromURL(dsn)
		})
	})
}
