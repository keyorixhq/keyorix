// Two targets PROMOTED from the M10 SAST-guided loop
// (scripts/fuzzing/autofuzzgen + .github/codeql/manual-queries/FuzzHarnessTargets.ql,
// #1925's infrastructure, run end to end for the first time — see the fuzz-harness
// track report for the full alert->harness->reached?->result table this run
// produced). Both are "parser" sink-kind leads: static data-flow found a
// RemoteFlowSource reaching these functions' arguments; both are pure,
// standalone, no storage/DB dependency, making them tractable to promote
// immediately rather than left as skeletons.
package core

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseLeafCertificate — PROMOTED from autotarget_parser_parseLeafCertificate.txt
// (sink: internal/core/certificate.go:187). BOUNDED-WORK + NEVER-PANIC: parseLeafCertificate
// itself documents its own bound (maxCertBlocks=64 pem.Decode/x509.ParseCertificate attempts,
// gated on ATTEMPTS not on blocks successfully parsed, specifically so a value that is mostly
// non-CERTIFICATE or unparseable blocks can't turn the loop unbounded). Assert only the
// bounded/never-panic direction, never "must parse."
func FuzzParseLeafCertificate(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, value []byte) {
		fuzzutil.Guard(t.Fatalf, "core.parseLeafCertificate", func() {
			_, _ = parseLeafCertificate(value)
		})
	})
}

// FuzzParseDSNHostFromURL — PROMOTED from autotarget_parser_parseDSNHostFromURL.txt
// (sink: internal/core/dynamic_secrets.go:106). NEVER-PANIC: a thin wrapper over
// net/url.Parse + net.SplitHostPort, both already hardened stdlib parsers with no
// internal loop/recursion of their own — the invariant worth stating explicitly is
// that composing them here introduces no NEW panic surface, not a claim about the
// stdlib functions themselves.
func FuzzParseDSNHostFromURL(f *testing.F) {
	f.Add("")
	f.Add("postgres://user:pass@host:5432/db")
	f.Add("mysql://user@[::1]:3306/db")
	f.Fuzz(func(t *testing.T, dsn string) {
		fuzzutil.Guard(t.Fatalf, "core.parseDSNHostFromURL", func() {
			_, _ = parseDSNHostFromURL(dsn)
		})
	})
}
