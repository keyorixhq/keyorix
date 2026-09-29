package certparse

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseLeafCertificate — PROMOTED from autotarget_parser_parseLeafCertificate.txt
// (sink: internal/core/certificate.go, before this Session M move; now
// internal/core/certs/certs.go). BOUNDED-WORK + NEVER-PANIC: ParseLeafCertificate
// itself documents its own bound (maxCertBlocks=64 pem.Decode/x509.ParseCertificate
// attempts, gated on ATTEMPTS not on blocks successfully parsed, specifically so a
// value that is mostly non-CERTIFICATE or unparseable blocks can't turn the loop
// unbounded). Assert only the bounded/never-panic direction, never "must parse."
func FuzzParseLeafCertificate(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, value []byte) {
		fuzzutil.Guard(t.Fatalf, "certs.ParseLeafCertificate", func() {
			_, _ = ParseLeafCertificate(value)
		})
	})
}
