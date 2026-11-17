package certdiff

import (
	"context"
	"strings"
	"testing"
)

// FuzzCertChainDifferential drives the crypto/x509-vs-openssl trust oracle. The
// fuzzer's bytes are decoded into Frankencert mutation knobs; the same generated
// chain is handed to both verifiers; any accept/reject disagreement that the
// documented-differences table does not explain is reported.
//
// A divergence is NOT written into a committed crasher under testdata/: for a
// third-party (openssl) finding the reproducer bytes stay private
// (.scratch/findings/, per scripts/fuzzing/DISCLOSURE-TRIAGE.md). The failure
// message prints the decoded knobs, which are enough to reconstruct the case
// without publishing raw bytes.
func FuzzCertChainDifferential(f *testing.F) {
	c, err := NewComparator()
	if err != nil {
		f.Skipf("openssl unavailable: %v", err)
	}

	// Seeds: each byte position is a knob (see decodeKnobs).
	seeds := [][]byte{
		{},                             // plain chain
		{1},                            // one intermediate
		{2},                            // two intermediates
		{0, 0, 0, 1},                   // expired leaf
		{0, 0, 0, 0, 1},                // future leaf
		{1, 1},                         // non-CA intermediate
		{1, 0, 0, 0, 0, 1},             // forged signature
		{2, 0, 1},                      // pathlen:0
		{0, 0, 0, 0, 0, 0, 1},          // unknown critical ext
		{1, 0, 0, 0, 0, 0, 0, 1, 1},    // name-constraint mismatch
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // non-critical basic constraints
		{2, 1, 1, 1, 0, 0, 1, 1, 1, 1}, // everything on
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		k := decodeKnobs(data)
		ch, err := buildChain(k)
		if err != nil {
			return // an impossible template is a skip, never a divergence
		}
		diverged, d := c.Compare(context.Background(), ch)
		if !diverged {
			return
		}
		// Guard against an openssl INFRASTRUCTURE error masquerading as a reject
		// (binary vanished, could not spawn) — that is not a trust divergence.
		if _, oerr := (opensslVerify{bin: "openssl"}).Run(context.Background(), ch); oerr != nil &&
			strings.Contains(oerr.Error(), "exec error") {
			return
		}
		t.Errorf("CERT TRUST DIVERGENCE knobs=%+v\n%v", k, d)
	})
}
