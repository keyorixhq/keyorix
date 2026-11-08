package notary

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

// TestReceiptBitFlip runs the verifierflip mutation set (every bit, truncate,
// extend, reorder, insert/delete) against VerifyReceipt with a real, valid
// RFC 3161 token chained to a configured root. Canon is nil on purpose: DER is
// canonical, so ANY accepted mutation is reported as ACCEPT-DIFFERENT and must
// be examined by hand. See internal/verifierflip/PREREG.md.
func TestReceiptBitFlip(t *testing.T) {
	pki := buildCertPKI(t)
	roots := x509.NewCertPool()
	roots.AddCert(pki.rootR)
	legit := buildScenarios(t, pki)[0]
	require.Equal(t, "legit-chain", legit.name)
	verify := func(b []byte) bool {
		_, err := VerifyReceipt(roots, certChainMessage, b)
		return err == nil
	}
	require.True(t, verify(legit.token), "positive control: legit receipt must verify")

	if p := os.Getenv("RECEIPT_DUMP"); p != "" {
		_ = os.WriteFile(p, legit.token, 0o600)
	}
	tg := verifierflip.Target{Name: "rfc3161-verify-receipt", Artifact: legit.token, Verify: verify,
		Region: func(off int) string { return fmt.Sprintf("off%04d", off) }}
	o := verifierflip.DefaultOptions(1)
	o.SkipTiming = true
	rep, err := verifierflip.Run(tg, o)
	require.NoError(t, err)
	t.Logf("%s mutations=%d reject=%d equiv=%d DIFFERENT=%d PANIC=%d", rep.Target, rep.Mutations, rep.Rejects, rep.Equivalent, rep.Different, rep.Panics)

	require.Zero(t, rep.Panics)

	// Expected-equivalent class (classified, 3 identical runs): CMS framing
	// fields that the signature does not cover and the verifier does not
	// cross-check: SignedData.version (25), digestAlgorithms OID (<=40),
	// eContentType OID and the eContent OCTET STRING header (<=62), and
	// SignerInfo.version. The TSTInfo (time, message imprint) stays signed, so
	// none of these changes the verified time or the message binding. Anything
	// ACCEPT-DIFFERENT outside this set fails the test, including mutations
	// with no byte offset (truncate, extend, reorder, duplicate).
	siv := bytes.LastIndex(legit.token, []byte{0x02, 0x01, 0x01, 0x30, 0x25})
	require.Greater(t, siv, 100, "could not locate SignerInfo.version")
	require.Empty(t, receiptViolations(rep, siv))

	// Planted defects, judged by the same check as the real verifier.
	region := func(off int) string { return fmt.Sprintf("off%04d", off) }
	n := len(legit.token)
	plants := []struct {
		name         string
		verify       func([]byte) bool
		wantNoOffset bool
	}{
		{"ignores-last-byte", func(b []byte) bool {
			return len(b) > 0 && verify(append(bytes.Clone(b[:len(b)-1]), legit.token[n-1]))
		}, false},
		{"ignores-trailing-bytes", func(b []byte) bool {
			return len(b) >= n && verify(b[:n])
		}, true},
	}
	for _, p := range plants {
		planted := verifierflip.Target{Name: "planted-" + p.name, Artifact: legit.token, Verify: p.verify, Region: region}
		brep, err := verifierflip.Run(planted, o)
		require.NoError(t, err)
		got := receiptViolations(brep, siv)
		require.NotEmpty(t, got, "planted defect %s not detected", p.name)
		if p.wantNoOffset {
			require.True(t, slices.ContainsFunc(got, func(v string) bool { return strings.Contains(v, noOffsetViolation) }),
				"planted defect %s not reported as a no-offset accept: %v", p.name, got)
		}
	}
}

const noOffsetViolation = "no byte offset"

// receiptViolations lists the ACCEPT-DIFFERENT results outside the framing
// allowlist documented in TestReceiptBitFlip. A key that does not parse has
// no byte offset to allow, so it is always a violation.
func receiptViolations(rep *verifierflip.Report, siv int) []string {
	var bad []string
	for k, n := range rep.ByRegion {
		if !strings.HasPrefix(k, verifierflip.AcceptDifferent+"/") {
			continue
		}
		var off int
		if _, err := fmt.Sscanf(k, verifierflip.AcceptDifferent+"/off%d", &off); err != nil {
			bad = append(bad, fmt.Sprintf("%s x%d: %s", k, n, noOffsetViolation))
			continue
		}
		if off > 62 && (off < siv || off > siv+3) {
			bad = append(bad, fmt.Sprintf("offset %d x%d outside framing allowlist", off, n))
		}
	}
	slices.Sort(bad)
	return bad
}
