package notary

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
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
	// ACCEPT-DIFFERENT outside this set fails the test.
	siv := bytes.LastIndex(legit.token, []byte{0x02, 0x01, 0x01, 0x30, 0x25})
	require.Greater(t, siv, 100, "could not locate SignerInfo.version")
	bad := 0
	for k, n := range rep.ByRegion {
		var off int
		if _, err := fmt.Sscanf(k, "ACCEPT-DIFFERENT/off%d", &off); err != nil {
			continue
		}
		if off <= 62 || (off >= siv && off <= siv+3) {
			t.Logf("expected-equivalent framing field: offset %d x%d", off, n)
			continue
		}
		bad += n
		t.Errorf("ACCEPT-DIFFERENT outside framing allowlist: offset %d x%d", off, n)
	}
	require.Zero(t, bad)

	// Planted defect: a verifier that ignores the last byte must be caught.
	planted := verifierflip.Target{Name: "planted-ignore-last", Artifact: legit.token,
		Verify: func(b []byte) bool {
			if len(b) == 0 {
				return false
			}
			return verify(append(append([]byte(nil), b[:len(b)-1]...), legit.token[len(legit.token)-1]))
		}}
	brep, err := verifierflip.Run(planted, o)
	require.NoError(t, err)
	require.NotZero(t, brep.Different, "planted defect not detected")
}
