package crypto

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzCombineKEK fuzzes the Shamir share-parsing/reconstruction boundary — the
// most security-critical parser in the codebase, since it turns untrusted-shape
// input (an operator-configured share file or env var, see ShamirKeyProvider.KEK)
// into the master KEK. decodeShare is the actual byte-payload parser (raw / hex /
// base64), and combineKEK is where a bad reconstruction must fail closed (#429).
//
// This does not just fuzz for crashes: it also asserts the #429 security
// invariant survives arbitrary fuzzed input — combineKEK must never return a
// "success" whose reconstructed KEK fails the HMAC commitment check when a
// commitment is configured (mirroring TestShamir_ForgedShare_FoolsMagicOnlyCheck_
// ButCommitmentCatchesIt / TestShamir_CombineKEK_CommitmentRoundTrip in
// shamir_test.go, which construct the same genuine-shares + commitment setup by
// hand for a fixed table of forged inputs instead of a fuzzed input space).
func FuzzCombineKEK(f *testing.F) {
	kek := testKEK()
	threshold := 3
	shares, err := SplitKEK(kek, 5, threshold)
	require.NoError(f, err)
	commitment := CommitKEK(kek)

	// The attacker/fuzzer is modeled as controlling ONE of the threshold-many
	// share sources; genuine holds the other threshold-1 real shares (mirrors
	// TestShamirKeyProvider_ForgedShareRejectedWithCommitment's setup).
	genuine := append([][]byte{}, shares[:threshold-1]...)

	// --- Seed corpus, harvested from shamir_provider_test.go / shamir_test.go ---
	f.Add([]byte{})              // empty payload
	f.Add([]byte("a"))           // too short (1 byte) to even be a share
	f.Add([]byte("!"))           // garbage share (TestShamirKeyProvider_Errors)
	f.Add([]byte(kekShareMagic)) // legacy magic-only format, no threshold/KEK bytes

	// A genuinely valid share (raw bytes) for the SAME split/KEK — completing the
	// threshold, this must actually succeed and match the commitment.
	f.Add(append([]byte{}, shares[threshold-1]...))
	// The same genuine share, but as hex/base64 TEXT — decodeShare must transparently
	// decode either encoding, exactly as a share file/env var may contain.
	f.Add([]byte(hex.EncodeToString(shares[threshold-1])))
	f.Add([]byte(base64.StdEncoding.EncodeToString(shares[threshold-1])))

	// A duplicate of an already-genuine share (same x-coordinate) — Combine must
	// reject this as a duplicate rather than silently accepting it.
	f.Add(append([]byte{}, genuine[0]...))

	// A share from Split (not SplitKEK) — unframed, wrong length relative to the
	// framed shares (TestShamirKeyProvider_UnframedSharesRejected).
	unframedShares, uerr := Split(kek, 3, 2)
	require.NoError(f, uerr)
	f.Add(append([]byte{}, unframedShares[0]...))

	// A valid share for a DIFFERENT KEK (correct length/framing, wrong content) —
	// must reconstruct to something that does not satisfy this commitment.
	otherKEK := make([]byte, KEKSize)
	for i := range otherKEK {
		otherKEK[i] = byte(255 - i)
	}
	otherShares, oerr := SplitKEK(otherKEK, 5, threshold)
	require.NoError(f, oerr)
	f.Add(append([]byte{}, otherShares[threshold-1]...))

	// A forged share (#429 construction): an attacker holding threshold-1 genuine
	// shares picks an arbitrary x-coordinate and solves for the y-values that make
	// the WHOLE payload (magic, threshold, and a chosen fake KEK) interpolate
	// exactly — the exact attack combineKEK's commitment check must catch.
	fakeKEK := make([]byte, KEKSize)
	for i := range fakeKEK {
		fakeKEK[i] = 0x77
	}
	targetPayload := append(append([]byte{}, kekShareMagic...), byte(threshold))
	targetPayload = append(targetPayload, fakeKEK...)
	forged := forgeShare(genuine, 210, targetPayload)
	f.Add(append([]byte{}, forged...))

	f.Fuzz(func(t *testing.T, data []byte) {
		thirdShare, derr := decodeShare(data)
		if derr != nil {
			// Too short to be any kind of share (decodeShare's only failure mode) —
			// nothing meaningful to combine, and decodeShare itself must not panic
			// getting here, which the fuzz harness already enforces.
			return
		}
		attackerShares := append(append([][]byte{}, genuine...), thirdShare)
		kek, cerr := combineKEK(attackerShares, commitment)
		if cerr != nil {
			return
		}
		if !hmac.Equal(CommitKEK(kek), commitment) {
			t.Fatalf("combineKEK returned success (no error) for a reconstructed KEK that fails its own HMAC commitment check — commitment bypass; data=%x kek=%x", data, kek)
		}
	})
}
