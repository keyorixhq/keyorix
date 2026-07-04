package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamir_RoundTrip_AnyThresholdSubset(t *testing.T) {
	secret := testKEK() // 32 bytes
	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)
	require.Len(t, shares, 5)
	for _, s := range shares {
		require.Len(t, s, len(secret)+1)
	}

	// Any 3 of the 5 shares reconstruct the secret; exhaustively check several subsets.
	subsets := [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {2, 3, 4}, {0, 1, 4}}
	for _, idx := range subsets {
		sub := [][]byte{shares[idx[0]], shares[idx[1]], shares[idx[2]]}
		got, err := Combine(sub)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(secret, got), "subset %v must reconstruct", idx)
	}

	// More than threshold also works.
	got, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestShamir_BelowThresholdDoesNotReveal(t *testing.T) {
	secret := testKEK()
	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)

	// 2 shares (< threshold 3) combine to a well-formed but WRONG secret — it must
	// not equal the real one (that is the secrecy guarantee). Combine still succeeds
	// structurally, so callers must validate (e.g. KEK round-trips the DEK).
	wrong, err := Combine([][]byte{shares[0], shares[1]})
	require.NoError(t, err)
	assert.False(t, bytes.Equal(secret, wrong), "2 of 3 shares must not reconstruct the secret")
}

func TestShamir_2of2(t *testing.T) {
	secret := []byte("a-shorter-secret")
	shares, err := Split(secret, 2, 2)
	require.NoError(t, err)
	got, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestShamir_SplitValidation(t *testing.T) {
	_, err := Split(nil, 5, 3)
	require.Error(t, err)
	_, err = Split([]byte("x"), 5, 1) // threshold < 2
	require.Error(t, err)
	_, err = Split([]byte("x"), 2, 3) // parts < threshold
	require.Error(t, err)
	_, err = Split([]byte("x"), 256, 2) // parts > 255
	require.Error(t, err)
}

func TestShamir_CombineValidation(t *testing.T) {
	secret := testKEK()
	shares, err := Split(secret, 3, 2)
	require.NoError(t, err)

	t.Run("too few shares", func(t *testing.T) {
		_, err := Combine([][]byte{shares[0]})
		require.Error(t, err)
	})
	t.Run("mismatched lengths", func(t *testing.T) {
		_, err := Combine([][]byte{shares[0], append([]byte{0x1}, shares[1]...)})
		require.Error(t, err)
	})
	t.Run("duplicate x-coordinate", func(t *testing.T) {
		_, err := Combine([][]byte{shares[0], shares[0]})
		require.Error(t, err)
	})
}

// TestGF_FieldAxioms spot-checks the GF(2^8) arithmetic the split/combine relies on.
func TestGF_FieldAxioms(t *testing.T) {
	// Multiplicative identity and inverse for every non-zero element.
	for a := 1; a < 256; a++ {
		x := byte(a)
		assert.Equal(t, x, gfMul(x, 1), "1 is the identity")
		assert.Equal(t, byte(1), gfMul(x, gfInv(x)), "a * a^-1 == 1 for a=%d", a)
	}
}

// --- #429 forgery reproduction -------------------------------------------------
//
// lagrangeCoeffAtZero and forgeShare implement the SAME backward-Lagrange-
// interpolation forgery an attacker uses when they hold threshold-1 genuine Shamir
// shares: pick an arbitrary x-coordinate for a "share" they don't actually have, then
// solve — independently, one secret byte at a time — for the unique y-value that
// makes the full set (their real shares + this forged one) interpolate to ANY chosen
// target byte at x=0. Because every byte of the split payload (magic, threshold, and
// the KEK itself) is reconstructed via an independent polynomial evaluated at the
// same x-coordinates, this lets the forger dictate the ENTIRE reconstructed payload,
// magic bytes included — proving the magic-byte check alone is not a real
// cryptographic integrity check (see combineKEK's doc comment).

// lagrangeCoeffAtZero returns L_i(0), the Lagrange basis coefficient by which ys[i]
// is weighted in interpolateAtZero(xs, ys) — i.e. the same product xs[j]/(xs[i]^xs[j])
// interpolateAtZero computes internally, exposed here so a forger (and this test)
// can solve for an unknown y rather than only evaluate with known ones.
func lagrangeCoeffAtZero(xs []byte, i int) byte {
	num := byte(1)
	den := byte(1)
	for j := range xs {
		if i == j {
			continue
		}
		num = gfMul(num, xs[j])
		den = gfMul(den, xs[i]^xs[j])
	}
	return gfMul(num, gfInv(den))
}

// forgeShare builds a single additional Shamir share at x-coordinate forgedX that,
// combined with knownShares (typically threshold-1 genuine shares), reconstructs
// EXACTLY targetPayload. This is the forgery construction #429 documents: for each
// byte position, targetPayload's byte = (sum of known shares' Lagrange
// contributions) XOR (forged share's Lagrange coefficient * forged y-byte); solving
// for the forged y-byte is a single GF(2^8) division.
func forgeShare(knownShares [][]byte, forgedX byte, targetPayload []byte) []byte {
	n := len(knownShares)
	xs := make([]byte, n+1)
	for i, s := range knownShares {
		xs[i] = s[len(s)-1]
	}
	xs[n] = forgedX

	forged := make([]byte, len(targetPayload)+1)
	forged[len(targetPayload)] = forgedX
	forgedCoeff := lagrangeCoeffAtZero(xs, n)
	for bi := range targetPayload {
		var knownSum byte
		for i, s := range knownShares {
			knownSum ^= gfMul(lagrangeCoeffAtZero(xs, i), s[bi])
		}
		// target = knownSum XOR forgedCoeff*y  =>  y = forgedCoeff^-1 * (target XOR knownSum)
		forged[bi] = gfMul(gfInv(forgedCoeff), targetPayload[bi]^knownSum)
	}
	return forged
}

// TestShamir_ForgedShare_ReconstructsExactAttackerChosenPayload proves the forgery
// construction itself works, independent of combineKEK: an attacker with
// threshold-1 genuine shares picks the ENTIRE reconstructed payload, including bytes
// that aren't theirs to choose (the magic and threshold framing), not just the KEK.
func TestShamir_ForgedShare_ReconstructsExactAttackerChosenPayload(t *testing.T) {
	kek := testKEK()
	threshold := 3
	shares, err := SplitKEK(kek, 5, threshold)
	require.NoError(t, err)

	// Attacker holds only 2 (threshold-1) genuine shares.
	genuine := [][]byte{shares[0], shares[1]}

	fakeKEK := bytes.Repeat([]byte{0x41}, KEKSize)
	targetPayload := append(append([]byte{}, kekShareMagic...), byte(threshold))
	targetPayload = append(targetPayload, fakeKEK...)

	forged := forgeShare(genuine, 250, targetPayload)
	attackerShares := append(append([][]byte{}, genuine...), forged)

	got, err := Combine(attackerShares)
	require.NoError(t, err)
	assert.Equal(t, targetPayload, got, "forged share must make Combine reconstruct the attacker's exact chosen payload, magic bytes included")
	assert.NotEqual(t, kek, got[len(kekShareMagic)+1:], "the forged reconstruction is NOT the real KEK")
}

// TestShamir_ForgedShare_FoolsMagicOnlyCheck_ButCommitmentCatchesIt is the core #429
// regression test: it reproduces the empirically-verified forgery attack end to end
// through combineKEK and shows (a) the pre-fix magic-only path is fooled into
// accepting an attacker-chosen KEK, and (b) with a real KEK commitment configured
// (computed at split time from the true KEK, stored outside the shares), the exact
// same forged shares are now REJECTED.
func TestShamir_ForgedShare_FoolsMagicOnlyCheck_ButCommitmentCatchesIt(t *testing.T) {
	kek := testKEK()
	threshold := 3
	shares, err := SplitKEK(kek, 5, threshold)
	require.NoError(t, err)
	commitment := CommitKEK(kek) // computed once, at split time, from the REAL KEK

	genuine := [][]byte{shares[0], shares[1]} // threshold-1 genuine shares
	fakeKEK := bytes.Repeat([]byte{0x99}, KEKSize)
	require.NotEqual(t, kek, fakeKEK)
	targetPayload := append(append([]byte{}, kekShareMagic...), byte(threshold))
	targetPayload = append(targetPayload, fakeKEK...)
	forged := forgeShare(genuine, 200, targetPayload)
	attackerShares := append(append([][]byte{}, genuine...), forged)

	// (a) VULNERABILITY: no commitment configured (legacy behavior / pre-existing key
	// material) — the 4-byte magic + threshold framing is the only check, and the
	// forged share was built to satisfy it exactly, so this "succeeds" with the
	// attacker's chosen KEK rather than the real one.
	legacyKEK, err := combineKEK(attackerShares, nil)
	require.NoError(t, err, "demonstrates the vulnerability: magic-only verification accepts a forged reconstruction")
	assert.Equal(t, fakeKEK, legacyKEK, "the accepted KEK is the attacker's chosen value, not the real KEK")

	// (b) FIX: the real commitment (over the true KEK, stored outside the Shamir
	// shares) is supplied — reconstruction from the SAME forged shares must now be
	// rejected instead of silently returning the attacker's chosen KEK.
	_, err = combineKEK(attackerShares, commitment)
	require.Error(t, err, "forged share reconstructing an attacker-chosen KEK must be rejected once a real commitment is verified")
}

// TestShamir_CombineKEK_CommitmentRoundTrip proves genuine (non-forged) reconstruction
// still succeeds and matches the original KEK once a commitment is configured, and
// that a corrupted/mismatched commitment is itself rejected (it isn't merely
// computed-and-ignored).
func TestShamir_CombineKEK_CommitmentRoundTrip(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	commitment := CommitKEK(kek)

	got, err := combineKEK(shares[:3], commitment)
	require.NoError(t, err)
	assert.Equal(t, kek, got, "genuine shares + correct commitment must still reconstruct the real KEK")

	badCommitment := append([]byte{}, commitment...)
	badCommitment[0] ^= 0xff
	_, err = combineKEK(shares[:3], badCommitment)
	require.Error(t, err, "a mismatched commitment must be rejected even for a genuine reconstruction")

	// No commitment configured at all: falls back to the legacy magic-only check
	// (backward compatibility with pre-existing key material) and still succeeds.
	got, err = combineKEK(shares[:3], nil)
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}
