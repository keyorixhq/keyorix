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
