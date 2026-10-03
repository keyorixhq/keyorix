package crypto

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestShamir_ThresholdExhaustive guards INV-ENCRYPTION-26 (ADR-038 K-of-N KEK
// custody) over every subset, not a hand-picked few:
//
//   - every K-subset of the N shares reconstructs the secret, in more than one
//     share order;
//   - every (K-1)-subset fails to reconstruct it: Combine either refuses (fewer
//     than 2 shares) or returns a value that is not the secret.
//
// The (K-1) half is probabilistic by construction: K-1 shares of a random
// degree-(K-1) polynomial interpolate to a uniformly random byte per secret
// byte, so a 32-byte secret is matched by chance with probability 2^-256 per
// subset. A deterministic match means the polynomial degree or its randomness
// is broken (for example, coefficients left zero, or degree K-2), which is
// exactly what this test is meant to catch.
//
// What this does not check: the information-theoretic secrecy of K-1 shares
// (that they are independent of the secret). It checks only that they do not
// reconstruct it.
func TestShamir_ThresholdExhaustive(t *testing.T) {
	cases := []struct{ n, k int }{
		{2, 2}, {3, 2}, {3, 3}, {4, 2}, {4, 3}, {5, 3}, {5, 5}, {6, 4}, {7, 4},
	}
	secret := testKEK()

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d-of-%d", tc.k, tc.n), func(t *testing.T) {
			shares, err := Split(secret, tc.n, tc.k)
			require.NoError(t, err)
			require.Len(t, shares, tc.n)

			for _, idx := range combinations(tc.n, tc.k) {
				sub := pick(shares, idx)
				got, err := Combine(sub)
				require.NoError(t, err, "K-subset %v", idx)
				require.True(t, bytes.Equal(secret, got), "K-subset %v must reconstruct the secret", idx)

				reversed := make([][]byte, len(sub))
				for i := range sub {
					reversed[len(sub)-1-i] = sub[i]
				}
				got, err = Combine(reversed)
				require.NoError(t, err, "reversed K-subset %v", idx)
				require.True(t, bytes.Equal(secret, got), "reversed K-subset %v must reconstruct the secret", idx)
			}

			for _, idx := range combinations(tc.n, tc.k-1) {
				got, err := Combine(pick(shares, idx))
				if err != nil {
					continue // fewer than 2 shares: refused outright, cannot reconstruct
				}
				require.False(t, bytes.Equal(secret, got), "(K-1)-subset %v must NOT reconstruct the secret", idx)
			}
		})
	}
}

// combinations returns every size-k subset of {0..n-1} as ascending index slices.
func combinations(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return out
}

func pick(shares [][]byte, idx []int) [][]byte {
	out := make([][]byte, len(idx))
	for i, j := range idx {
		out[i] = shares[j]
	}
	return out
}
