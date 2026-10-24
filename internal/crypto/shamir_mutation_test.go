package crypto

// Tests added for the gremlins survivors in shamir.go / shamir_provider.go
// (#3412 -> #3612, MUTANT-CRYPTO-1): boundaries asserted exactly.

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shamir.go:77 — parts is capped at 255 (x-coordinates are single non-zero
// bytes): 255 is the last accepted value, 256 the first refused.
func TestSplit_PartsBoundary(t *testing.T) {
	secret := []byte{0x42}

	shares, err := Split(secret, 255, 2)
	require.NoError(t, err)
	require.Len(t, shares, 255)
	assert.Equal(t, byte(255), shares[254][1], "the 255th share's x-coordinate is 255")

	_, err = Split(secret, 256, 2)
	require.ErrorContains(t, err, "parts must be <= 255")
}

func TestSplit_ThresholdAndPartsLowerBounds(t *testing.T) {
	secret := []byte{0x42}

	_, err := Split(secret, 3, 1)
	require.ErrorContains(t, err, "threshold must be at least 2")
	_, err = Split(secret, 3, 0)
	require.ErrorContains(t, err, "threshold must be at least 2")

	_, err = Split(secret, 2, 3)
	require.ErrorContains(t, err, "parts (2) must be >= threshold (3)")
	shares, err := Split(secret, 3, 3)
	require.NoError(t, err, "parts == threshold is the minimum valid split")
	assert.Len(t, shares, 3)

	_, err = Split(nil, 3, 2)
	require.ErrorContains(t, err, "empty secret")
}

// shamir_provider.go:73 — the framed threshold is one byte, so 255 is the last
// accepted threshold and 256 the first refused; 2 is the first accepted.
func TestSplitKEK_ThresholdBoundary(t *testing.T) {
	kek := testKEK()

	for _, th := range []int{0, 1} {
		_, err := SplitKEK(kek, 5, th)
		require.ErrorContains(t, err, "threshold must be between 2 and 255", "threshold %d", th)
	}
	_, err := SplitKEK(kek, 256, 256)
	require.ErrorContains(t, err, "threshold must be between 2 and 255")

	shares, err := SplitKEK(kek, 2, 2)
	require.NoError(t, err)
	assert.Len(t, shares, 2)

	// 255-of-255: every share is needed, and all of them reconstruct the KEK.
	shares, err = SplitKEK(kek, 255, 255)
	require.NoError(t, err)
	require.Len(t, shares, 255)
	for _, s := range shares {
		require.Len(t, s, kekFrameLen+1)
	}
	got, err := combineKEK(shares, CommitKEK(kek))
	require.NoError(t, err)
	assert.Equal(t, kek, got)

	_, err = SplitKEK(kek[:KEKSize-1], 3, 2)
	require.ErrorContains(t, err, "KEK must be 32 bytes")
}

// The frame is magic ‖ threshold ‖ KEK; pinning the length pins the const
// expression `len(magic) + 1 + KEKSize` that gremlins reports as NOT COVERED
// (a const declaration has no coverage block, so it can never be "covered").
func TestKEKFrameLen(t *testing.T) {
	assert.Equal(t, 4+1+32, kekFrameLen)
	shares, err := SplitKEK(testKEK(), 3, 2)
	require.NoError(t, err)
	assert.Len(t, shares[0], 4+1+32+1, "frame plus the x-coordinate byte")
}

func writeShareFiles(t *testing.T, shares [][]byte) []string {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, len(shares))
	for i, s := range shares {
		paths[i] = filepath.Join(dir, fmt.Sprintf("share-%d", i))
		require.NoError(t, os.WriteFile(paths[i], []byte(hex.EncodeToString(s)+"\n"), 0o600))
	}
	return paths
}

// threshold-1 shares fail, threshold shares (any subset) succeed — through the
// real provider, with and without the stored commitment.
func TestShamirKeyProvider_ThresholdMinusOneFailsThresholdSucceeds(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	files := writeShareFiles(t, shares)
	commitment := hex.EncodeToString(CommitKEK(kek))

	for _, c := range []string{"", commitment} {
		t.Run("commitment="+fmt.Sprint(c != ""), func(t *testing.T) {
			for _, sub := range [][]string{files[:2], {files[0], files[4]}, {files[3], files[1]}} {
				got, err := NewShamirKeyProvider(sub, nil, c).KEK()
				require.Error(t, err, "2 of a 3-threshold split must fail closed")
				assert.Nil(t, got)
			}
			for _, sub := range [][]string{files[:3], files[2:], {files[4], files[0], files[2]}, files} {
				got, err := NewShamirKeyProvider(sub, nil, c).KEK()
				require.NoError(t, err)
				assert.Equal(t, kek, got)
			}
		})
	}
}

func TestShamirKeyProvider_DuplicateAndZeroShareIndexRefused(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)
	files := writeShareFiles(t, shares)

	// The same share supplied twice: distinct files, identical x-coordinate.
	_, err = NewShamirKeyProvider([]string{files[0], files[0], files[1]}, nil, "").KEK()
	require.ErrorContains(t, err, "duplicate share x-coordinate 1")

	zero := append([]byte(nil), shares[0]...)
	zero[len(zero)-1] = 0
	zeroFile := writeShareFiles(t, [][]byte{zero})[0]
	_, err = NewShamirKeyProvider([]string{zeroFile, files[1]}, nil, "").KEK()
	require.ErrorContains(t, err, "zero x-coordinate")

	_, err = NewShamirKeyProvider([]string{files[0]}, nil, "").KEK()
	require.ErrorContains(t, err, "need at least 2 shares, got 1")
}

// shamir_provider.go:240/244/248 — the minimum decodable share is exactly 2
// bytes (one data byte plus the x-coordinate), in each accepted encoding.
func TestDecodeShare_TwoByteBoundaryPerEncoding(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []byte
		err  string
	}{
		{"hex, exactly 2 bytes", "abcd", []byte{0xab, 0xcd}, ""},
		{"hex with surrounding whitespace", " abcd\n", []byte{0xab, 0xcd}, ""},
		{"hex, 1 byte is below the minimum so it is taken raw", "ab", []byte("ab"), ""},
		{"base64 std, exactly 2 bytes", "//4=", []byte{0xff, 0xfe}, ""},
		{"base64 raw (unpadded), exactly 2 bytes", "//4", []byte{0xff, 0xfe}, ""},
		{"base64 url, exactly 2 bytes", "__4=", []byte{0xff, 0xfe}, ""},
		{"raw 2 bytes", "!!", []byte("!!"), ""},
		{"raw 1 byte", "!", nil, "at least 2 bytes"},
		{"empty", "", nil, "empty share"},
		{"whitespace only", " \n", nil, "empty share"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeShare([]byte(tc.in))
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
