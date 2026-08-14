package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirKeyProvider_Name(t *testing.T) {
	assert.Equal(t, "shamir", NewShamirKeyProvider(nil, nil, "").Name())
}

func TestShamirKeyProvider_CombinesSharesFromFilesAndEnv(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK() // 32 bytes
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)

	// Two shares as hex files, one as a base64 env var → threshold 3 reached.
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])+"\n"), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))
	t.Setenv("KX_SHARE_3", base64.StdEncoding.EncodeToString(shares[2]))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	got, err := NewShamirKeyProvider([]string{f1, f2}, []string{"KX_SHARE_3"}, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

func TestShamirKeyProvider_TooFewSharesFailsClosed(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))

	// Only one share configured — below the minimum, rejected outright.
	_, err = NewShamirKeyProvider([]string{f1}, nil, "").KEK()
	require.Error(t, err)
}

// TestShamirKeyProvider_SubThresholdRejected is the core fail-closed guarantee:
// supplying fewer than the split's threshold (but >= 2) must be REJECTED rather
// than silently reconstructing a wrong KEK — even though Combine itself would
// happily return a 32-byte value. The framing magic + embedded threshold catch it.
func TestShamirKeyProvider_SubThresholdRejected(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3) // threshold 3
	require.NoError(t, err)
	// Supply only 2 of the 3 required shares.
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	_, err = NewShamirKeyProvider([]string{f1, f2}, nil, commitmentHex).KEK()
	require.Error(t, err, "below-threshold shares must fail closed, not reconstruct a wrong KEK")
}

func TestShamirKeyProvider_UnframedSharesRejected(t *testing.T) {
	dir := t.TempDir()
	// Raw Split (not SplitKEK) produces shares without the KEK framing — the provider
	// must reject them rather than accept an unverified reconstruction.
	kek := testKEK()
	shares, err := Split(kek, 3, 2)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	// A commitment is required now; even with a valid commitment the unframed shares
	// must be rejected by combineKEK's magic-byte check.
	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	_, err = NewShamirKeyProvider([]string{f1, f2}, nil, commitmentHex).KEK()
	require.Error(t, err, "shares without the KEK framing must be rejected")
}

func TestShamirKeyProvider_Errors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := NewShamirKeyProvider([]string{filepath.Join(t.TempDir(), "nope")}, nil, "").KEK()
		require.Error(t, err)
	})
	t.Run("unset env", func(t *testing.T) {
		_, err := NewShamirKeyProvider(nil, []string{"KX_SHARE_DOES_NOT_EXIST"}, "").KEK()
		require.Error(t, err)
	})
	t.Run("garbage share", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "g")
		require.NoError(t, os.WriteFile(f, []byte("!"), 0600))
		_, err := NewShamirKeyProvider([]string{f}, []string{}, "").KEK()
		require.Error(t, err)
	})
}

// TestShamirKeyProvider_ForgedShareRejectedWithCommitment is the #429 regression
// test at the ShamirKeyProvider level (the real code path an operator's configured
// shamir_share_files hit), mirroring the file-based custodian setup an attacker
// would actually exploit: they hold threshold-1 genuine share FILES and can
// write/replace the one remaining configured share source with a forged share.
func TestShamirKeyProvider_ForgedShareRejectedWithCommitment(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	threshold := 3
	shares, err := SplitKEK(kek, 5, threshold)
	require.NoError(t, err)
	commitmentHex := hex.EncodeToString(CommitKEK(kek))

	genuine := shares[:2] // attacker holds threshold-1 genuine shares
	fakeKEK := bytes.Repeat([]byte{0x77}, KEKSize)
	targetPayload := append(append([]byte{}, kekShareMagic...), byte(threshold))
	targetPayload = append(targetPayload, fakeKEK...)
	forged := forgeShare(genuine, 210, targetPayload)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	f3 := filepath.Join(dir, "s3-forged") // the attacker-replaced share source
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(genuine[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(genuine[1])), 0600))
	require.NoError(t, os.WriteFile(f3, []byte(hex.EncodeToString(forged)), 0600))

	// With shamir_commitment configured: the forged share is rejected instead of
	// silently returning the attacker-chosen KEK.
	_, err = NewShamirKeyProvider([]string{f1, f2, f3}, nil, commitmentHex).KEK()
	require.Error(t, err, "forged share must be rejected once shamir_commitment is configured")
}

// TestShamirKeyProvider_NoCommitmentConfiguredDoesNotExit is #G61: KEK() used to
// log.Fatalf (os.Exit) when shamir_commitment was unset, unlike every other
// KeyProvider implementation, which returns an error. This proves the process
// survives — reconstruction proceeds with the weaker magic-byte-only check
// (#429) instead of killing the whole server. If this test were run against
// the pre-fix code, the log.Fatalf would tear down the test binary itself
// (not just fail this test), which is exactly the bug.
func TestShamirKeyProvider_NoCommitmentConfiguredDoesNotExit(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	f3 := filepath.Join(dir, "s3")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))
	require.NoError(t, os.WriteFile(f3, []byte(hex.EncodeToString(shares[2])), 0600))

	got, err := NewShamirKeyProvider([]string{f1, f2, f3}, nil, "").KEK()
	require.NoError(t, err, "no shamir_commitment configured must reduce verification strength, not kill the process")
	assert.Equal(t, kek, got)
}

// TestMultiKeyProvider_FallsBackWhenShamirKEKErrors is #G61's fallback half:
// a ShamirKeyProvider that returns an error (too few shares, here) must let
// MultiKeyProvider move on to the next configured provider — the whole reason
// KEK() must return an error instead of calling log.Fatalf, which would have
// killed the process before MultiKeyProvider ever got a chance to fall back.
func TestMultiKeyProvider_FallsBackWhenShamirKEKErrors(t *testing.T) {
	failingShamir := NewShamirKeyProvider(nil, nil, "") // 0 shares < threshold 2 → KEK() errors
	kek := testKEK()
	kekPath := filepath.Join(t.TempDir(), "kek.bin")
	require.NoError(t, os.WriteFile(kekPath, kek, 0600))
	fallback := NewFileKeyProvider(kekPath)

	m, err := NewMultiKeyProvider([]KeyProvider{failingShamir, fallback})
	require.NoError(t, err)

	got, err := m.KEK()
	require.NoError(t, err, "MultiKeyProvider must fall back to the next provider when shamir errors")
	assert.Equal(t, kek, got)
}
