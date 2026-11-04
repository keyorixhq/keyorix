package azurekms

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// FIPS-TAILS-2 review finding 3: on the MAC-mismatch return Decrypt dropped the
// unwrap result without clearing it, leaving recovered key material live in
// the buffer the provider client handed back. The fake returns the same slice
// it holds, so the buffer Decrypt discarded is observable after the call.
func TestDecrypt_MACMismatchZeroesUnwrapResult(t *testing.T) {
	// The envelope's MAC is keyed on one KEK; the fake "unwraps" to another.
	blob, err := encodeEnvelope("v1", []byte("ct"), []byte(testKEK32))
	require.NoError(t, err)

	leaked := []byte("fedcba9876543210fedcba9876543210")
	require.Len(t, leaked, 32)
	require.False(t, bytes.Equal(leaked, make([]byte, 32)))

	c := &client{keys: fakePermissiveKeys{plaintext: leaked}, keyName: "kek", keyVersion: ""}
	pt, err := c.Decrypt(context.Background(), blob)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed integrity check")
	require.Nil(t, pt, "no key material may be returned with the error")
	require.Equal(t, make([]byte, 32), leaked, "the discarded unwrap result must be zeroed")
}
