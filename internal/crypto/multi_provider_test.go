package crypto_test

import (
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubProvider struct {
	name string
	key  []byte
	err  error
}

func (s *stubProvider) Name() string         { return s.name }
func (s *stubProvider) KEK() ([]byte, error) { return s.key, s.err }

func goodProvider(name string) *stubProvider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &stubProvider{name: name, key: key}
}

func badProvider(name string) *stubProvider {
	return &stubProvider{name: name, err: errors.New("provider unavailable")}
}

func TestMultiKeyProvider_EmptyListError(t *testing.T) {
	_, err := crypto.NewMultiKeyProvider(nil)
	require.Error(t, err)
}

func TestMultiKeyProvider_PrimarySucceeds(t *testing.T) {
	good := goodProvider("primary")
	bad := badProvider("fallback")
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{good, bad})
	require.NoError(t, err)
	key, err := m.KEK()
	require.NoError(t, err)
	assert.Equal(t, good.key, key)
}

func TestMultiKeyProvider_FallsBackOnPrimaryFailure(t *testing.T) {
	fbKey := make([]byte, 32)
	for i := range fbKey {
		fbKey[i] = 0xff
	}
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{
		badProvider("primary"),
		&stubProvider{name: "fallback", key: fbKey},
	})
	require.NoError(t, err)
	key, err := m.KEK()
	require.NoError(t, err)
	assert.Equal(t, fbKey, key)
}

func TestMultiKeyProvider_AllFail(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{badProvider("a"), badProvider("b")})
	require.NoError(t, err)
	_, err = m.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all key providers failed")
}

func TestMultiKeyProvider_Name(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{goodProvider("aws-kms"), goodProvider("file")})
	require.NoError(t, err)
	assert.Equal(t, "multi(aws-kms,file)", m.Name())
}
