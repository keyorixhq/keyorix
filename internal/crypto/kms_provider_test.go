package crypto

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKMS is an in-memory envelope cipher: it "wraps" by prefixing a tag, so
// Decrypt(Encrypt(x)) == x, and a different key (tag) fails to decrypt.
type fakeKMS struct {
	tag      string
	encrypts int
	decrypts int
	failEncr bool
	failDecr bool
}

func (f *fakeKMS) Encrypt(_ context.Context, pt []byte) ([]byte, error) {
	f.encrypts++
	if f.failEncr {
		return nil, errors.New("kms encrypt boom")
	}
	return append([]byte(f.tag+"|"), pt...), nil
}
func (f *fakeKMS) Decrypt(_ context.Context, ct []byte) ([]byte, error) {
	f.decrypts++
	if f.failDecr {
		return nil, errors.New("kms decrypt boom")
	}
	prefix := []byte(f.tag + "|")
	if len(ct) < len(prefix) || string(ct[:len(prefix)]) != f.tag+"|" {
		return nil, errors.New("kms: ciphertext was not wrapped by this key")
	}
	return ct[len(prefix):], nil
}

func TestKMSKeyProvider_WrapsThenUnwrapsStably(t *testing.T) {
	dir := t.TempDir()
	kms := &fakeKMS{tag: "cmk-A"}
	p := NewKMSKeyProvider(kms, "aws-kms", dir, "kek.kms")

	// First run: generates a KEK, wraps it, persists the wrapped blob.
	kek1, err := p.KEK()
	require.NoError(t, err)
	require.Len(t, kek1, KEKSize)
	assert.Equal(t, 1, kms.encrypts)
	assert.Equal(t, 0, kms.decrypts)

	wrapped, err := os.ReadFile(filepath.Join(dir, "kek.kms"))
	require.NoError(t, err)
	assert.NotEqual(t, kek1, wrapped, "the on-disk blob is the wrapped (ciphertext) KEK, not the raw key")

	// Restart: a fresh provider over the same dir + same KMS unwraps the SAME KEK.
	p2 := NewKMSKeyProvider(&fakeKMS{tag: "cmk-A"}, "aws-kms", dir, "kek.kms")
	kek2, err := p2.KEK()
	require.NoError(t, err)
	assert.Equal(t, kek1, kek2, "the KEK must be stable across restarts")
}

func TestKMSKeyProvider_WrongKMSKeyCannotUnwrap(t *testing.T) {
	dir := t.TempDir()
	_, err := NewKMSKeyProvider(&fakeKMS{tag: "cmk-A"}, "aws-kms", dir, "kek.kms").KEK()
	require.NoError(t, err)

	// A different KMS key (tag) cannot decrypt the wrapped blob — like rotating the
	// CMK out from under the data.
	_, err = NewKMSKeyProvider(&fakeKMS{tag: "cmk-B"}, "aws-kms", dir, "kek.kms").KEK()
	require.Error(t, err)
}

func TestKMSKeyProvider_Errors(t *testing.T) {
	dir := t.TempDir()
	t.Run("nil client", func(t *testing.T) {
		_, err := NewKMSKeyProvider(nil, "aws-kms", dir, "kek.kms").KEK()
		require.Error(t, err)
	})
	t.Run("empty wrapped_key_path", func(t *testing.T) {
		_, err := NewKMSKeyProvider(&fakeKMS{tag: "x"}, "aws-kms", dir, "").KEK()
		require.Error(t, err)
	})
	t.Run("KMS encrypt failure on first run", func(t *testing.T) {
		_, err := NewKMSKeyProvider(&fakeKMS{tag: "x", failEncr: true}, "aws-kms", dir, "fail.kms").KEK()
		require.Error(t, err)
		assert.NoFileExists(t, filepath.Join(dir, "fail.kms"), "no wrapped blob persisted on encrypt failure")
	})
	t.Run("KMS decrypt failure on restart", func(t *testing.T) {
		d2 := t.TempDir()
		_, err := NewKMSKeyProvider(&fakeKMS{tag: "x"}, "aws-kms", d2, "k.kms").KEK()
		require.NoError(t, err)
		_, err = NewKMSKeyProvider(&fakeKMS{tag: "x", failDecr: true}, "aws-kms", d2, "k.kms").KEK()
		require.Error(t, err)
	})
}

func TestKMSKeyProvider_RejectsWrongSizeKEK(t *testing.T) {
	dir := t.TempDir()
	// A KMS that returns a non-32-byte "KEK" on decrypt must be rejected.
	bad := &shortKMS{}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k.kms"), []byte("anything"), 0600))
	_, err := NewKMSKeyProvider(bad, "aws-kms", dir, "k.kms").KEK()
	require.Error(t, err)
}

type shortKMS struct{}

func (shortKMS) Encrypt(_ context.Context, pt []byte) ([]byte, error) { return pt, nil }
func (shortKMS) Decrypt(_ context.Context, _ []byte) ([]byte, error)  { return []byte("too-short"), nil }
