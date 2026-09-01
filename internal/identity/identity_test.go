package identity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nfcCafe/nfdCafe reproduce #1642's exact live-demonstrated collision: two
// byte-different, visually-identical representations of "cafe" + acute
// accent. Built from \u escape sequences (pure ASCII source), not a literal
// typed/pasted character -- an editor, terminal, or file-write layer can
// silently re-normalize a literal combining-character sequence to NFC on
// save, which would make this fixture worthless (the exact gotcha the
// original #1642 recon itself called out).
var (
	nfcCafe = "café"  // e-acute precomposed (U+00E9), 5 bytes UTF-8
	nfdCafe = "café" // e (U+0065) + combining acute accent (U+0301), 6 bytes UTF-8
)

func TestNewFoldedName_NFCCollisionResolved(t *testing.T) {
	require.NotEqual(t, nfcCafe, nfdCafe, "test fixture must actually be byte-different")

	a, err := NewFoldedName(nfcCafe)
	require.NoError(t, err)
	b, err := NewFoldedName(nfdCafe)
	require.NoError(t, err)

	assert.Equal(t, a.Folded(), b.Folded(), "NFC and NFD forms of the same identity must fold to the same key")
}

func TestNewFoldedName_CaseCollisionResolved(t *testing.T) {
	a, err := NewFoldedName("Admin")
	require.NoError(t, err)
	b, err := NewFoldedName("admin")
	require.NoError(t, err)

	assert.Equal(t, a.Folded(), b.Folded())
	// Display form is preserved exactly as typed.
	assert.Equal(t, "Admin", a.Display())
	assert.Equal(t, "admin", b.Display())
}

func TestNewFoldedName_PreservesSpaces(t *testing.T) {
	n, err := NewFoldedName("Support Team")
	require.NoError(t, err)
	assert.Equal(t, "support team", n.Folded())
	assert.Equal(t, "Support Team", n.Display())
}

func TestNewFoldedName_RejectsControlCharacters(t *testing.T) {
	_, err := NewFoldedName("readonly\n[AUDIT] granted admin")
	require.Error(t, err)
}

func TestNewFoldedName_RejectsBidiOverride(t *testing.T) {
	_, err := NewFoldedName("read\u202eonly")
	require.Error(t, err)
}

func TestNewFoldedName_RejectsEmpty(t *testing.T) {
	_, err := NewFoldedName("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmpty))
}

func TestNewAddressName_NFCCollisionResolved(t *testing.T) {
	a, err := NewAddressName(nfcCafe)
	require.NoError(t, err)
	b, err := NewAddressName(nfdCafe)
	require.NoError(t, err)

	assert.Equal(t, a.String(), b.String(), "NFC and NFD forms must normalize to the same address")
}

func TestNewAddressName_DoesNotFoldCase(t *testing.T) {
	a, err := NewAddressName("PROD_KEY")
	require.NoError(t, err)
	b, err := NewAddressName("prod_key")
	require.NoError(t, err)

	assert.NotEqual(t, a.String(), b.String(), "secret names are addresses -- case must stay distinct")
	assert.Equal(t, "PROD_KEY", a.String())
	assert.Equal(t, "prod_key", b.String())
}

func TestNewAddressName_PreservesSpacesAndPunctuation(t *testing.T) {
	for _, raw := range []string{"prod.database.url", "prod/database/url", "AWS:SECRET_KEY", "my key with spaces"} {
		n, err := NewAddressName(raw)
		require.NoError(t, err, "raw=%q", raw)
		assert.Equal(t, raw, n.String())
	}
}

func TestNewAddressName_RejectsControlCharacters(t *testing.T) {
	_, err := NewAddressName("key\n[injected]")
	require.Error(t, err)
}

func TestNewAddressName_RejectsBidiOverride(t *testing.T) {
	_, err := NewAddressName("key\u202evalue")
	require.Error(t, err)
}

func TestNewAddressName_RejectsEmpty(t *testing.T) {
	_, err := NewAddressName("")
	require.Error(t, err)
}

func TestFoldedName_StringImplementsStringer(t *testing.T) {
	n, err := NewFoldedName("MyUser")
	require.NoError(t, err)
	assert.Equal(t, "MyUser", n.String())
}
