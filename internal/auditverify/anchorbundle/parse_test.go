package anchorbundle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MUTANT-SEC-3: the parser is exercised by the fuzz target only for "does not
// panic"; these pin what it accepts and rejects.
func TestParseExternalAnchorBundle(t *testing.T) {
	b, err := ParseExternalAnchorBundle([]byte(`{"chained_events":10,"head_id":9,"head_hash":"abc","key_version":"v1","signature":"sig","anchor_token":"dG9r","anchor_provider":"tsa"}`))
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, int64(10), b.ChainedEvents)
	assert.Equal(t, uint64(9), b.HeadID)
	assert.Equal(t, "abc", b.HeadHash)
	assert.Equal(t, "v1", b.KeyVersion)
	assert.Equal(t, "sig", b.Signature)
	assert.Equal(t, []byte("tok"), b.AnchorToken)
	assert.Equal(t, "tsa", b.AnchorProvider)
}

func TestParseExternalAnchorBundle_Rejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":            ``,
		"not json":         `not json`,
		"truncated json":   `{"head_hash":"abc","signature":"sig"`,
		"wrong field type": `{"chained_events":"ten","head_hash":"abc","signature":"sig"}`,
		"no head_hash":     `{"signature":"sig"}`,
		"no signature":     `{"head_hash":"abc"}`,
		"empty head_hash":  `{"head_hash":"","signature":"sig"}`,
		"empty signature":  `{"head_hash":"abc","signature":""}`,
		"json null":        `null`,
		"json array":       `[]`,
	} {
		b, err := ParseExternalAnchorBundle([]byte(in))
		assert.Error(t, err, name)
		assert.Nil(t, b, name)
	}
}
