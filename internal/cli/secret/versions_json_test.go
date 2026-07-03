package secret

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDisplayVersionsJSON_EscapesSecretName guards #354: a secret name/type
// containing raw quotes/braces must not be able to break out of the JSON
// string and inject arbitrary keys into `secret versions --format json`
// output.
func TestDisplayVersionsJSON_EscapesSecretName(t *testing.T) {
	malicious := `foo", "admin": true, "x":"`
	secret := &models.SecretNode{ID: 1, Name: malicious, Type: "generic"}
	versions := []*models.SecretVersion{
		{ID: 10, VersionNumber: 1, ReadCount: 2, CreatedAt: time.Now()},
	}

	out := captureStdout(t, func() {
		displayVersionsJSON(secret, versions)
	})

	var parsed jsonVersionsOutput
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "output must be valid, well-formed JSON")
	assert.Equal(t, malicious, parsed.Secret.Name, "the hostile name must round-trip as a single escaped string value")
	require.Len(t, parsed.Versions, 1)
	assert.Equal(t, uint(10), parsed.Versions[0].ID)
}

// TestDisplayVersionsJSON_EmbedsEncryptionMetadataRaw confirms the existing
// behavior of inlining EncryptionMetadata (already-serialized JSON bytes) is
// preserved through the json.RawMessage switch, rather than double-encoding
// it into an escaped string.
func TestDisplayVersionsJSON_EmbedsEncryptionMetadataRaw(t *testing.T) {
	secret := &models.SecretNode{ID: 1, Name: "db", Type: "generic"}
	versions := []*models.SecretVersion{
		{ID: 10, VersionNumber: 1, CreatedAt: time.Now(), EncryptionMetadata: models.JSON(`{"algorithm":"AES-256-GCM"}`)},
	}

	out := captureStdout(t, func() {
		displayVersionsJSON(secret, versions)
	})

	var parsed jsonVersionsOutput
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	require.Len(t, parsed.Versions, 1)
	require.NotNil(t, parsed.Versions[0].EncryptionMetadata)
	var meta map[string]string
	require.NoError(t, json.Unmarshal(parsed.Versions[0].EncryptionMetadata, &meta))
	assert.Equal(t, "AES-256-GCM", meta["algorithm"])
}
