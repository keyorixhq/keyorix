package secret

import (
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout runs fn and returns everything it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// TestDisplaySecretsJSON_EscapesSecretName guards #354: a secret name (or any
// other string field) containing raw quotes/braces must not be able to break
// out of the JSON string and inject arbitrary keys into `secret list --format
// json` output.
func TestDisplaySecretsJSON_EscapesSecretName(t *testing.T) {
	malicious := `foo", "admin": true, "x":"`
	secrets := []*models.SecretNode{
		{
			ID:            1,
			Name:          malicious,
			Type:          "generic",
			Status:        "active",
			ProjectID:     1,
			EnvironmentID: 1,
			CreatedBy:     "alice",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}
	filter := &coreStorage.SecretFilter{Page: 1, PageSize: 50}

	out := captureStdout(t, func() {
		displaySecretsJSON(secrets, 1, filter)
	})

	var parsed jsonSecretsOutput
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "output must be valid, well-formed JSON")
	require.Len(t, parsed.Secrets, 1)
	assert.Equal(t, malicious, parsed.Secrets[0].Name, "the hostile name must round-trip as a single escaped string value")
	assert.False(t, parsed.Secrets[0].MaxReads != nil && *parsed.Secrets[0].MaxReads != 0, "no injected keys should have leaked into an unrelated field")
}
