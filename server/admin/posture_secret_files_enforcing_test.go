package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// In an enforcing mode nothing is appended: the server and every admin command
// refuse the file instead.
func TestPosture_EnforcingModeAppendsNothing(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "siem-token")
	require.NoError(t, os.WriteFile(secret, []byte(postureSecretFileContent+"\n"), 0o600))
	require.NoError(t, os.Chmod(secret, 0o644))
	t.Setenv("KEYORIX_SIEM_TOKEN", "")
	t.Setenv("KEYORIX_SIEM_TOKEN_FILE", secret)
	yaml := strings.NewReplacer("{{CHECK}}", "true", "{{UNSAFE}}", "false").Replace(postureSecretFilesYAML)
	_, cfg := writePostureFixture(t, yaml, 0o600)
	for _, line := range []secretFilesLine{secretFilesOnDisabledLine, secretFilesOnAllowUnsafeLine, secretFilesOnGraceLine} {
		assert.Empty(t, secretFilesNamedIn(cfg, line))
	}
}
