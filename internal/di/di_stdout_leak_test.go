package di

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sentinelDBPassword is a recognizable value that must never appear on
// InitializeApp's stdout output. If this constant ever shows up in captured
// output, the loaded *config.Config (or some field of it carrying a live
// secret) is being printed somewhere in the init path — see the security
// note on InitializeApp in wire.go.
const sentinelDBPassword = "S3ntinel-Do-Not-Leak-9f3ac21c"

// TestInitializeApp_DoesNotLeakConfigSecretsToStdout is a regression test for
// a HIGH-severity finding: InitializeApp used to do
// fmt.Println("Config successfully loaded:", conf), printing the entire
// loaded *config.Config value — including live secrets such as
// storage.database.password — to stdout. stdout is routinely captured by
// container/systemd/CI log pipelines that have far broader read access than
// the config file itself, so every process start leaked every secret
// embedded in config.
//
// This test writes a keyorix.yaml containing a recognizable sentinel value in
// storage.database.password, captures everything InitializeApp writes to
// os.Stdout, and asserts the sentinel never appears in that output.
func TestInitializeApp_DoesNotLeakConfigSecretsToStdout(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(restoreWD(t))

	cfgYAML := `
storage:
  database:
    password: "` + sentinelDBPassword + `"
`
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o600))
	require.NoError(t, os.Chdir(dir))

	output := captureStdout(t, func() {
		result, err := InitializeApp()
		require.NoError(t, err, "InitializeApp must succeed with a valid keyorix.yaml")
		assert.NotEmpty(t, result)
	})

	assert.NotContains(t, output, sentinelDBPassword,
		"InitializeApp must never print secret config values (e.g. storage.database.password) to stdout")
	assert.False(t, strings.Contains(output, "Password"),
		"InitializeApp's stdout output should not include a serialized Config struct field dump")
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. fn runs synchronously; os.Stdout is restored
// before captureStdout returns (including on failure/panic).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "failed to create pipe for stdout capture")
	os.Stdout = w
	defer func() {
		os.Stdout = origStdout
	}()

	fn()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err, "failed to read captured stdout")
	return buf.String()
}
