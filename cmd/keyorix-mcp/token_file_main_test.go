package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SECRETENV-TAILS-2 F8: KEYORIX_TOKEN_FILE, judged by secretenv.LookupChecked.
// These drive main() in a subprocess, the way an agent client starts the binary.

const tokenFileSecret = "kx_machine_tokenfile_secret_value"

// writeTokenFile writes content to a fresh file with the given mode and returns
// its absolute path.
func writeTokenFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

// runTokenFileChild is the child half: KEYORIX_MCP_TEST_FILE_UID makes every file
// report that owner (a test cannot chown to a third account), as the secretenv
// matrix tests do through the same seam.
func runTokenFileChild() {
	if os.Getenv("KEYORIX_MCP_TEST_FILE_UID") == "4242" {
		defer secretenv.OverrideOwnershipForTest(4242, os.Geteuid())()
	}
	main()
}

func TestMainSubprocess_TokenFile_Works(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		runTokenFileChild()
		return
	}
	p := writeTokenFile(t, tokenFileSecret+"\n", 0o600)
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_TokenFile_Works",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN_FILE=" + p}, bytes.NewReader(nil))
	require.NoError(t, runErr, "a 0600 KEYORIX_TOKEN_FILE owned by the running user must be accepted; stderr: %s", stderr)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, "ready (server dev)")
	assert.NotContains(t, stderr, tokenFileSecret)
}

func TestMainSubprocess_TokenFile_BothSetRefuses(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		runTokenFileChild()
		return
	}
	p := writeTokenFile(t, tokenFileSecret+"\n", 0o600)
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_TokenFile_BothSetRefuses",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN=env_token_value", "KEYORIX_TOKEN_FILE=" + p}, bytes.NewReader(nil))
	require.Error(t, runErr, "KEYORIX_TOKEN and KEYORIX_TOKEN_FILE both set must refuse (DEPLOY-2), not pick one")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "both KEYORIX_TOKEN and KEYORIX_TOKEN_FILE are set")
	assert.NotContains(t, stderr, "env_token_value")
	assert.NotContains(t, stderr, tokenFileSecret)
}

func TestMainSubprocess_TokenFile_TooOpenRefuses(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		runTokenFileChild()
		return
	}
	p := writeTokenFile(t, tokenFileSecret+"\n", 0o644)
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_TokenFile_TooOpenRefuses",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN_FILE=" + p}, bytes.NewReader(nil))
	require.Error(t, runErr, "a 0644 KEYORIX_TOKEN_FILE must be refused")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "KEYORIX_TOKEN_FILE=")
	assert.Contains(t, stderr, "mode 0644 is too open")
	assert.NotContains(t, stderr, tokenFileSecret)
}

func TestMainSubprocess_TokenFile_ForeignOwnerRefuses(t *testing.T) {
	if os.Getenv("KEYORIX_MCP_MAIN_SUBPROCESS") == "1" {
		runTokenFileChild()
		return
	}
	p := writeTokenFile(t, tokenFileSecret+"\n", 0o600)
	stderr, exitCode, runErr := runMainSubprocess(t, "TestMainSubprocess_TokenFile_ForeignOwnerRefuses",
		[]string{"KEYORIX_URL=http://127.0.0.1:1", "KEYORIX_TOKEN_FILE=" + p, "KEYORIX_MCP_TEST_FILE_UID=4242"}, bytes.NewReader(nil))
	require.Error(t, runErr, "a 0600 KEYORIX_TOKEN_FILE owned by another non-root account must be refused (#3393)")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, stderr, "owned by uid 4242")
	assert.NotContains(t, stderr, tokenFileSecret)
}
