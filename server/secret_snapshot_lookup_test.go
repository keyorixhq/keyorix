package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// loadWithSecretFiles runs config.Load (which snapshots every non-key-material
// *_FILE secret) on a config naming a Vault connector with token_env vaultEnv.
func loadWithSecretFiles(t *testing.T, vaultEnv string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "keyorix.yaml")
	yaml := "connect:\n  connectors:\n    - name: v\n      type: vault\n      token_env: " + vaultEnv + "\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
}

// swapFile replaces the file at path with new content through a rename, i.e. a
// different inode than the one Load opened and the permission check judged.
func swapFile(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".new"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

// #3830: the first-admin claim token is the snapshot's bytes, not whatever the
// path names by the time the server wires bootstrap.
func TestResolveBootstrapToken_AnsweredFromLoadSnapshot(t *testing.T) {
	snap := strings.Repeat("s", 40)
	swapped := strings.Repeat("x", 40)
	p := serverSecretFile(t, snap+"\n")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", p)
	loadWithSecretFiles(t, "KX_SNAP_VAULT_TOK")

	swapFile(t, p, swapped+"\n") // a file the permission check never saw

	got, err := resolveBootstrapToken()
	require.NoError(t, err)
	assert.Equal(t, snap, got)
	assert.NotEqual(t, swapped, got)
}

// #3830: same for the Vault connector token wired from server/wire_connect.go.
func TestResolveVaultToken_AnsweredFromLoadSnapshot(t *testing.T) {
	p := serverSecretFile(t, "hvs.snapshot\n")
	t.Setenv("KX_SNAP_VAULT_TOK_FILE", p)
	loadWithSecretFiles(t, "KX_SNAP_VAULT_TOK")

	swapFile(t, p, "hvs.swapped\n")

	got, err := resolveVaultToken("KX_SNAP_VAULT_TOK")
	require.NoError(t, err)
	assert.Equal(t, "hvs.snapshot", got)
}
