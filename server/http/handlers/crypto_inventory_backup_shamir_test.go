package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
)

// Review finding (#3754): `admin backup` archives the Shamir provider's share
// files (keyfiles.Registry), which are plaintext shares. With threshold-many of
// them in the archive the KEK can be rebuilt from the archive alone, so the
// backup asset must not be credited as AES-256-GCM; it fails closed and warns.
func TestCryptoInventoryHandler_BackupWithShamirShareFilesFailsClosed(t *testing.T) {
	f := newCryptoInvFixture(t)
	dir := t.TempDir()
	f.cfg.Storage.Encryption.KeyProvider = config.KeyProviderConfig{Type: "tpm",
		Fallbacks: []config.KeyProviderConfig{{Type: "shamir",
			ShamirShareFiles: []string{filepath.Join(dir, "s1"), filepath.Join(dir, "s2"), filepath.Join(dir, "s3")}}}}

	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	var backup *cryptoinventory.Asset
	for i := range env.Data.Assets {
		if env.Data.Assets[i].ID == "backup-archive" {
			backup = &env.Data.Assets[i]
		}
	}
	require.NotNil(t, backup, "backup asset missing")
	assert.NotEqual(t, "AES-256-GCM", backup.Algorithm, "plaintext share files in the archive: its encryption cannot be credited")
	assert.NotEqual(t, cryptoinventory.LevelLow, backup.Risk.Level, "fail closed")
	warned := false
	for _, w := range env.Data.Warnings {
		warned = warned || strings.Contains(w, "Shamir KEK share file")
	}
	assert.True(t, warned, "the plaintext shares in backups must be warned about: %v", env.Data.Warnings)
}
