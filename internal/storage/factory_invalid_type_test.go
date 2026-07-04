package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateStorage_RejectsUnknownStorageType is the defense-in-depth companion
// to Config.Validate() rejecting an unrecognized storage.type (#463). The
// factory's own dispatch used to silently fall through to SQLite for any value
// it didn't recognize ("local", "" or any typo alike) — a config typo like
// "postgres_typo" or "remot" would then boot each replica against its own,
// disconnected local database instead of the intended shared backend, with no
// error anywhere in the chain. CreateStorage must now return an error instead
// of silently constructing local storage, so that other code paths which build
// storage without going through Config.Validate() first are still protected.
func TestCreateStorage_RejectsUnknownStorageType(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres_typo"

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err)
	assert.Nil(t, st)
	assert.Contains(t, err.Error(), "postgres_typo")
}
