package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFreshBootCreatesAccountSchema verifies that a fresh-DB boot produces the
// enriched session schema (user_agent/ip_address/last_seen_at) and the
// personal_access_tokens table, and that a second CreateStorage on the same DB is
// idempotent (does not error).
func TestFreshBootCreatesAccountSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "account-boot.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "fresh-DB AutoMigrate must succeed with the account models")

	// A second boot against the same DB must remain idempotent.
	_, err = NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "re-running migrations must be a no-op, not an error")

	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	seen := time.Now().UTC().Truncate(time.Second)

	// #2701: a session or PAT insert re-checks that its owner is a live,
	// login-capable user and rolls back otherwise, so the round-trips below
	// need a real owner. The fresh boot seeds no users.
	owner, err := st.CreateUser(ctx, &models.User{
		Username: "boot-owner", Email: "boot-owner@example.test", IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)

	// Enriched session columns round-trip.
	s, err := st.CreateSession(ctx, &models.Session{
		UserID: owner.ID, SessionToken: "tok", UserAgent: "TestAgent/1.0",
		IPAddress: "10.0.0.1", LastSeenAt: &seen, ExpiresAt: &future,
	})
	require.NoError(t, err)
	sessions, err := st.ListSessionsByUser(ctx, owner.ID)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "TestAgent/1.0", sessions[0].UserAgent)
	assert.Equal(t, "10.0.0.1", sessions[0].IPAddress)
	require.NotNil(t, sessions[0].LastSeenAt)
	_ = s

	// personal_access_tokens table exists and round-trips.
	pat, err := st.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: owner.ID, Name: "ci", TokenHash: "h", TokenPrefix: "kx_pat_xyz",
	})
	require.NoError(t, err)
	got, err := st.GetPersonalAccessTokenByHash(ctx, "h")
	require.NoError(t, err)
	assert.Equal(t, pat.ID, got.ID)
}
