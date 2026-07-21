// local_token_expiry_test.go — unit tests for local_token_expiry.go.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTokenExpiryStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "token_expiry_"+t.Name(),
		&models.PersonalAccessToken{},
		&models.MachineIdentityCredential{},
	)
}

// ── ListExpiringPATs ──────────────────────────────────────────────────────────

func TestListExpiringPATs_ReturnsNonRevokedWithExpiresAtBeforeCutoff(t *testing.T) {
	ls := newTokenExpiryStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	cutoff := now.Add(7 * 24 * time.Hour)

	// Should be returned: non-revoked, ExpiresAt within window.
	expIn3Days := now.Add(3 * 24 * time.Hour)
	pat := models.PersonalAccessToken{
		UserID:    1,
		Name:      "matching-pat",
		TokenHash: "hash1",
		ExpiresAt: &expIn3Days,
		Revoked:   false,
	}
	require.NoError(t, ls.db.Create(&pat).Error)

	// Should NOT be returned: revoked.
	revokedExp := now.Add(2 * 24 * time.Hour)
	revoked := models.PersonalAccessToken{
		UserID:    2,
		Name:      "revoked-pat",
		TokenHash: "hash2",
		ExpiresAt: &revokedExp,
		Revoked:   true,
	}
	require.NoError(t, ls.db.Create(&revoked).Error)

	// Should NOT be returned: ExpiresAt beyond cutoff.
	farExp := now.Add(30 * 24 * time.Hour)
	far := models.PersonalAccessToken{
		UserID:    3,
		Name:      "far-pat",
		TokenHash: "hash3",
		ExpiresAt: &farExp,
		Revoked:   false,
	}
	require.NoError(t, ls.db.Create(&far).Error)

	// Should NOT be returned: ExpiresAt is nil.
	noExp := models.PersonalAccessToken{
		UserID:    4,
		Name:      "no-exp-pat",
		TokenHash: "hash4",
		ExpiresAt: nil,
		Revoked:   false,
	}
	require.NoError(t, ls.db.Create(&noExp).Error)

	pats, err := ls.ListExpiringPATs(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	assert.Equal(t, "matching-pat", pats[0].Name)
}

func TestListExpiringPATs_IncludesAlreadyExpired(t *testing.T) {
	// The storage layer includes already-expired (past) PATs; the core layer
	// filters them out. This verifies the storage doesn't over-filter.
	ls := newTokenExpiryStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	cutoff := now.Add(7 * 24 * time.Hour)

	pastExp := now.Add(-time.Hour)
	pat := models.PersonalAccessToken{
		UserID:    10,
		Name:      "already-expired",
		TokenHash: "hash-expired",
		ExpiresAt: &pastExp,
		Revoked:   false,
	}
	require.NoError(t, ls.db.Create(&pat).Error)

	pats, err := ls.ListExpiringPATs(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	assert.Equal(t, "already-expired", pats[0].Name)
}

func TestListExpiringPATs_EmptyWhenNone(t *testing.T) {
	ls := newTokenExpiryStore(t)
	ctx := context.Background()
	cutoff := time.Now().Add(7 * 24 * time.Hour)

	pats, err := ls.ListExpiringPATs(ctx, cutoff)
	require.NoError(t, err)
	assert.Empty(t, pats)
}

// ── ListExpiringMachineCredentials ────────────────────────────────────────────

func TestListExpiringMachineCredentials_ReturnsNonRevokedWithExpiresAtBeforeCutoff(t *testing.T) {
	ls := newTokenExpiryStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	cutoff := now.Add(7 * 24 * time.Hour)

	// Should be returned.
	expIn3Days := now.Add(3 * 24 * time.Hour)
	cred := models.MachineIdentityCredential{
		MachineIdentityID: 1,
		Name:              "matching-cred",
		TokenHash:         "mhash1",
		ExpiresAt:         &expIn3Days,
		Revoked:           false,
	}
	require.NoError(t, ls.db.Create(&cred).Error)

	// Should NOT be returned: revoked.
	revokedExp := now.Add(2 * 24 * time.Hour)
	revoked := models.MachineIdentityCredential{
		MachineIdentityID: 2,
		Name:              "revoked-cred",
		TokenHash:         "mhash2",
		ExpiresAt:         &revokedExp,
		Revoked:           true,
	}
	require.NoError(t, ls.db.Create(&revoked).Error)

	// Should NOT be returned: ExpiresAt beyond cutoff.
	farExp := now.Add(30 * 24 * time.Hour)
	far := models.MachineIdentityCredential{
		MachineIdentityID: 3,
		Name:              "far-cred",
		TokenHash:         "mhash3",
		ExpiresAt:         &farExp,
		Revoked:           false,
	}
	require.NoError(t, ls.db.Create(&far).Error)

	// Should NOT be returned: ExpiresAt is nil.
	noExp := models.MachineIdentityCredential{
		MachineIdentityID: 4,
		Name:              "no-exp-cred",
		TokenHash:         "mhash4",
		ExpiresAt:         nil,
		Revoked:           false,
	}
	require.NoError(t, ls.db.Create(&noExp).Error)

	creds, err := ls.ListExpiringMachineCredentials(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "matching-cred", creds[0].Name)
}

func TestListExpiringMachineCredentials_IncludesAlreadyExpired(t *testing.T) {
	ls := newTokenExpiryStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	cutoff := now.Add(7 * 24 * time.Hour)

	pastExp := now.Add(-time.Hour)
	cred := models.MachineIdentityCredential{
		MachineIdentityID: 10,
		Name:              "expired-cred",
		TokenHash:         "mhash-expired",
		ExpiresAt:         &pastExp,
		Revoked:           false,
	}
	require.NoError(t, ls.db.Create(&cred).Error)

	creds, err := ls.ListExpiringMachineCredentials(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "expired-cred", creds[0].Name)
}

func TestListExpiringMachineCredentials_EmptyWhenNone(t *testing.T) {
	ls := newTokenExpiryStore(t)
	ctx := context.Background()
	cutoff := time.Now().Add(7 * 24 * time.Hour)

	creds, err := ls.ListExpiringMachineCredentials(ctx, cutoff)
	require.NoError(t, err)
	assert.Empty(t, creds)
}
