// g81_dynamic_lease_timezone_test.go — regression coverage for G81's
// DynamicSecretLease member: this codebase previously fixed a GORM/SQLite
// timezone-comparison bug (mixed UTC/local time.Time values break SQLite's
// string-based time comparisons) by adding UTC-normalizing BeforeSave hooks
// to the affected models, but DynamicSecretLease was never given one — and
// its ExpiresAt is the field the auto-revoke sweep's whole purpose depends
// on comparing correctly.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newG81LeaseStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretLease{}))
	return NewLocalStorage(db)
}

// TestCreateDynamicSecretLease_NonUTCExpiryStoredAsUTC pins the write half of
// G81: a lease created with an ExpiresAt constructed in a non-UTC local
// timezone (e.g. a server running with TZ set) must be persisted as UTC.
func TestCreateDynamicSecretLease_NonUTCExpiryStoredAsUTC(t *testing.T) {
	ls := newG81LeaseStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC-7", -7*60*60)
	exp := time.Date(2026, 8, 20, 12, 0, 0, 0, nonUTC)

	created, err := ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: 1, LeaseID: "lease-1", Status: "active",
		IssuedAt: time.Now(), ExpiresAt: exp,
	})
	require.NoError(t, err)
	assert.Equal(t, time.UTC, created.ExpiresAt.Location(), "expires_at must be stored in UTC")
	assert.True(t, created.ExpiresAt.Equal(exp), "the instant must be preserved even though the zone changed")

	var reloaded models.DynamicSecretLease
	require.NoError(t, ls.db.First(&reloaded, created.ID).Error)
	assert.Equal(t, time.UTC, reloaded.ExpiresAt.Location())
}

// TestListExpiredActiveLeases_RecognizesNonUTCExpiryAsExpired is G81's own
// detection_idea for the DynamicSecretLease member, run directly: set a
// lease's expiry in a non-UTC local time that has genuinely already passed,
// persist it, and confirm the sweep query (ListExpiredActiveLeases) still
// recognizes it as expired — the exact scenario a mixed UTC/local ExpiresAt
// could silently break, letting a genuinely-expired lease's target
// credential stay live past its TTL undetected.
func TestListExpiredActiveLeases_RecognizesNonUTCExpiryAsExpired(t *testing.T) {
	ls := newG81LeaseStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC+9", 9*60*60)
	pastExpiry := time.Now().In(nonUTC).Add(-1 * time.Minute)

	_, err := ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: 1, LeaseID: "lease-expired", Status: "active",
		IssuedAt: time.Now(), ExpiresAt: pastExpiry,
	})
	require.NoError(t, err)

	// The sweep cutoff itself is also constructed in a non-UTC zone here,
	// matching server/main.go's real call site (time.Now(), local system
	// time) — ListExpiredActiveLeases must normalize it internally rather
	// than relying on the caller to remember to pass UTC.
	cutoff := time.Now().In(time.FixedZone("UTC+2", 2*60*60))
	expired, err := ls.ListExpiredActiveLeases(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, expired, 1, "the genuinely-expired non-UTC lease must be found by the sweep")
	assert.Equal(t, "lease-expired", expired[0].LeaseID)
}

// TestListExpiredActiveLeases_DoesNotFlagNotYetExpiredLease is the negative
// control for the same fix: a lease whose non-UTC expiry has NOT actually
// passed yet must not be swept.
func TestListExpiredActiveLeases_DoesNotFlagNotYetExpiredLease(t *testing.T) {
	ls := newG81LeaseStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC+9", 9*60*60)
	futureExpiry := time.Now().In(nonUTC).Add(1 * time.Hour)

	_, err := ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: 1, LeaseID: "lease-still-live", Status: "active",
		IssuedAt: time.Now(), ExpiresAt: futureExpiry,
	})
	require.NoError(t, err)

	expired, err := ls.ListExpiredActiveLeases(ctx, time.Now())
	require.NoError(t, err)
	assert.Empty(t, expired, "a lease that has not actually expired yet must not be swept")
}
