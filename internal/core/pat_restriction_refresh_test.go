package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// #146: CurrentPATRestriction must reflect the CURRENT row, not whatever was true
// when a caller last cached it — proving the primitive the auth middleware's
// cache-hit path relies on to avoid enforcing a stale CIDR allowlist.
func TestCurrentPATRestriction_ReflectsLiveNarrowing(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@x.io", IsActive: true}).Error)

	const raw = "kx_pat_narrowtest"
	cidrs, encErr := encodePATCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, encErr)
	pat := &models.PersonalAccessToken{
		ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw), AllowedCIDRs: cidrs,
	}
	require.NoError(t, db.Create(pat).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// Initially permits 10.0.0.0/8.
	restriction, err := c.CurrentPATRestriction(ctx, raw)
	require.NoError(t, err)
	require.NotNil(t, restriction)
	assert.Contains(t, restriction.AllowedCIDRs, "10.0.0.0/8")

	// An admin narrows the allowlist (simulating a mid-incident restriction change).
	narrowed, encErr := encodePATCIDRs([]string{"192.0.2.0/24"})
	require.NoError(t, encErr)
	pat.AllowedCIDRs = narrowed
	require.NoError(t, db.Save(pat).Error)

	// The VERY NEXT call — no TTL, no cache — must see the new, narrower allowlist.
	restriction, err = c.CurrentPATRestriction(ctx, raw)
	require.NoError(t, err)
	require.NotNil(t, restriction)
	assert.NotContains(t, restriction.AllowedCIDRs, "10.0.0.0/8", "the old allowlist must not still be honored")
	assert.Contains(t, restriction.AllowedCIDRs, "192.0.2.0/24")
}

// A lookup failure (e.g. the token was revoked/deleted between the caller's cache
// write and this refresh) must surface as an error, not silently report
// "unrestricted" — the caller must fail closed / fall back to the prior
// restriction, never treat a lookup failure as "no restriction."
func TestCurrentPATRestriction_LookupFailureIsAnError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	_, err = c.CurrentPATRestriction(context.Background(), "kx_pat_doesnotexist")
	require.Error(t, err, "a lookup failure must be a real error, not a silent nil-restriction")
}
