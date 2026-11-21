// pat_cache_hit_owner_recheck_test.go — the PAT branch of serveAuthCacheHit
// re-checks the token's OWNING ACCOUNT, not only the token row.
//
// Each test caches a PAT via the slow path, then changes the owner's account
// WITHOUT touching the token row (revoked stays false). That is the state a
// failed credential sweep leaves behind: SuspendUser/DeactivateUser/DeleteUser
// mark every PAT revoked and evict the cache only when the sweep succeeds, so
// before this re-check the cached token kept authenticating for up to
// validTokenTTL on every replica holding it. The machine-token branch has had
// the equivalent owner gate since #2518 (g18_cache_hit_revocation_test.go and
// TestCacheHit_MachineIdentityInactive_IsDefinitiveNotTransient).
//
// What this does not cover: RemoteStorage (never wired into the server,
// ADR-083), and the slow path, which ValidatePATToken already gates on the
// owner (TestValidatePATToken_SuspendRevokesTokenAccess in internal/core).
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// cachedPATOwnerWorld seeds one active user (id 3) and one unrevoked PAT owned
// by it (raw must be one fakeValidator accepts as that user's PAT), serves the PAT once so the slow path caches it, and returns the DB,
// the core and the handler for the cache-hit request.
func cachedPATOwnerWorld(t *testing.T, raw string) (*gorm.DB, *core.KeyorixCore, http.Handler) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true, AccountState: core.AccountActive}).Error)

	resetTokenCacheG18(raw)
	t.Cleanup(func() { resetTokenCacheG18(raw) })
	sum := sha256.Sum256([]byte(raw))
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hex.EncodeToString(sum[:])}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := authenticationWithValidator(fakeValidator{}, coreService)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	require.Equal(t, http.StatusOK, serveG18(handler, raw), "first request caches via the slow path")
	requirePositiveCacheEntry(t, raw)
	return db, coreService, handler
}

// requireCacheEntryEvicted asserts raw no longer holds a positive cache entry.
func requireCacheEntryEvicted(t *testing.T, raw string) {
	t.Helper()
	entry, found := cacheGet(tokenKey(raw))
	require.False(t, found && entry.userCtx != nil, "a definitive deny must evict the positive cache entry")
}

func TestCacheHit_PATOwnerSuspended_DeniedAndEvicted(t *testing.T) {
	const raw = "kx_pat_validtoken"
	db, _, handler := cachedPATOwnerWorld(t, raw)

	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 3).Update("account_state", core.AccountSuspended).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT whose owner was suspended after caching must be denied on the very next request, even with the token row unrevoked")
	requireCacheEntryEvicted(t, raw)
}

func TestCacheHit_PATOwnerDeactivated_DeniedAndEvicted(t *testing.T) {
	const raw = "kx_pat_validtoken"
	db, _, handler := cachedPATOwnerWorld(t, raw)

	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 3).Update("is_active", false).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT whose owner was deactivated after caching must be denied on the very next request")
	requireCacheEntryEvicted(t, raw)
}

func TestCacheHit_PATOwnerDeprovisioned_DeniedAndEvicted(t *testing.T) {
	const raw = "kx_pat_validtoken"
	db, _, handler := cachedPATOwnerWorld(t, raw)

	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 3).Update("account_state", core.AccountDeprovisioned).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT whose owner was deprovisioned after caching must be denied on the very next request")
	requireCacheEntryEvicted(t, raw)
}

func TestCacheHit_PATOwnerDeleted_DeniedAndEvicted(t *testing.T) {
	const raw = "kx_pat_validtoken"
	db, _, handler := cachedPATOwnerWorld(t, raw)

	require.NoError(t, db.Unscoped().Delete(&models.User{}, 3).Error)

	require.Equal(t, http.StatusUnauthorized, serveG18(handler, raw),
		"a PAT whose owner row is gone must be denied on the very next request")
	requireCacheEntryEvicted(t, raw)
}

// TestCacheHit_PATOwnerReadFails_RefusedNotServed: the owner re-read itself
// fails. That is indeterminate, so the request is refused 503 and the entry
// kept (CACHE-FAILCLOSED-1), the same contract as a failed token-row re-read
// (TestCacheHit_PATTransientStorageError_Refused).
func TestCacheHit_PATOwnerReadFails_RefusedNotServed(t *testing.T) {
	const raw = "kx_pat_validtoken"
	db, coreService, handler := cachedPATOwnerWorld(t, raw)

	require.NoError(t, db.Migrator().DropTable(&models.User{}))
	_, err := coreService.CurrentPATRestriction(t.Context(), raw)
	require.Error(t, err, "precondition: the owner re-read must actually fail")

	require.Equal(t, http.StatusServiceUnavailable, serveG18(handler, raw),
		"a failed owner re-read must refuse the request, not authenticate from the cache")
	requirePositiveCacheEntry(t, raw)
}

// TestCacheHit_PATOwnerActive_StillServed is the green calibration: an
// untouched active owner keeps a cached PAT working, so the deny cases above
// are caused by the owner change and not by the re-check itself.
func TestCacheHit_PATOwnerActive_StillServed(t *testing.T) {
	const raw = "kx_pat_validtoken"
	_, _, handler := cachedPATOwnerWorld(t, raw)

	require.Equal(t, http.StatusOK, serveG18(handler, raw), "an active owner's cached PAT is still served")
	require.Equal(t, http.StatusOK, serveG18(handler, raw))
}
