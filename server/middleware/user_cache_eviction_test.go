package middleware

// user_cache_eviction_test.go -- ERRLOSS-REVOKE-1. InvalidateUserTokenCache is the
// fail-closed fallback for the session-revocation paths in internal/core when the
// user's session-token hashes could not be listed: it must drop every cache entry of
// that user (session and PAT), and nothing else, without writing tombstones.

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

const evictTestUserID = 9001 // distinct from every other test's user id: userEvictedAt is process-wide

func forgetUserEvictionForTest(t *testing.T, ids ...uint) {
	t.Helper()
	t.Cleanup(func() {
		tokenCacheMu.Lock()
		for _, id := range ids {
			delete(userEvictedAt, id)
		}
		tokenCacheMu.Unlock()
	})
}

func TestInvalidateUserTokenCache_DropsOnlyThatUsersEntries(t *testing.T) {
	resetTokenCacheForTest(t)
	forgetUserEvictionForTest(t, evictTestUserID)
	exp := time.Now().Add(validTokenTTL)
	sess, pat := tokenKey("user-session"), tokenKey("kx_pat_user")
	other, machine := tokenKey("other-session"), tokenKey("kx_machine_x")
	cacheSetValidated(sess, &UserContext{UserID: evictTestUserID, SessionAuth: true}, time.Now(), exp)
	cacheSetValidated(pat, &UserContext{UserID: evictTestUserID}, time.Now(), exp)
	cacheSetValidated(other, &UserContext{UserID: evictTestUserID + 1}, time.Now(), exp)
	cacheSetValidated(machine, &UserContext{UserID: evictTestUserID, ActorType: core.ActorTypeMachine}, time.Now(), exp)

	InvalidateUserTokenCache(evictTestUserID)

	for name, key := range map[string]string{"session": sess, "pat": pat} {
		if e, ok := cacheGet(key); ok {
			t.Fatalf("the user's %s entry survived the per-user eviction (negative=%v); want a miss so it re-validates against storage", name, e.userCtx == nil)
		}
	}
	if e, ok := cacheGet(other); !ok || e.userCtx == nil {
		t.Fatal("another user's entry was evicted")
	}
	if e, ok := cacheGet(machine); !ok || e.userCtx == nil {
		t.Fatal("a machine entry was evicted by a human user's eviction")
	}
}

// A slow-path validation of the user's session that began BEFORE the eviction (its DB
// read may predate the revoke) and finishes after it must not re-cache a positive entry
// for a key that was not in the cache at eviction time: a per-key tombstone cannot cover
// that, which is why the eviction records the user and cacheSetValidatedGen checks it.
func TestInvalidateUserTokenCache_DropsInFlightPositiveForUncachedKey(t *testing.T) {
	resetTokenCacheForTest(t)
	forgetUserEvictionForTest(t, evictTestUserID)
	key := tokenKey("never-cached-session")
	validatedAt := time.Now()

	InvalidateUserTokenCache(evictTestUserID)

	cacheSetValidated(key, &UserContext{UserID: evictTestUserID, SessionAuth: true}, validatedAt, time.Now().Add(validTokenTTL))
	if _, ok := cacheGet(key); ok {
		t.Fatal("a validation that began before the eviction re-cached the revoked session")
	}

	// A validation that starts after the eviction caches normally: the user is not locked out.
	cacheSetValidated(key, &UserContext{UserID: evictTestUserID, SessionAuth: true}, time.Now(), time.Now().Add(validTokenTTL))
	if e, ok := cacheGet(key); !ok || e.userCtx == nil {
		t.Fatal("a post-eviction validation was not cached")
	}
}

func TestInvalidateUserTokenCache_ZeroUserIsANoOp(t *testing.T) {
	resetTokenCacheForTest(t)
	key := tokenKey("machine-like")
	cacheSetValidated(key, &UserContext{UserID: 0, MachineIdentityID: new(uint)}, time.Now(), time.Now().Add(validTokenTTL))
	InvalidateUserTokenCache(0)
	if e, ok := cacheGet(key); !ok || e.userCtx == nil {
		t.Fatal("user id 0 (federated/machine principals) must never be matched")
	}
}
