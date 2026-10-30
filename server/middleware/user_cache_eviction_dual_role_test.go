package middleware

// user_cache_eviction_dual_role_test.go -- REVFIX-3777-1 leftover. A user can be BOTH
// the target of an impersonation session (UserID = user, ImpersonatedBy = admin) and an
// impersonator (UserID = victim, ImpersonatedBy = user) in the same cache.
// InvalidateUserTokenCache(user) must drop every one of those entries and the in-flight
// guard must refuse to re-cache any of them, without touching the other principals' own
// sessions. Pin only: userCacheEntryOf / userEvictedDuringLocked already match both roles.

import (
	"testing"
	"time"
)

func TestInvalidateUserTokenCache_UserBothImpersonationTargetAndImpersonator(t *testing.T) {
	resetTokenCacheForTest(t)
	const (
		userID  = evictTestUserID + 10 // the evicted user
		adminID = evictTestUserID + 11 // impersonates userID
		otherID = evictTestUserID + 12 // impersonated BY userID
	)
	forgetUserEvictionForTest(t, userID, adminID, otherID)
	user, admin := uint(userID), uint(adminID)
	exp := time.Now().Add(validTokenTTL)

	// Each context is built fresh per call: the cache stores the pointer.
	ownCtx := func() *UserContext { return &UserContext{UserID: userID, SessionAuth: true} }
	asTargetCtx := func() *UserContext { return &UserContext{UserID: userID, SessionAuth: true, ImpersonatedBy: &admin} }
	asImpersonatorCtx := func() *UserContext { return &UserContext{UserID: otherID, SessionAuth: true, ImpersonatedBy: &user} }
	adminOwnCtx := func() *UserContext { return &UserContext{UserID: adminID, SessionAuth: true} }
	otherOwnCtx := func() *UserContext { return &UserContext{UserID: otherID, SessionAuth: true} }

	evicted := map[string]func() *UserContext{
		"own":             ownCtx,
		"as-target":       asTargetCtx,
		"as-impersonator": asImpersonatorCtx,
	}
	survivors := map[string]func() *UserContext{
		"admin-own": adminOwnCtx,
		"other-own": otherOwnCtx,
	}
	cached := map[string]string{}
	for name, mk := range evicted {
		cached[name] = tokenKey("dual-cached-" + name)
		cacheSetValidated(cached[name], mk(), time.Now(), exp)
	}
	for name, mk := range survivors {
		cached[name] = tokenKey("dual-cached-" + name)
		cacheSetValidated(cached[name], mk(), time.Now(), exp)
	}
	validatedAt := time.Now() // slow-path validations that began before the eviction

	InvalidateUserTokenCache(userID)

	for name := range evicted {
		if _, ok := cacheGet(cached[name]); ok {
			t.Fatalf("%s entry survived the eviction of a user who is both impersonation target and impersonator", name)
		}
	}
	for name := range survivors {
		if e, ok := cacheGet(cached[name]); !ok || e.userCtx == nil {
			t.Fatalf("%s entry of an unrelated principal was evicted", name)
		}
	}

	// In-flight validations that predate the eviction must not resurrect any role's entry.
	for name, mk := range evicted {
		key := tokenKey("dual-inflight-" + name)
		cacheSetValidated(key, mk(), validatedAt, exp)
		if _, ok := cacheGet(key); ok {
			t.Fatalf("in-flight %s validation re-cached after the eviction (resurrection)", name)
		}
	}

	// A validation starting strictly after the eviction caches normally for every role:
	// the guard fails closed for the old window only, it does not lock the user out.
	after := evictedAtForTest(t, userID).Add(time.Nanosecond)
	for name, mk := range evicted {
		key := tokenKey("dual-after-" + name)
		cacheSetValidated(key, mk(), after, exp)
		if e, ok := cacheGet(key); !ok || e.userCtx == nil {
			t.Fatalf("post-eviction %s validation was not cached", name)
		}
	}
}
