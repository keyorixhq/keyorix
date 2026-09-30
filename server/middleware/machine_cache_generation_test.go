package middleware

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

func resetTokenCacheForTest(t *testing.T) {
	t.Helper()
	tokenCacheMu.Lock()
	tokenCache = map[string]tokenCacheEntry{}
	tokenCacheMu.Unlock()
}

// A slow-path validation for a machine token that was NOT cached when
// InvalidateAllMachineTokenCache ran, and whose DB read predates the revoke,
// must not cache its (now stale) positive result. A per-key tombstone can't
// catch this because no entry for the key existed at flush time.
func TestMachineFlush_DropsInFlightPositiveForUncachedKey(t *testing.T) {
	resetTokenCacheForTest(t)
	key := tokenKey("kxm_inflight")
	validatedAt := time.Now()
	gen := currentMachineCacheGen() // captured before the (simulated) DB read

	InvalidateAllMachineTokenCache() // revoke committed + fallback flush

	machine := &UserContext{UserID: 42, ActorType: core.ActorTypeMachine}
	cacheSetValidatedGen(key, machine, validatedAt, gen, time.Now().Add(validTokenTTL))
	if _, ok := cacheGet(key); ok {
		t.Fatal("in-flight positive from before the flush was cached; revoked token would live for validTokenTTL")
	}

	// A validation that starts after the flush caches normally.
	cacheSetValidatedGen(key, machine, time.Now(), currentMachineCacheGen(), time.Now().Add(validTokenTTL))
	if e, ok := cacheGet(key); !ok || e.userCtx == nil {
		t.Fatal("post-flush validation was not cached")
	}
}

// After a flush, other machines' entries are misses (so they re-validate and
// succeed), not negative hits; human entries are untouched.
func TestMachineFlush_NoNegativeEntriesAndHumansUntouched(t *testing.T) {
	resetTokenCacheForTest(t)
	mKey, hKey := tokenKey("kxm_bystander"), tokenKey("session_human")
	exp := time.Now().Add(validTokenTTL)
	cacheSetValidated(mKey, &UserContext{UserID: 7, ActorType: core.ActorTypeMachine}, time.Now(), exp)
	cacheSetValidated(hKey, &UserContext{UserID: 1}, time.Now(), exp)

	InvalidateAllMachineTokenCache()

	if e, ok := cacheGet(mKey); ok {
		t.Fatalf("bystander machine entry still present after flush (negative=%v); want a miss", e.userCtx == nil)
	}
	if e, ok := cacheGet(hKey); !ok || e.userCtx == nil {
		t.Fatal("human entry was affected by the machine flush")
	}
}

// A machine entry stamped with an older generation is a miss even if it is
// somehow still in the map.
func TestMachineFlush_OldGenerationEntryIsMiss(t *testing.T) {
	resetTokenCacheForTest(t)
	key := tokenKey("kxm_old")
	tokenCacheMu.Lock()
	tokenCache[key] = tokenCacheEntry{
		userCtx:    &UserContext{UserID: 9, ActorType: core.ActorTypeMachine},
		expiresAt:  time.Now().Add(validTokenTTL),
		machineGen: machineCacheGen,
	}
	machineCacheGen++
	tokenCacheMu.Unlock()
	if _, ok := cacheGet(key); ok {
		t.Fatal("machine entry from an older generation was served")
	}
}
