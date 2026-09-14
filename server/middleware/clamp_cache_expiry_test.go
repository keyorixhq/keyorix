package middleware

import (
	"testing"
	"time"
)

// TestClampCacheExpiry covers the F-TOK-1 decision in isolation: a session's positive
// auth-cache entry must never outlive the session itself, while a non-session token (nil
// expiry) or a session outliving the cache window keeps the normal validTokenTTL bound.
func TestClampCacheExpiry(t *testing.T) {
	base := time.Now().Add(30 * time.Second)

	// Non-session token (nil session expiry): the normal cache window stands.
	if got := clampCacheExpiry(base, nil); !got.Equal(base) {
		t.Errorf("nil sessionExpiry must leave base unchanged, got %v", got)
	}

	// Session expires BEFORE the cache window ends: clamp the entry to the session expiry,
	// so the entry can't authenticate past the session's own expiry on a cache hit.
	sooner := base.Add(-20 * time.Second)
	if got := clampCacheExpiry(base, &sooner); !got.Equal(sooner) {
		t.Errorf("a session expiring before base must clamp the entry to the session expiry; got %v want %v", got, sooner)
	}

	// Session outlives the cache window: the shorter validTokenTTL bound is kept
	// (revocation is still caught by the every-hit re-check + explicit eviction).
	later := base.Add(time.Hour)
	if got := clampCacheExpiry(base, &later); !got.Equal(base) {
		t.Errorf("a session expiring after base must leave the shorter cache window in place, got %v", got)
	}
}
