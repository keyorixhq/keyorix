package store

import (
	"context"
	"time"
)

// Login rate limiting is server-side only (ADR-040) — the limiter runs in the
// server's auth handlers against LocalStorage; a remote (client) caller never
// records or counts attempts.
//
// #452: this also fires when the SERVER itself is booted with storage.type: remote
// (a chained deployment proxying to an upstream Keyorix server via
// internal/storage/factory.go's createRemoteStorage) — the local server's own
// server/http/handlers/auth.go still calls IsLoginRateLimited/RecordFailedLogin
// against ITS OWN storage on every login, so these three methods are on the hot
// path there too, not just an unreachable client-mode corner.
//
// A real proxied implementation (having the upstream server expose a login-attempt
// counter/record REST endpoint for a downstream server to call) was considered and
// rejected for this PR: no such endpoint exists today, and the upstream server's
// own login_attempts table is scoped to rate-limiting ITS OWN direct /auth/login
// traffic (ADR-040) — reusing it for a downstream server's unrelated per-IP budget
// would need a new endpoint, a new authorization model for a system-to-system
// (not end-user) caller, and versioned API/client wiring on both sides. That is a
// legitimate architectural improvement but is materially bigger than this
// security-hardening PR's scope (#452, HIGH: silent fail-open, not silent-and-
// unfixable). Instead, CountRecentLoginAttempts continues to return the
// ErrRemoteUnsupported/ErrUnsupportedByBackend sentinel, and the caller
// (internal/core/rate_limit.go) now logs a loud, one-time operator warning the
// first time it observes this sentinel, rather than failing open with zero
// visibility. Fail-open itself is unavoidable without the real proxy above (rate
// limiting is a backstop, not the primary auth boundary) — this closes the
// "silent" half of the gap, not the "fails open" half.
func (rs *RemoteStorage) RecordLoginAttempt(_ context.Context, _ string, _ time.Time) error {
	return remoteUnsupported("RecordLoginAttempt")
}
func (rs *RemoteStorage) CountRecentLoginAttempts(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("CountRecentLoginAttempts")
}
func (rs *RemoteStorage) PruneLoginAttempts(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PruneLoginAttempts")
}
