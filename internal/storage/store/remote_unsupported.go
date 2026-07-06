package store

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ErrRemoteUnsupported is returned by RemoteStorage methods whose operation has
// no server REST endpoint to proxy to. A round-119 completeness audit found
// that most of these are NOT the "a remote caller never invokes this directly"
// case an earlier version of this comment claimed — that assumption was
// verified false for the majority of stubs still remaining (several of their
// own per-method doc comments made the same false claim independently, e.g.
// GetGroupRoleGrants's). Every remaining stub is now exhaustively classified
// in remote_unsupported_completeness_test.go's remoteUnsupportedAllowlist as
// either genuinely permanent (statusIntentional, with a verified reason — no
// reachable caller exists, or a different mechanism already covers the need)
// or a confirmed, currently-reachable gap (statusKnownGap, tracked in
// docs/security/HARDENING-BACKLOG.md for a future fix round).
// TestRemoteUnsupportedStubsAreAllowlisted enforces that this list stays an
// exact, current match against the source — see that file before assuming any
// new stub is safe to leave unclassified.
//
// Callers can errors.Is against ErrRemoteUnsupported to distinguish "not
// supported in remote mode" from a genuine transport/API failure.
//
// Also wraps the backend-agnostic storage.ErrUnsupportedByBackend, so callers that
// only know about the storage.Storage interface (e.g. internal/core) can detect
// "this backend can never do this" without importing this concrete implementation
// package.
var ErrRemoteUnsupported = fmt.Errorf("operation not supported in remote (client) mode: %w", storage.ErrUnsupportedByBackend)

// remoteUnsupported wraps ErrRemoteUnsupported with the calling operation's name.
func remoteUnsupported(op string) error {
	return fmt.Errorf("%s: %w", op, ErrRemoteUnsupported)
}
