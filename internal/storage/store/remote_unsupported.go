package store

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ErrRemoteUnsupported is returned by RemoteStorage methods whose operation has
// no server REST endpoint to proxy to. These fall into two groups: server-internal
// primitives that a remote (client-mode) caller never invokes directly — project
// membership lifecycle, access-request primitives, notification creation,
// low-level permission lookups — and a handful not yet exposed for client mode.
// (Group CRUD/membership and project-invitation primitives used to fall in this
// first category too, until each got its own thin /api/v1/system/* proxy route
// — see internal/storage/store/remote_users.go's Group section and
// remote_invitations.go's #507 doc comment.) Callers can errors.Is against it to
// distinguish "not supported in remote mode" from a genuine transport/API
// failure.
//
// The live data path for these features runs on the server (LocalStorage); the
// remote client reaches them through higher-level REST endpoints, not raw storage
// primitives, so faithful one-to-one proxying isn't possible.
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
