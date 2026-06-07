package store

import (
	"errors"
	"fmt"
)

// ErrRemoteUnsupported is returned by RemoteStorage methods whose operation has
// no server REST endpoint to proxy to. These fall into two groups: server-internal
// primitives that a remote (client-mode) caller never invokes directly — project
// membership lifecycle, invitation/access-request primitives, notification
// creation, group CRUD, low-level permission lookups — and a handful not yet
// exposed for client mode. Callers can errors.Is against it to distinguish
// "not supported in remote mode" from a genuine transport/API failure.
//
// The live data path for these features runs on the server (LocalStorage); the
// remote client reaches them through higher-level REST endpoints, not raw storage
// primitives, so faithful one-to-one proxying isn't possible.
var ErrRemoteUnsupported = errors.New("operation not supported in remote (client) mode")

// remoteUnsupported wraps ErrRemoteUnsupported with the calling operation's name.
func remoteUnsupported(op string) error {
	return fmt.Errorf("%s: %w", op, ErrRemoteUnsupported)
}
