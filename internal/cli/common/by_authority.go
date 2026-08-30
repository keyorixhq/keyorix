package common

import (
	"errors"
	"fmt"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// ByAuthorityUnavailableError wraps the error from a --by authority check
// (core.Authorize, called by requireUserAuthority/requireInviteAuthority/
// requireReviewAuthority/requireTemplateAuthority) with a message an operator
// can act on.
//
// #1575: under storage.type: remote, core.Authorize always fails via
// RemoteStorage's permanently-stubbed GetUserRoleIDsAt/GetUserGroupRoleIDsAt/
// RoleSetHasPermission (ADR-086 — implementing them over the wire would be a
// fat-client authorization anti-pattern, so they stay stubbed). Before this,
// every one of the 11 affected commands (invite send/resend/revoke, migrate
// user-to-machine, request list/review, user revoke-sessions/suspend/
// reactivate/resend-setup-link/delete) surfaced that stub's raw, internal
// error text ("not supported in remote storage") with no indication of why
// or what to do instead. errors.Is against the shared ErrUnsupportedByBackend
// sentinel (which RemoteStorage's stubs now wrap, instead of a bare string —
// see remote_rbac.go) distinguishes this specific, permanent limitation from
// an ordinary "the resolved actor doesn't hold this permission" denial, which
// keeps its own message unchanged.
//
// alternative names what to do instead — a specific reachability finding from
// the #1575 investigation (every one of the 11 operations has an equivalent,
// ordinary, RBAC-gated HTTP route that works correctly with the operator's
// own real session, unlike storage.type: remote's shared static credential),
// not a generic "not supported."
func ByAuthorityUnavailableError(err error, alternative string) error {
	if !errors.Is(err, corestorage.ErrUnsupportedByBackend) {
		return fmt.Errorf("failed to verify --by authority: %w", err)
	}
	return fmt.Errorf("--by authority evaluation is not available against a remote backend (storage.type: remote): "+
		"the check depends on server-internal RBAC primitives RemoteStorage never implements, by design (ADR-086) — "+
		"%s", alternative)
}
