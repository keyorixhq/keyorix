// migrate_authorize_error_test.go — closes the two remaining branches inside
// requireMigrationAuthority (user_to_machine.go) where svc.Authorize itself
// returns a genuine storage-layer error (not merely "not authorized") for the
// roles.assign check and, separately, the users.write check.
//
// Neither branch is reachable by manipulating account state or permission
// grants alone: a canceled context fails the earlier AccountStillUsable check
// first (see TestRequireMigrationAuthority_AuthorizeErrorFirstCall in
// migrate_s3_test.go), and Authorize's only error surface is a genuine
// storage-layer failure inside scopedRoleIDs/roleSetContainsAdmin — see the
// extensive commentary on TestRequireMigrationAuthority_AuthorizeErrorSecondCall
// in migrate_s3_test.go, which concludes this needs "internal access" to
// trigger cleanly. This file supplies that access from outside core/storage by
// wrapping the storage.Storage interface core.NewKeyorixCore already accepts,
// injecting a targeted failure into GetUserRoleIDsAt (the first call
// scopedRoleIDs makes) on a chosen invocation, while every other storage call —
// including the ones AccountStillUsable and the untouched Authorize calls
// need — passes through to the real, fully-functional underlying storage.
package migrate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// roleIDsFailingStorage wraps a real storage.Storage and forces
// GetUserRoleIDsAt to fail starting from the failFromCall'th invocation
// (1-indexed) onward; every call before that, and every other method, is
// delegated unmodified to the embedded real implementation.
type roleIDsFailingStorage struct {
	corestorage.Storage
	calls        atomic.Int32
	failFromCall int32
}

func (s *roleIDsFailingStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope corestorage.Scope) ([]uint, error) {
	n := s.calls.Add(1)
	if n >= s.failFromCall {
		return nil, errors.New("injected storage failure")
	}
	return s.Storage.GetUserRoleIDsAt(ctx, userID, scope)
}

// TestRequireMigrationAuthority_RolesAssignAuthorizeErrors exercises the
// error return of the FIRST svc.Authorize call (roles.assign,
// user_to_machine.go:119-122): AccountStillUsable succeeds (it only calls
// GetUser, untouched by the wrapper), but the very first GetUserRoleIDsAt call
// — made by scopedRoleIDs inside Authorize's roles.assign check — fails, so
// Authorize itself returns a genuine error rather than (false, nil).
func TestRequireMigrationAuthority_RolesAssignAuthorizeErrors(t *testing.T) {
	_, st := newBootstrappedCore(t)
	ctx := context.Background()

	bareUser := seedUserWithRole(t, st, "wrap-roles-assign-actor", "project_viewer", core.Scope{ProjectID: 1})

	wrapped := &roleIDsFailingStorage{Storage: st, failFromCall: 1}
	wrappedCore := core.NewKeyorixCore(wrapped)

	err := requireMigrationAuthority(ctx, wrappedCore, bareUser, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
	assert.Contains(t, err.Error(), "injected storage failure")
	// Exactly one GetUserRoleIDsAt call happened before the error propagated —
	// proving this is the FIRST Authorize call's error surface, not the second.
	assert.Equal(t, int32(1), wrapped.calls.Load())
}

// TestRequireMigrationAuthority_UsersWriteAuthorizeErrors exercises the error
// return of the SECOND svc.Authorize call (users.write,
// user_to_machine.go:126-129). The actor holds the global admin role, so the
// first Authorize call (roles.assign at the project scope) succeeds using one
// real, unwrapped GetUserRoleIDsAt call; only the SECOND invocation — made for
// the users.write check at global scope — is forced to fail.
func TestRequireMigrationAuthority_UsersWriteAuthorizeErrors(t *testing.T) {
	_, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin := seedUserWithRole(t, st, "wrap-users-write-actor", "admin", core.Scope{})

	wrapped := &roleIDsFailingStorage{Storage: st, failFromCall: 2}
	wrappedCore := core.NewKeyorixCore(wrapped)

	err := requireMigrationAuthority(ctx, wrappedCore, admin, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify --by authority")
	assert.Contains(t, err.Error(), "injected storage failure")
	// Two GetUserRoleIDsAt calls happened: the first (roles.assign) succeeded
	// via the real storage, the second (users.write) is the one that errored —
	// proving this is genuinely the SECOND Authorize call's error surface.
	assert.Equal(t, int32(2), wrapped.calls.Load())
}
