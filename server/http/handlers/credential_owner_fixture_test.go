package handlers

// credential_owner_fixture_test.go — handler-layer counterpart of
// internal/storage/store/credential_owner_test_seed_test.go (#2701).
//
// CreatePersonalAccessToken / CreateSession / RotateSession re-read the owning
// user inside the insert's transaction and roll back unless it is a live,
// login-capable account (requireLiveCredentialOwner). freshCoreS12 migrates
// `users` but never creates the acting user that withUserCtx claims (UserID=1),
// so a handler test that mints a PAT for that user was minting a credential with
// no owner: a state production cannot reach, since the actor has already been
// authenticated by the time a handler runs.
//
// This is a SEPARATE fixture, used only by the tests that create a credential,
// rather than seeding inside freshCoreS12 itself. Seeding user 1 in the shared
// fixture was tried and broke TestAddGroupMember_GroupNotFound_S13 and
// TestUpdateProfile_EmailAlreadyInUse_S13, which share freshCoreS12 and depend on
// user 1 NOT existing. A fixture fix must not perturb unrelated tests to satisfy
// its own.
//
// It is deliberately a fixture fix, not a weakening of the re-check: "the owner
// does not exist" is the strongest case of the owner not being usable.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// freshCoreS12WithCredentialOwners is freshCoreS12 plus an active,
// login-capable user row for each of ids, so a test that creates a PAT or a
// session for one of those ids has an owner for it.
func freshCoreS12WithCredentialOwners(t *testing.T, ids ...uint) *core.KeyorixCore {
	t.Helper()
	require.NotEmpty(t, ids, "name the user ids the test creates credentials for")
	ls := freshLocalStorageS12(t)
	for _, id := range ids {
		name := fmt.Sprintf("cred-owner-%d", id)
		u := &models.User{
			ID:             id,
			Username:       name,
			UsernameFolded: name,
			Email:          name + "@example.test",
			EmailFolded:    name + "@example.test",
			IsActive:       true,
			AccountState:   "active",
		}
		require.NoError(t, ls.DB().Create(u).Error)
	}
	return core.NewKeyorixCore(ls)
}
