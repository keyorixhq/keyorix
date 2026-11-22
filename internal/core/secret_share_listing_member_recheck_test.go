// secret_share_listing_member_recheck_test.go — REVIEW-4628 M1: the share term of the
// secret listing (ListSecretsWithSharingInfo -> getSharedSecretsWithSharingInfo, and
// the decoration path sharedSecretDecorations) must list a received share only while
// its recipient is a live member of the shared secret's project, the rule
// batchShareStage applies when it authorizes. No path deletes a recipient's share rows
// when membership ends (RemoveProjectMember deletes only ACL rows), so before the fix
// the listing kept showing the secret's metadata to a former member.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// shareListingFixture shares "acl-target" (owned by the admin) read-only with alice,
// a project_viewer, and returns the pieces the cases need.
func shareListingFixture(t *testing.T) (c *KeyorixCore, projectID, aliceID, actorID uint) {
	t.Helper()
	c, projectID, aliceID, actorID, secretID := grantACLMemberFixture(t)
	// The fixture's owner is the global admin, who is a member of no project and so
	// cannot pass ShareSecret's owner gate; the row ShareSecret would write is created
	// directly, which is all the listing reads.
	_, err := c.storage.CreateShareRecord(context.Background(), &models.ShareRecord{
		SecretID: secretID, OwnerID: actorID, RecipientID: aliceID, Permission: "read",
	})
	require.NoError(t, err)
	return c, projectID, aliceID, actorID
}

// TestSecretListing_ShareOfRemovedMemberNotListed: red before the fix (the listing
// still returned acl-target with member=false). Both ways a membership ends without
// touching share rows are covered.
func TestSecretListing_ShareOfRemovedMemberNotListed(t *testing.T) {
	t.Parallel()
	t.Run("RemoveUserRole", func(t *testing.T) {
		t.Parallel()
		c, projectID, aliceID, actorID := shareListingFixture(t)
		require.Contains(t, aclListedNames(t, c, aliceID), "acl-target", "control: a member sees the shared secret")

		revokeOnlyProjectRole(t, c, actorID, aliceID, projectID)

		assert.NotContains(t, aclListedNames(t, c, aliceID), "acl-target",
			"CWE-284: the listing must not disclose a secret through a share its recipient no longer holds as a member")
	})
	t.Run("RemoveProjectMember", func(t *testing.T) {
		t.Parallel()
		c, projectID, aliceID, actorID := shareListingFixture(t)
		require.Contains(t, aclListedNames(t, c, aliceID), "acl-target", "control: a member sees the shared secret")

		require.NoError(t, c.RemoveProjectMember(context.Background(), actorID, projectID, aliceID))
		member, err := c.IsProjectMember(context.Background(), aliceID, projectID)
		require.NoError(t, err)
		require.False(t, member, "fixture: alice must no longer be a project member")

		assert.NotContains(t, aclListedNames(t, c, aliceID), "acl-target",
			"CWE-284: RemoveProjectMember leaves share rows, so the listing must re-check membership")
	})
}

// TestSecretListing_ShareMembershipReadFaultFailsTheListing: the membership read is
// fail-closed, as on the ACL term. A user with only a share must get an error and a
// nil response, never an unchecked row and never a silent empty list.
func TestSecretListing_ShareMembershipReadFaultFailsTheListing(t *testing.T) {
	t.Parallel()
	c, _, aliceID, _ := shareListingFixture(t)
	ctx := context.Background()

	driverErr := errors.New("driver: bad connection")
	faulty := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "ProjectMembershipsAmong", NthCall: 1, Kind: faultstorage.KindError, Err: driverErr,
	})
	c2 := newACLCoreWithStorage(c, faulty)
	resp, err := c2.ListSecretsWithSharingInfo(ctx, aliceID, &models.SecretListFilter{Page: 1, PageSize: 100})
	require.True(t, faulty.Fired(), "the listing must read the recipient's membership, or this case proves nothing")
	require.Error(t, err, "a membership read fault must fail the listing")
	assert.ErrorIs(t, err, driverErr)
	assert.Nil(t, resp)
}
