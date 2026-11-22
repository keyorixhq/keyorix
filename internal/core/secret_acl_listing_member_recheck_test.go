// secret_acl_listing_member_recheck_test.go — #4623: the secret listing
// (ListSecretsWithSharingInfo -> getACLGrantedSecretsWithSharingInfo) must honour
// an ACL grant only while its grantee is a live member of the granted node's
// project, the rule aclGrantsPermission (#G13) and batchACLStage apply when they
// authorize. Only RemoveProjectMember deletes a user's ACL rows; RemoveUserRole of
// a member's only project role leaves them, and before the fix the listing kept
// showing those secrets' metadata (and every descendant of a folder grant) to the
// former member.
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

// aclListedNames is every secret name ListSecretsWithSharingInfo returns for userID.
func aclListedNames(t *testing.T, c *KeyorixCore, userID uint) []string {
	t.Helper()
	resp, err := c.ListSecretsWithSharingInfo(context.Background(), userID, &models.SecretListFilter{Page: 1, PageSize: 100})
	require.NoError(t, err)
	var names []string
	for _, s := range resp.Secrets {
		names = append(names, s.Name)
	}
	return names
}

// revokeOnlyProjectRole removes alice's project_viewer grant at projectID through
// the core path an admin uses (DELETE /user-roles), which does not touch ACL rows.
func revokeOnlyProjectRole(t *testing.T, c *KeyorixCore, actorID, aliceID, projectID uint) {
	t.Helper()
	ctx := context.Background()
	role, err := c.storage.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, c.RemoveUserRole(ctx, actorID, aliceID, role.ID, Scope{ProjectID: projectID}))
	member, err := c.IsProjectMember(ctx, aliceID, projectID)
	require.NoError(t, err)
	require.False(t, member, "fixture: alice must no longer be a project member")
}

// TestSecretListing_ACLGrantOfRemovedMemberNotListed: red before the fix
// (listed=[acl-target] with member=false and HasSecretACL=false).
func TestSecretListing_ACLGrantOfRemovedMemberNotListed(t *testing.T) {
	t.Parallel()
	c, projectID, aliceID, actorID, secretID := grantACLMemberFixture(t)
	ctx := context.Background()
	require.NoError(t, c.GrantSecretACL(ctx, actorID, secretID, aliceID, []string{"secrets.read"}))
	require.Contains(t, aclListedNames(t, c, aliceID), "acl-target", "control: a member sees the ACL-granted secret")

	revokeOnlyProjectRole(t, c, actorID, aliceID, projectID)

	acls, err := c.storage.ListSecretACLsByUser(ctx, aliceID)
	require.NoError(t, err)
	require.Len(t, acls, 1, "fixture: the ACL row must survive RemoveUserRole, or this case proves nothing")
	has, err := c.HasSecretACL(ctx, aliceID, secretID, "secrets.read")
	require.NoError(t, err)
	require.False(t, has, "authorization already refuses the stale grant (#G13)")

	assert.NotContains(t, aclListedNames(t, c, aliceID), "acl-target",
		"CWE-284: the listing must not disclose a secret through an ACL grant its grantee no longer holds as a member")
}

// TestSecretListing_FolderACLGrantOfRemovedMemberListsNoDescendant: the folder
// expansion (applyACLGrant -> collectFolderDescendants) is behind the same check.
func TestSecretListing_FolderACLGrantOfRemovedMemberListsNoDescendant(t *testing.T) {
	t.Parallel()
	c, projectID, aliceID, actorID, secretID := grantACLMemberFixture(t)
	ctx := context.Background()
	target, err := c.storage.GetSecret(ctx, secretID)
	require.NoError(t, err)
	folder, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "acl-folder", ProjectID: projectID, EnvironmentID: target.EnvironmentID,
		Type: "generic", IsSecret: false, Status: "active", OwnerID: actorID,
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "acl-folder-child", ProjectID: projectID, EnvironmentID: target.EnvironmentID, ParentID: &folder.ID,
		Type: "password", IsSecret: true, Status: "active", Classification: "internal", OwnerID: actorID,
	})
	require.NoError(t, err)
	require.NoError(t, c.GrantSecretACL(ctx, actorID, folder.ID, aliceID, []string{"secrets.read"}))
	require.Contains(t, aclListedNames(t, c, aliceID), "acl-folder-child", "control: a member sees the folder's descendants")

	revokeOnlyProjectRole(t, c, actorID, aliceID, projectID)

	assert.NotContains(t, aclListedNames(t, c, aliceID), "acl-folder-child",
		"CWE-284: a folder ACL of a removed member must not list its descendants")
}

// TestSecretListing_ACLMembershipReadFaultFailsTheListing: the membership read is
// fail-closed. A fault must fail the listing, never list the grant unchecked and
// never drop it silently behind a success.
func TestSecretListing_ACLMembershipReadFaultFailsTheListing(t *testing.T) {
	t.Parallel()
	c, _, aliceID, actorID, secretID := grantACLMemberFixture(t)
	ctx := context.Background()
	require.NoError(t, c.GrantSecretACL(ctx, actorID, secretID, aliceID, []string{"secrets.read"}))

	driverErr := errors.New("driver: bad connection")
	faulty := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "ProjectMembershipsAmong", NthCall: 1, Kind: faultstorage.KindError, Err: driverErr,
	})
	c2 := newACLCoreWithStorage(c, faulty)
	resp, err := c2.ListSecretsWithSharingInfo(ctx, aliceID, &models.SecretListFilter{Page: 1, PageSize: 100})
	require.True(t, faulty.Fired(), "the listing must read the grantee's membership, or this case proves nothing")
	require.Error(t, err, "a membership read fault must fail the listing")
	assert.ErrorIs(t, err, driverErr)
	assert.Nil(t, resp)
}
