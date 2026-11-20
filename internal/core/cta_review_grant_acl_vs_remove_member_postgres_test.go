// cta_review_grant_acl_vs_remove_member_postgres_test.go — #4533, the second variant
// #2649 names: GrantSecretACL racing RemoveProjectMember(grantee). #2785 closed the
// DeleteSecret half; this half is open, so the test is skipped with its issue.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres: B's
// RemoveProjectMember commits between A's membership check and A's ACL upsert. B's
// DeleteSecretACLsByUserAndProject ran before the grant existed, so the grant commits
// for a non-member. Authorization stays denied while they are out (HasSecretACL and
// batchACLStage re-check membership, #G13), but the row is not inert:
// ListSecretsWithSharingInfo's ACL source (applyACLGrant) does not re-check membership,
// so the removed user still lists the secret's metadata (for a folder grant, every
// descendant), and the grant is live again when an admin re-adds them. Neither serial
// order leaves an ACL row for a removed member, which is the invariant asserted here;
// the listing and re-add checks below make the eventual fix prove both consequences.
//
// B runs synchronously inside A's GORM hook. If the fix takes a lock B needs before
// A's upsert, this hangs to the timeout instead of failing: switch to beforeA plus a
// goroutine for B then.
func TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres(t *testing.T) {
	t.Skip("#4533: GrantSecretACL's membership check is not serialized against RemoveProjectMember's ACL cascade")
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclmember", "project_viewer")
	s := f.secret("cta-aclmember-secret", f.adminID)

	var errB error
	fired := f.beforeA("create", "secret_acls", func() {
		errB = f.coreB.RemoveProjectMember(f.ctx, f.adminID, f.projectID, grantee.ID)
	})
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	t.Logf("GrantSecretACL (A) err=%v, RemoveProjectMember (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's RemoveProjectMember before A's ACL upsert")
	require.NoError(t, errB)

	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ? AND user_id = ?", s.ID, grantee.ID),
		"CWE-284: an ACL grant survives for a user removed from the project")

	// While removed, the stale grant must not list the secret's metadata either.
	listed, err := f.setup.ListSecretsWithSharingInfo(f.ctx, grantee.ID, &models.SecretListFilter{})
	require.NoError(t, err)
	for _, ls := range listed.Secrets {
		assert.NotEqual(t, s.ID, ls.ID, "a removed member still lists an ACL-granted secret's metadata")
	}

	// The consequence: re-adding the member brings the removed grant back.
	role, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRole(f.ctx, grantee.ID, role.ID, Scope{ProjectID: f.projectID}))
	ok, err := f.setup.HasSecretACL(f.ctx, grantee.ID, s.ID, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok, "re-adding a removed member reactivated an ACL grant the removal revoked")
}
