// secret_acl_grant_member_removed_test.go — #4533, the single-process half:
// GrantSecretACL's membership pre-check passes, the grantee's project grants are
// removed before the ACL upsert runs, and the grant must still be refused with the
// same invalid-request error a serial remove-then-grant gets, leaving no ACL row.
//
// The cross-replica race itself (RemoveProjectMember committing on another replica
// between the pre-check and the upsert) is proven on Postgres by
// TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres and the
// race loop in cta_review_liveness_race_loop_postgres_test.go. This test drives the
// same storage path on SQLite through a hook, so the default CI run guards the
// mechanism (the write-then-check in LocalStorage.CreateOrUpdateSecretACL and core's
// mapping of storage.ErrSecretACLGranteeNotMember) without a second database.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// grantACLMemberFixture: a project with one environment, alice a project_viewer
// member, and an admin-owned secret alice holds no grant on.
func grantACLMemberFixture(t *testing.T) (c *KeyorixCore, projectID, aliceID, actorID, secretID uint) {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const actor = uint(1) // the bootstrapped admin

	alice, err := st.CreateUser(ctx, foldedTestUser(t, "alice-acl", "alice-acl@example.com"))
	require.NoError(t, err)
	proj, err := c.CreateProject(ctx, "acl-member-proj", "")
	require.NoError(t, err)
	env, err := c.CreateEnvironment(ctx, proj.ID, "prod")
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj.ID, alice.ID, "project_viewer", false))

	s, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "acl-target", ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "password", IsSecret: true, Status: "active", Classification: "internal", OwnerID: actor,
	})
	require.NoError(t, err)
	return c, proj.ID, alice.ID, actor, s.ID
}

// TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow: the hook
// removes alice's project grants on the transaction handle immediately before the
// ACL upsert, i.e. after GrantSecretACL's own IsProjectMember read said "member".
//
// Red before the fix: the upsert committed and the grant succeeded for a user with
// no grant at the project (an ACL row RemoveProjectMember's cascade never saw).
// Green: the storage re-check after the write refuses, the transaction rolls back,
// and core answers the serial remove-then-grant refusal (ErrInvalidSecretACLRequest).
func TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow(t *testing.T) {
	t.Parallel()
	c, projectID, aliceID, actorID, secretID := grantACLMemberFixture(t)
	base := c.storage
	removed := false
	c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		CreateOrUpdateSecretACL: func(next storage.Storage, ctx context.Context, acl *models.SecretACL) error {
			if err := next.RemoveAllProjectRoleGrants(ctx, acl.UserID, projectID); err != nil {
				return err
			}
			removed = true
			return next.CreateOrUpdateSecretACL(ctx, acl)
		},
	})

	ctx := context.Background()
	err := c.GrantSecretACL(ctx, actorID, secretID, aliceID, []string{"secrets.read"})
	require.True(t, removed, "the hook must have removed the membership before the upsert")
	require.Error(t, err, "CWE-284: an ACL grant committed for a user who is no longer a project member")
	assert.ErrorIs(t, err, storage.ErrInvalidSecretACLRequest, "the refusal must be the one a serial remove-then-grant gets")

	acls, lerr := base.ListSecretACLs(ctx, secretID)
	require.NoError(t, lerr)
	assert.Empty(t, acls, "the refused grant must have left no ACL row")
	// The removal ran inside the grant's own transaction here, so rolling the grant
	// back rolled it back too: alice is still a member. (On Postgres, with the
	// removal on another replica, she stays removed; the point is the atomicity.)
	member, merr := c.IsProjectMember(ctx, aliceID, projectID)
	require.NoError(t, merr)
	assert.True(t, member, "the refusal must roll the whole transaction back")
}

// TestGrantSecretACL_MemberGrantee_StillGranted: the control. With the membership
// in place the re-check passes and the grant commits as before.
func TestGrantSecretACL_MemberGrantee_StillGranted(t *testing.T) {
	t.Parallel()
	c, _, aliceID, actorID, secretID := grantACLMemberFixture(t)
	ctx := context.Background()
	require.NoError(t, c.GrantSecretACL(ctx, actorID, secretID, aliceID, []string{"secrets.read"}))
	ok, err := c.HasSecretACL(ctx, aliceID, secretID, "secrets.read")
	require.NoError(t, err)
	assert.True(t, ok)
}
