package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestOwnerWithoutSecretsWrite_CannotSetTagsDescriptionOrMove is #4508: the owner
// pass alone must not authorize SetSecretTags, SetSecretDescription or MoveSecret.
// REST gates all three on secrets.write with no owner pass, so a project viewer who
// owns a secret is refused there; core now refuses it too (the known-03 pattern
// #4160 closed for update and delete). The project-developer owner is the positive
// control: the same calls succeed for an owner whose role grants secrets.write.
func TestOwnerWithoutSecretsWrite_CannotSetTagsDescriptionOrMove(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		role    string
		allowed bool
	}{
		{"project_viewer", false},
		{"project_developer", true},
	} {
		t.Run(tc.role, func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()

			proj, err := st.CreateProject(ctx, &models.Project{Name: "owner-gate-" + tc.role})
			require.NoError(t, err)
			owner, err := st.CreateUser(ctx, foldedTestUser(t, "owner-"+tc.role, "owner-"+tc.role+"@example.com"))
			require.NoError(t, err)
			role, err := st.GetRoleByName(ctx, tc.role)
			require.NoError(t, err)
			require.NoError(t, st.AssignRole(ctx, owner.ID, role.ID, storage.Scope{ProjectID: proj.ID}))
			secret, err := st.CreateSecret(ctx, &models.SecretNode{
				Name: "owned", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
				IsSecret: true, OwnerID: owner.ID, Status: "active",
			})
			require.NoError(t, err)

			_, tagErr := c.SetSecretTags(ctx, secret.ID, owner.ID, []string{"prod"})
			_, descErr := c.SetSecretDescription(ctx, owner.ID, secret.ID, "changed")
			_, moveErr := c.MoveSecret(ctx, owner.ID, secret.ID, nil)

			after, err := st.GetSecret(ctx, secret.ID)
			require.NoError(t, err)
			tags, err := st.GetSecretTags(ctx, secret.ID)
			require.NoError(t, err)
			if tc.allowed {
				require.NoError(t, tagErr)
				require.NoError(t, descErr)
				require.NoError(t, moveErr)
				require.Equal(t, "changed", after.Description)
				require.Equal(t, []string{"prod"}, tags)
				return
			}
			require.ErrorIs(t, tagErr, ErrPermissionDenied, "SetSecretTags")
			require.ErrorIs(t, descErr, ErrPermissionDenied, "SetSecretDescription")
			require.ErrorIs(t, moveErr, ErrPermissionDenied, "MoveSecret")
			require.Empty(t, after.Description, "the description is unchanged")
			require.Empty(t, tags, "no tag was written")
		})
	}
}
