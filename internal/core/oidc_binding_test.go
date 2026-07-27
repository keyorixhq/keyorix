package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCreateOIDCBinding_RequiresGlobalAdminAuthority pins #127: (issuer, subject)
// is a GLOBAL namespace — GetMachineByOIDCSubject and the token-verify path
// resolve it with no project scoping — but binding creation previously required
// only project-scoped authority (the machine's own project). A project-A admin
// could pre-claim another team's well-known, not-yet-bound subject for their own
// machine; the victim workload's genuine token would then authenticate as the
// attacker's machine identity. Creating a binding must require GLOBAL admin
// authority, not merely membership/admin rights within the machine's project.
func TestCreateOIDCBinding_RequiresGlobalAdminAuthority(t *testing.T) {
	ctx := context.Background()
	machine := &models.MachineIdentity{ID: 5, ProjectID: 1, State: MachineActive}

	t.Run("project-scoped admin (no global authority) is refused", func(t *testing.T) {
		store := new(MockStorage)
		c := NewKeyorixCore(store)
		c.now = time.Now
		store.On("GetMachineIdentity", ctx, uint(5)).Return(machine, nil)
		// Actor 2 has NO role grants at global scope (project_id=0) — only within
		// project 1, which requireAuthorityForRole(..., projectID=0, ...) never sees.
		store.On("GetUserRoleIDsAt", ctx, uint(2), mock.MatchedBy(func(s interface{}) bool { return true })).Return([]uint{}, nil)
		store.On("GetUserGroupRoleIDsAt", ctx, uint(2), mock.MatchedBy(func(s interface{}) bool { return true })).Return([]uint{}, nil)

		_, err := c.CreateOIDCBinding(ctx, 1, 5, "https://idp.test", "system:serviceaccount:victim:ci", 2)
		require.Error(t, err)
		require.ErrorContains(t, err, "admin authority")
		store.AssertNotCalled(t, "CreateOIDCBinding", mock.Anything, mock.Anything)
	})

	t.Run("global admin authority succeeds", func(t *testing.T) {
		store := new(MockStorage)
		c := NewKeyorixCore(store)
		c.now = time.Now
		store.On("GetMachineIdentity", ctx, uint(5)).Return(machine, nil)
		store.On("GetRoleByName", ctx, mock.Anything).Return(&models.Role{ID: 99, Name: "system_admin"}, nil)
		store.On("GetUserRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{99}, nil)
		store.On("GetUserGroupRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{}, nil)
		store.On("CreateOIDCBinding", ctx, mock.MatchedBy(func(b *models.MachineIdentityOIDCBinding) bool {
			return b.MachineIdentityID == 5 && b.Issuer == "https://idp.test" && b.Subject == "system:serviceaccount:victim:ci"
		})).Return(&models.MachineIdentityOIDCBinding{ID: 1, MachineIdentityID: 5}, nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		b, err := c.CreateOIDCBinding(ctx, 1, 5, "https://idp.test", "system:serviceaccount:victim:ci", 1)
		require.NoError(t, err)
		require.NotNil(t, b)
	})
}
