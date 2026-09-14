// idp_autogrant_escalation_test.go — the shared backstop for IdP-DRIVEN automatic role
// grants (SSO GroupRoleMap reconciliation + SCIM/SSO group-membership conferral), from the
// 2026-09-14 adversarial review (F-RBAC-1). These auto-grants deliberately skip the normal
// grant-ceiling (a first-login user can't pre-hold the role's permissions), so
// idpAutoGrantOfRoleIsEscalation is the only thing standing between a self-service IdP group
// and an escalation. Before this it was inconsistent (SSO checked the admin NAME, SCIM the
// bypass FLAG) and both missed a custom role bundling roles.assign under a plain name. Both
// directions asserted, including the usability case that must stay OPEN.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestIDPAutoGrantOfRoleIsEscalation(t *testing.T) {
	t.Parallel()

	t.Run("canonical admin role name is blocked (short-circuits, no storage lookup)", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		assert.True(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 1, "system_admin"))
	})

	t.Run("admin-bypass-flag role is blocked", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{2}).Return(true, nil)
		c := NewKeyorixCore(ms)
		assert.True(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 2, "custom-bypass"))
	})

	t.Run("role carrying roles.assign is blocked regardless of a benign name", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{3}).Return(false, nil)
		ms.On("GetRolePermissions", mock.Anything, uint(3)).Return([]*models.Permission{
			{Name: permSecretsRead}, {Name: permRolesAssign},
		}, nil)
		c := NewKeyorixCore(ms)
		assert.True(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 3, "deployer"),
			"a self-service IdP group must not be mappable to a role that can itself grant roles (a privilege pump)")
	})

	t.Run("ordinary privileged role (incl. system.write) stays ALLOWED — no Vault-style friction", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{4}).Return(false, nil)
		ms.On("GetRolePermissions", mock.Anything, uint(4)).Return([]*models.Permission{
			{Name: permSecretsRead}, {Name: permSecretsWrite}, {Name: "system.write"},
		}, nil)
		c := NewKeyorixCore(ms)
		assert.False(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 4, "ops"),
			"an ordinary privileged role is the admin's legitimate mapping intent and must remain IdP-mappable")
	})

	t.Run("fails closed when the permission lookup errors", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{5}).Return(false, nil)
		ms.On("GetRolePermissions", mock.Anything, uint(5)).Return(nil, errors.New("db down"))
		c := NewKeyorixCore(ms)
		assert.True(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 5, "unknown"),
			"an inability to verify the role's permissions must refuse the auto-grant, not open it")
	})

	t.Run("fails closed when the bypass-flag lookup errors", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{6}).Return(false, errors.New("db down"))
		c := NewKeyorixCore(ms)
		assert.True(t, c.idpAutoGrantOfRoleIsEscalation(context.Background(), 6, "unknown"))
	})
}
