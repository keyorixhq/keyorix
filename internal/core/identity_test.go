package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrimaryRole(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  string
	}{
		{"empty", nil, ""},
		{"single", []string{"viewer"}, "viewer"},
		{"admin beats viewer regardless of order", []string{"viewer", "admin"}, "admin"},
		{"system_admin outranks admin", []string{"admin", "system_admin"}, "system_admin"},
		{"super_admin tops all", []string{"admin", "super_admin", "system_admin"}, "super_admin"},
		{"project roles below system_viewer", []string{"system_viewer", "project_admin"}, "project_admin"},
		{"unknown role ranks last", []string{"custom_thing", "viewer"}, "viewer"},
		{"only unknown is returned", []string{"custom_thing"}, "custom_thing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, primaryRole(tc.roles))
		})
	}
}

func TestGetUserIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("assembles primary role, all roles, and permission union", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetUserRoles", ctx, uint(1)).Return([]*models.Role{
			{ID: 1, Name: "viewer"}, {ID: 2, Name: "admin"},
		}, nil)
		ms.On("GetUserPermissions", ctx, uint(1)).Return([]*storage.Permission{
			{Name: "secrets.read"}, {Name: "users.read"},
		}, nil)

		id, err := c.GetUserIdentity(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "admin", id.Role)
		assert.Equal(t, []string{"viewer", "admin"}, id.Roles)
		assert.ElementsMatch(t, []string{"secrets.read", "users.read"}, id.Permissions)
	})

	t.Run("user with no roles yields empty (non-nil) slices and blank primary", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{}, nil)
		ms.On("GetUserPermissions", ctx, uint(2)).Return([]*storage.Permission{}, nil)

		id, err := c.GetUserIdentity(ctx, 2)
		require.NoError(t, err)
		assert.Equal(t, "", id.Role)
		assert.NotNil(t, id.Roles)
		assert.NotNil(t, id.Permissions)
		assert.Empty(t, id.Roles)
		assert.Empty(t, id.Permissions)
	})
}
