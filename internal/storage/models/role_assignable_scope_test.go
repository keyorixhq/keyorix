package models

import "testing"

func TestRoleBeforeCreate_FillsOnlyAnUnsetAssignableScope(t *testing.T) {
	cases := []struct {
		role Role
		want string
	}{
		{Role{Name: "system_admin"}, RoleAssignableGlobal},
		{Role{Name: "project_viewer"}, RoleAssignableProject},
		{Role{Name: "viewer"}, RoleAssignableAny},
		{Role{Name: "deployers"}, RoleAssignableProject}, // a custom role: fail closed
		{Role{Name: "deployers", AssignableScope: RoleAssignableAny}, RoleAssignableAny},
		{Role{Name: "system_admin", AssignableScope: RoleAssignableAny}, RoleAssignableAny}, // explicit wins
	}
	for _, tc := range cases {
		r := tc.role
		if err := r.BeforeCreate(nil); err != nil {
			t.Fatal(err)
		}
		if r.AssignableScope != tc.want {
			t.Errorf("%s (%q): got %q, want %q", tc.role.Name, tc.role.AssignableScope, r.AssignableScope, tc.want)
		}
	}
}

func TestBuiltinRoleAssignableScopes_AreValid(t *testing.T) {
	for name, s := range BuiltinRoleAssignableScopes {
		if !IsValidRoleAssignableScope(s) {
			t.Errorf("built-in %s has invalid scope %q", name, s)
		}
	}
}
