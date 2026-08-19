// default_roles_permission_catalog_test.go — regression test for #1497:
// defaultPermissions (auth_bootstrap.go:47) and adminPermissions
// (auth_bootstrap.go:95) matched 14/14 by coincidence, with nothing
// enforcing it. Two distinct invariants, checked separately so a failure
// names which one broke:
//
//   - Identity: adminPermissions (shared by the "admin" and "system_admin"
//     defaultRoles entries — the two roles whose own description promises
//     "full access") must contain every permission in defaultPermissions,
//     exactly. A permission added to defaultPermissions without a matching
//     addition to adminPermissions would be created in the catalog by
//     ReconcileRBACPermissions but never granted to admin/system_admin,
//     silently narrowing "full access" (see #1496's investigation).
//   - Subset: every OTHER defaultRoles entry's Permissions list must
//     reference only names that exist in defaultPermissions. A dangling
//     reference there would be a live bug (a role definition naming a
//     permission that's never created), not just a missing test — verified
//     absent today by direct enumeration during #1497's investigation, but
//     nothing stopped a future entry from introducing one silently.
package core

import (
	"sort"
	"testing"
)

// defaultPermissionNames returns the set of permission names defaultPermissions
// declares.
func defaultPermissionNames() map[string]bool {
	names := make(map[string]bool, len(defaultPermissions))
	for _, p := range defaultPermissions {
		names[p.Name] = true
	}
	return names
}

// TestAdminPermissions_MatchesDefaultPermissionsCatalogExactly encodes the
// identity invariant: adminPermissions must be exactly defaultPermissions,
// no more, no less. Fails naming any permission missing from adminPermissions
// (admin/system_admin would silently lose "full access" to it) and any extra
// permission in adminPermissions that isn't in defaultPermissions (a typo or
// stale name — the grant would fail at bootstrap since AssignPermissionToRole
// resolves it against the created catalog).
func TestAdminPermissions_MatchesDefaultPermissionsCatalogExactly(t *testing.T) {
	catalog := defaultPermissionNames()

	admin := make(map[string]bool, len(adminPermissions))
	for _, name := range adminPermissions {
		admin[name] = true
	}

	var missingFromAdmin, extraInAdmin []string
	for name := range catalog {
		if !admin[name] {
			missingFromAdmin = append(missingFromAdmin, name)
		}
	}
	for name := range admin {
		if !catalog[name] {
			extraInAdmin = append(extraInAdmin, name)
		}
	}
	sort.Strings(missingFromAdmin)
	sort.Strings(extraInAdmin)

	if len(missingFromAdmin) > 0 {
		t.Errorf("adminPermissions is missing permission(s) present in defaultPermissions: %v\n"+
			"admin/system_admin are documented as \"full access\" — add the permission to adminPermissions "+
			"(auth_bootstrap.go), or ReconcileRBACPermissions will create it in the catalog but never grant "+
			"it to admin/system_admin on an upgraded install.", missingFromAdmin)
	}
	if len(extraInAdmin) > 0 {
		t.Errorf("adminPermissions references permission(s) not present in defaultPermissions: %v\n"+
			"this is a dangling name (typo, or a permission removed from defaultPermissions without "+
			"updating adminPermissions) — the grant would fail to resolve against the created catalog.", extraInAdmin)
	}
}

// TestDefaultRoles_NonAdminEntriesReferenceOnlyCatalogedPermissions encodes
// the subset invariant for every defaultRoles entry OTHER than "admin" and
// "system_admin" (covered by the identity invariant above, since they share
// adminPermissions): every permission name in the role's list must exist in
// defaultPermissions. A failure here means a role definition names a
// permission that's never created — a live bug, not a missing test, since
// AssignPermissionToRole would fail to resolve it during bootstrap.
func TestDefaultRoles_NonAdminEntriesReferenceOnlyCatalogedPermissions(t *testing.T) {
	catalog := defaultPermissionNames()

	// "admin" and "system_admin" both use adminPermissions and are covered by
	// the identity invariant test above — skip them here so a genuine subset
	// violation isn't masked by (or duplicated with) that test's own failure.
	adminTierRoles := map[string]bool{"admin": true, "system_admin": true}

	checked := 0
	for _, rdef := range defaultRoles {
		if adminTierRoles[rdef.Name] {
			continue
		}
		checked++
		var undefined []string
		for _, permName := range rdef.Permissions {
			if !catalog[permName] {
				undefined = append(undefined, permName)
			}
		}
		if len(undefined) > 0 {
			sort.Strings(undefined)
			t.Errorf("defaultRoles entry %q references permission(s) absent from defaultPermissions: %v\n"+
				"this role would fail to seed correctly at bootstrap — either add the permission to "+
				"defaultPermissions (auth_bootstrap.go) or remove the dangling reference from this role's list.",
				rdef.Name, undefined)
		}
	}

	// The two admin-tier roles are the only defaultRoles entries expected to
	// be skipped; if that ever changes (a role renamed, a new admin-tier role
	// added under a different name), this catches the coverage gap rather
	// than silently checking fewer roles than defaultRoles actually has.
	if want := len(defaultRoles) - len(adminTierRoles); checked != want {
		t.Fatalf("expected to check %d non-admin-tier defaultRoles entries, checked %d — "+
			"defaultRoles or adminTierRoles changed without updating this test", want, checked)
	}
}
