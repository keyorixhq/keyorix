package models

import (
	"slices"

	"gorm.io/gorm"
)

// Role.AssignableScope values (GROUP-ROLE-SCOPE-1 Phase 2, #3546; ADR-021
// amendment pending review). A grant's scope is {project, environment}, where
// project 0 is the global sentinel.
const (
	// RoleAssignableGlobal: only at the global scope (project 0). A system role.
	RoleAssignableGlobal = "global"
	// RoleAssignableProject: only at a project (optionally one of its
	// environments). A project role, and the default for a NEW custom role.
	RoleAssignableProject = "project"
	// RoleAssignableAny: at either. Existing custom roles were backfilled to
	// this so nothing that worked before breaks; an admin may set it explicitly.
	RoleAssignableAny = "any"
)

// RoleAssignableScopes lists the valid values, for validation and docs.
var RoleAssignableScopes = []string{RoleAssignableGlobal, RoleAssignableProject, RoleAssignableAny}

// IsValidRoleAssignableScope reports whether s is one of RoleAssignableScopes.
func IsValidRoleAssignableScope(s string) bool { return slices.Contains(RoleAssignableScopes, s) }

// BuiltinRoleAssignableScopes is the assignable scope of every built-in role:
// the one source both the first-boot seed (internal/core) and the one-time
// upgrade backfill (internal/storage) read, so they cannot disagree.
//
// The legacy single-tier roles (admin, editor, viewer, auditor, super_admin)
// are "global" (#3605, #3588): ADR-021's two tiers are the only model, so a
// project grant uses a project_* role (LegacyRoleProjectReplacements). Grants of
// them already held at a project are left in place and listed for replacement
// (core.ListLegacyRoleProjectGrants). Pinned by TestLegacyRolesAreGlobalOnly.
var BuiltinRoleAssignableScopes = map[string]string{
	"super_admin": RoleAssignableGlobal,
	"admin":       RoleAssignableGlobal,
	"editor":      RoleAssignableGlobal,
	"viewer":      RoleAssignableGlobal,
	"auditor":     RoleAssignableGlobal,

	"system_admin":   RoleAssignableGlobal,
	"system_auditor": RoleAssignableGlobal,
	"system_viewer":  RoleAssignableGlobal,
	"alert_operator": RoleAssignableGlobal,

	"project_admin":     RoleAssignableProject,
	"project_developer": RoleAssignableProject,
	"project_viewer":    RoleAssignableProject,
	"project_auditor":   RoleAssignableProject,
}

// LegacyRoleProjectReplacements names, for each legacy single-tier role, the
// project role to grant at a project instead (#3605). super_admin has no project
// equivalent of its own; project_admin is the highest project tier.
var LegacyRoleProjectReplacements = map[string]string{
	"super_admin": "project_admin",
	"admin":       "project_admin",
	"editor":      "project_developer",
	"viewer":      "project_viewer",
	"auditor":     "project_auditor",
}

// LegacyRoleProjectReplacement returns the project role that replaces the legacy
// role name at a project, and false when name is not a legacy role.
func LegacyRoleProjectReplacement(name string) (string, bool) {
	replacement, ok := LegacyRoleProjectReplacements[name]
	return replacement, ok
}

// LegacyRoleNames returns the legacy single-tier role names, sorted.
func LegacyRoleNames() []string {
	names := make([]string, 0, len(LegacyRoleProjectReplacements))
	for name := range LegacyRoleProjectReplacements {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// DefaultRoleAssignableScope is the scope a role row gets when it is written
// without one: a built-in role's fixed scope, otherwise the new-role default,
// project (fail closed: never any).
func DefaultRoleAssignableScope(name string) string {
	if s, ok := BuiltinRoleAssignableScopes[name]; ok {
		return s
	}
	return RoleAssignableProject
}

// EffectiveRoleAssignableScope is the scope the grant check enforces for r: its
// stored scope, or, when that is unset or invalid (only a hand-built Role can
// have one), DefaultRoleAssignableScope. Every reader uses this, so the API
// shows exactly what the check enforces.
func EffectiveRoleAssignableScope(r *Role) string {
	if IsValidRoleAssignableScope(r.AssignableScope) {
		return r.AssignableScope
	}
	return DefaultRoleAssignableScope(r.Name)
}

// BeforeCreate fills an unset AssignableScope (DefaultRoleAssignableScope), so
// no role row is written with a built-in name and the wrong scope: GORM would
// otherwise leave the column to its default (project), which is wrong for a
// system role. Every production writer sets the scope explicitly
// (LocalStorage.CreateRole, role seeding); this is the backstop for a writer
// that forgets, e.g. a later built-in seeded outside BootstrapSystem.
func (r *Role) BeforeCreate(_ *gorm.DB) error {
	if r.AssignableScope == "" {
		r.AssignableScope = DefaultRoleAssignableScope(r.Name)
	}
	return nil
}

// BuiltinRoleNamesWithAssignableScope returns the built-in role names whose
// assignable scope is scope, sorted.
func BuiltinRoleNamesWithAssignableScope(scope string) []string {
	var out []string
	for name, s := range BuiltinRoleAssignableScopes {
		if s == scope {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
