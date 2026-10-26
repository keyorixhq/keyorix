package rules

// Moved verbatim from internal/core/authz.go (CORE-PURE-AUTH-LEAVES-1); core
// keeps the name as an alias (internal/core/pat_aliases.go).

import "strings"

// PATRestriction bounds what a request authenticated by a personal access token
// (ADR-042) may do, independent of — and intersected with — the owning user's own
// permissions. It is a least-privilege FILTER: it can only narrow a token below
// its owner, never grant the owner anything extra. The owner's live role
// resolution still runs after this check, so a restriction listing a permission
// the owner has since lost grants nothing.
type PATRestriction struct {
	// Permissions, when non-empty, is the exhaustive allowlist of permission
	// strings the token may exercise. Empty = inherit the owner's full set. An
	// entry may be an exact permission ("secrets.read"), the catch-all "*", or a
	// prefix wildcard ("secrets.*").
	Permissions []string
	// ProjectID, when non-zero, restricts the token to that project's scope;
	// any check at a different project — or at global/system scope (project 0) —
	// is denied. Zero = any scope the owner can reach.
	ProjectID uint
	// EnvironmentID, when non-zero, further restricts the token to that one
	// environment: any check whose resolved scope is a different environment — or a
	// project-level/global scope (environment 0) — is denied. Environment ids are
	// globally unique, so this confines the token to that env's project too. Zero =
	// any environment. (Secret-level checks carry the secret's environment; broader
	// project-level operations resolve environment 0 and so are denied for an
	// environment-scoped token — correct least privilege for, e.g., a staging-only
	// CI credential.)
	EnvironmentID uint
	// AllowedCIDRs, when non-empty, restricts the token to requests whose source IP falls
	// within one of the listed CIDR blocks. Enforced at the auth boundary (fail-closed: an
	// undeterminable/unparseable source IP is denied). Empty = no network restriction.
	AllowedCIDRs []string
}

// Allows reports whether this restriction permits exercising permission at scope.
// A nil restriction (no PAT, or an unrestricted PAT) is handled by the caller.
func (r *PATRestriction) Allows(permission string, scope Scope) bool {
	if r == nil {
		return true
	}
	// A project-scoped token may act ONLY within its project. A check at global
	// scope (ProjectID 0 — system-wide actions like users.read) is therefore
	// denied for a project-scoped token: it is not a system credential.
	if r.ProjectID != 0 && scope.ProjectID != r.ProjectID {
		return false
	}
	// An environment-scoped token may act ONLY within its environment; a check at a
	// different (or project-level/global) environment is denied.
	if r.EnvironmentID != 0 && scope.EnvironmentID != r.EnvironmentID {
		return false
	}
	if len(r.Permissions) == 0 {
		return true
	}
	for _, p := range r.Permissions {
		if p == "*" || p == permission {
			return true
		}
		if strings.HasSuffix(p, ".*") && strings.HasPrefix(permission, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}
