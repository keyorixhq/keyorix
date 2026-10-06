package core

import (
	"context"
	"fmt"
)

// adminBypassRoleIDSet is THE single source of truth for "which roles confer
// administrative authority" (#2496, INV-CORE-20). It resolves the set
// structurally, from models.Role.BypassesPermissionChecks (ADR-084), and from
// nothing else.
//
// It replaces installAdminRoleIDSet, which resolved the same set by matching a
// separately-maintained fixed name list
// (`super_admin`/`admin`/`system_admin`) via GetRoleByName — ADR-084's own
// documented "Not yet done". The two definitions disagreed, and the
// disagreement was load-bearing in both directions:
//
//   - UNDER-detection, the dangerous direction. A role carrying the flag but
//     named outside that list — the seeded `project_admin`, or anything the
//     one-time ADR-084 backfill flagged — confers full install-wide authority
//     when held at the global scope, because roleSetContainsAdmin is name-blind
//     and applies the bypass at whatever scope the role is held. The name list
//     could not see it, so removing the install's LAST such grant was not an
//     "admin role removal" at all: RemoveUserRole fell straight through to the
//     unguarded primitive and stranded the install with nobody able to manage
//     users, roles or settings.
//   - OVER-refusal, the merely-wrong direction. A SURVIVING flag-carrying
//     holder named outside the list was not counted as a backup administrator,
//     so a legitimate removal was refused as if it were the last one.
//
// `server/http/handlers/users_update_lastadmin_test.go` documents the same
// divergence from the other side ("these use two different definitions of
// 'admin'") and uses it as a deliberate test fixture.
//
// Errors are returned, never swallowed into an empty set. The predecessor
// returned a bare map and silently degraded a storage failure to "no admin
// roles exist", which disabled every last-admin guard built on it on exactly
// the failure mode those guards exist to survive. This mirrors
// roleSetContainsAdmin's documented fail-closed stance (INV-CORE-19): a lookup
// error on a security-relevant path must not be indistinguishable from a
// legitimate negative result. Every caller propagates the error, which refuses
// the mutation.
//
// There is deliberately NO name fallback. A name list here would reintroduce
// exactly the second source of truth this function exists to remove; see
// admin_role_name_list_singleton_test.go, which fails if a second one appears.
func (c *KeyorixCore) adminBypassRoleIDSet(ctx context.Context) (map[uint]bool, error) {
	ids, err := c.storage.ListAdminBypassRoleIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the install's admin-bypass roles: %w", err)
	}
	set := make(map[uint]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// adminBypassRoleIDSlice is adminBypassRoleIDSet in the []uint shape the
// storage-level guards take (RemoveGlobalAdminRoleGuarded,
// ListGlobalAdminAssignmentsForUpdate). Returned directly from storage rather
// than rebuilt from the map so the two shapes cannot drift.
func (c *KeyorixCore) adminBypassRoleIDSlice(ctx context.Context) ([]uint, error) {
	ids, err := c.storage.ListAdminBypassRoleIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the install's admin-bypass roles: %w", err)
	}
	return ids, nil
}
