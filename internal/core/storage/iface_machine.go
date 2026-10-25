package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MachineStore is the Storage slice for machine identities, credentials, roles and OIDC bindings.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type MachineStore interface {
	// Machine identities (ADR-023) — non-human project members.
	CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error)
	GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error)
	// LockMachineIdentityForUpdate re-reads a machine identity by ID, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a read-modify-write on the row serializes against a concurrent
	// writer of the same row — mirroring LockUserForUpdate. Use this — not
	// GetMachineIdentity — inside a WithTransaction whenever a caller conditionally
	// mutates state (e.g. TransitionMachineIdentity's revoked-is-terminal invariant,
	// #388) that must not lose an update under concurrency.
	LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error)
	// TransitionMachineIdentityState persists m's full row via a single
	// conditional write — "UPDATE ... WHERE id = ? AND state = ?" — succeeding
	// only if the row's CURRENT persisted state still equals fromState (the
	// value TransitionMachineIdentity observed via LockMachineIdentityForUpdate
	// immediately before mutating m in memory), mirroring
	// UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'` pattern
	// (#412). Returns whether the write actually matched a row.
	//
	// This exists because the now-deleted RemoteStorage's WithTransaction was a
	// no-op passthrough — there was no client-side transaction to open over HTTP
	// — so a generic two-call Lock-then-Update sequence run against it got NONE of
	// the atomicity LocalStorage provides via a real DB transaction + row lock
	// (Postgres: SELECT ... FOR UPDATE), silently reopening the exact #388 race (a
	// concurrent revoke and reactivate racing off the same pre-transition state
	// could un-revoke a just-revoked machine identity) across the HTTP hop.
	// Routing the actual write through this one conditional round trip restores
	// the same guarantee LocalStorage already has, without making any
	// transition-legality decision here: the caller (core.TransitionMachineIdentity)
	// still decides fromState/to via canTransitionMachine before calling this;
	// a false match result must be treated exactly like an illegal transition,
	// not retried or silently overwritten.
	TransitionMachineIdentityState(ctx context.Context, m *models.MachineIdentity, fromState string) (bool, error)
	ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error)
	// ListAllMachineIdentities returns every machine identity across all projects —
	// for install-wide sweeps such as SoD conflict detection over non-human principals.
	ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error)
	// CountMachineIdentitiesByClassification returns install-wide counts keyed by
	// classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error)
	// CountStaleMachineIdentitiesByProject returns, for every project in
	// projectIDs in a single grouped query, the count of ACTIVE machine identities
	// not seen since olderThan (never-seen counts from creation) — the same
	// definition as ListStaleMachineIdentities, but deployment-wide in one query
	// instead of one call per project. Used by the hygiene rollup (#393). A
	// project absent from the result has zero stale machine identities.
	CountStaleMachineIdentitiesByProject(ctx context.Context, projectIDs []uint, olderThan time.Time) (map[uint]int, error)

	// Machine-token credentials (ADR-030) — opaque bearer tokens, hashed at rest.
	CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error)
	GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error)
	// GetMachineIdentityCredentialWithIdentityStateByHash is
	// GetMachineIdentityCredentialByHash plus the owning MachineIdentity's State,
	// fetched in ONE query (a JOIN) instead of the two sequential round trips
	// GetMachineIdentityCredentialByHash + GetMachineIdentity would otherwise cost
	// every call (SESSION-PERF, #2403 follow-up). Returns only the identity's State,
	// not the full MachineIdentity row: CurrentMachineTokenRestriction — the one
	// caller this exists for — never needed anything else from it, and returning a
	// single scalar (rather than hand-listing every MachineIdentity column to avoid
	// a name collision with MachineIdentityCredential's own, e.g. both have `id`/
	// `name`/`created_at`/`classification`) keeps this safe from column drift if
	// either model gains fields later. identityState is "" if the identity row is
	// somehow missing (the INNER JOIN would have excluded it; treat as not-found,
	// same as today's sequential GetMachineIdentity failing).
	GetMachineIdentityCredentialWithIdentityStateByHash(ctx context.Context, hash string) (cred *models.MachineIdentityCredential, identityState string, err error)
	GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error)
	ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error)
	// ListMachineCredentialUsageByMachineIDs is the batch form of ListMachineIdentityCredentials
	// for the machine audit report (LIST-ENDPOINTS-1): per machine, its credentials with ONLY
	// id, machine_identity_id and last_used_at populated (no token hash or CIDR list).
	ListMachineCredentialUsageByMachineIDs(ctx context.Context, machineIDs []uint) (map[uint][]*models.MachineIdentityCredential, error)
	// ListActiveMachineIdentityCredentials returns every non-revoked machine
	// credential across all identities — the deployment-wide view for token-hygiene
	// auditing (stale / expired-but-active).
	ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error)
	// SetMachineIdentityCredentialClassification persists ONLY the
	// classification column of credentialID, and only if the row's CURRENT
	// classification is still fromClassification (the value the caller read
	// before deciding to change it): "UPDATE ... SET classification WHERE
	// id = ? AND classification = ?". matched=false (no error) means the row
	// moved since that read; the caller must fail closed.
	//
	// This REPLACES the former UpdateMachineIdentityCredential, a bare GORM
	// Save of the whole row (#2696). Classification is the only field any
	// caller of that method ever changed, but Save wrote back every column
	// the caller's earlier, unlocked read had put in the struct — `revoked`
	// included. A RevokeMachineToken that committed on another replica in
	// between was therefore silently undone, and the revoked token
	// authenticated again with no audit record of the un-revoke. The narrow
	// method is deliberately the ONLY one left: a full-row writer for this
	// model would reintroduce that for whatever the next caller forgets.
	SetMachineIdentityCredentialClassification(ctx context.Context, credentialID uint, fromClassification, toClassification string) (matched bool, err error)
	// RevokeMachineIdentityCredential revokes credentialID, but only if it
	// belongs to a machine identity owned by projectID (#1551) — the same
	// ownership check core.machineInProject already applies for every other
	// machine-token operation, now enforced at the storage boundary too so a
	// caller that reaches this primitive directly (bypassing core, e.g. the
	// /system RevokeMachineIdentityCredentialProxy relay) can't revoke a
	// credential cross-tenant by supplying a project_id it doesn't actually
	// own for a credential that belongs to a different one. Returns
	// ErrNotFound (via the same not-found path as an unknown ID) when the
	// credential exists but its machine's project doesn't match — the two
	// cases are indistinguishable to the caller by design, matching how a
	// non-existent row and a row a caller wasn't allowed to see already read
	// the same "not found" elsewhere in this codebase.
	RevokeMachineIdentityCredential(ctx context.Context, projectID, credentialID uint) error
	// CountMachineIdentityCredentialsByClassification returns install-wide counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error)
	TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error
	// ListExpiringMachineCredentials returns every non-revoked MachineIdentityCredential
	// whose ExpiresAt is non-nil and strictly before before. Used by CheckTokenExpiry.
	ListExpiringMachineCredentials(ctx context.Context, before time.Time) ([]models.MachineIdentityCredential, error)

	// Machine-identity role grants (ADR-030) — mirror the user_roles surface.
	AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope Scope) ([]uint, error)
	// ResolveMachinePermissionAt is GetMachineRoleIDsAt plus RoleSetHasPermission
	// for one machine-principal decision (PERF-FIX-6, collapse C4): the role ids
	// and the role->permission cache generation come from ONE statement (one
	// snapshot), and the permission join runs only when that cache misses.
	// BypassesPermissionChecks is never set: a machine never bypasses (ADR-030).
	ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope Scope, permission string) (*PrincipalPermission, error)
	GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error)
	// GetMachineRoleScopes returns the distinct (project, environment) scopes at
	// which machineID holds ANY role grant (machine_identity_roles) — the
	// machine-identity mirror of GetUserRoleScopes (G33): a helper that must
	// enumerate every scope a principal holds a role at (e.g. actorRoleIDs's
	// Connect ref-grant match, GetReadableScopes) needs this to discover
	// project-scoped machine grants the same way it already discovers
	// project-scoped user grants, rather than resolving only the global scope.
	GetMachineRoleScopes(ctx context.Context, machineID uint) ([]Scope, error)

	// Machine-identity OIDC bindings (ADR-031) — map an external token's
	// (issuer, subject) to a machine identity for federated authentication.
	CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error)
	GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error)
	ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error)
	GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error)
	DeleteOIDCBinding(ctx context.Context, id uint) error
}
