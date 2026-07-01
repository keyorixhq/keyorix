package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Storage defines the unified interface for data persistence operations
// This interface abstracts away the underlying storage implementation,
// allowing for both local database access and remote API calls
type Storage interface {
	// Login rate limiting (ADR-040) — cluster-wide brute-force protection. Replaces
	// the per-process in-memory limiter so the limit holds across HA replicas.
	RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error
	CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error)
	PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error)

	// WithSchedulerLock runs fn only if this process can take the named scheduler
	// lock, so a background job runs on a single replica at a time (HA, ADR-039).
	// On PostgreSQL it uses a session advisory lock (pg_try_advisory_lock); on
	// SQLite (single instance) fn always runs. Returns ran=false (and nil error)
	// when another replica holds the lock — the caller should simply skip this tick.
	WithSchedulerLock(ctx context.Context, key int64, fn func() error) (ran bool, err error)

	// WithTransaction runs fn inside a single storage transaction: every mutation fn
	// performs through the provided Storage commits together, or rolls back together if
	// fn returns an error. The backing store decides the semantics — the local (DB)
	// store opens a real transaction and hands fn a transaction-scoped Storage; the
	// remote store runs fn directly against itself (each remote call is already atomic
	// server-side, so there is no client-side transaction to open). Use it for
	// multi-step mutations that must not half-apply (e.g. a suspend + delete pair).
	WithTransaction(ctx context.Context, fn func(Storage) error) error

	// Project / Environment management
	CreateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	GetProject(ctx context.Context, id uint) (*models.Project, error)
	UpdateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	DeleteProject(ctx context.Context, id uint) error
	RestoreProject(ctx context.Context, id uint) error
	ListProjects(ctx context.Context) ([]*models.Project, error)
	ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]ProjectWithCounts, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	GetEnvironment(ctx context.Context, id uint) (*models.Environment, error)
	DeleteEnvironment(ctx context.Context, id uint) error
	// RestoreEnvironment restores a soft-deleted environment, scoped to projectID
	// so a caller authorized for one project cannot restore another's environment.
	RestoreEnvironment(ctx context.Context, projectID, id uint) error
	ListEnvironments(ctx context.Context) ([]*models.Environment, error)
	ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListProjectMembers(ctx context.Context, projectID uint) ([]ProjectMember, error)
	// ListProjectRoleAssignments returns every direct (user) and group role grant
	// scoped to the project (project_id = projectID, any environment) — the raw
	// rows for a project access review. Global (project 0) grants are excluded:
	// those are install-level, reviewed separately.
	ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]RoleAssignment, error)
	// LastUserSecretActivity returns, per user, the most recent secret-access time
	// in the project (from the audit trail). Backs dormant-access detection in the
	// access review — a grant whose principal has no recent activity is stale
	// standing access to prune. Users with no recorded activity are absent from the
	// map.
	LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error)

	// Project invitations (ADR-024).
	CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error)
	GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error)
	UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) error
	ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error)

	// Access requests (ADR-024).
	CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error)
	GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error)
	UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) error
	ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error)
	// Access-request approvals (N-of-M dual control). One row per approver sign-off.
	CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error
	ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error)

	// Access-review campaigns (ISO 27001 A.5.18) — periodic recertification cycles
	// and the per-grant items captured within them.
	CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error)
	GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error)
	ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error)
	UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) error
	CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error
	ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error)
	GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error)
	UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) error

	// Separation-of-duties policies (ISO 27001 A.5.3 / SOX) — toxic permission pairs.
	CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error)
	GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error)
	ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error)
	DeleteSoDPolicy(ctx context.Context, id uint) error

	// Secret dependency edges (ADR-052) — the per-project secret dependency graph.
	CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)
	GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error)
	ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error)
	DeleteSecretDependency(ctx context.Context, id uint) error

	// Legal hold (ISO 27001 A.5.34 / eDiscovery) — a deployment-wide hold that
	// blocks the purge jobs from hard-deleting records while active.
	CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error)
	GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error)
	UpdateLegalHold(ctx context.Context, h *models.LegalHold) error

	// Risk exceptions (ISO 27001 A.5.8 risk treatment) — governed, time-bound
	// acceptances of a known control gap. CreateRiskException records one;
	// ListRiskExceptions returns all (activeOnly excludes revoked rows; expiry is
	// computed in core); GetRiskException/UpdateRiskException support revoke.
	CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error)
	ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error)
	GetRiskException(ctx context.Context, id uint) (*models.RiskException, error)
	UpdateRiskException(ctx context.Context, e *models.RiskException) error

	// SSO login state (OIDC human SSO) — short-lived CSRF/nonce state.
	// ConsumeSSOLoginState is single-use: it returns the row and deletes it.
	CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error
	ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error)

	// Break-glass emergency-access activations (NIS2/DORA incident response).
	CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error)
	GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error)
	ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error)
	UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error
	// Machine identities (ADR-023) — non-human project members.
	CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error)
	GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error)
	UpdateMachineIdentity(ctx context.Context, m *models.MachineIdentity) error
	ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error)
	// ListAllMachineIdentities returns every machine identity across all projects —
	// for install-wide sweeps such as SoD conflict detection over non-human principals.
	ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error)
	// CountMachineIdentitiesByClassification returns install-wide counts keyed by
	// classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error)

	// Machine-token credentials (ADR-030) — opaque bearer tokens, hashed at rest.
	CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error)
	GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error)
	GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error)
	ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error)
	// ListActiveMachineIdentityCredentials returns every non-revoked machine
	// credential across all identities — the deployment-wide view for token-hygiene
	// auditing (stale / expired-but-active).
	ListActiveMachineIdentityCredentials(ctx context.Context) ([]*models.MachineIdentityCredential, error)
	UpdateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) error
	RevokeMachineIdentityCredential(ctx context.Context, id uint) error
	// CountMachineIdentityCredentialsByClassification returns install-wide counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error)
	TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error

	// Machine-identity role grants (ADR-030) — mirror the user_roles surface.
	AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope) error
	GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope Scope) ([]uint, error)
	GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error)

	// Machine-identity OIDC bindings (ADR-031) — map an external token's
	// (issuer, subject) to a machine identity for federated authentication.
	CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error)
	GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error)
	ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error)
	GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error)
	DeleteOIDCBinding(ctx context.Context, id uint) error

	// Project membership lifecycle (ADR-022). Separate from the role grant.
	CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error)
	GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error)
	UpdateProjectMembership(ctx context.Context, m *models.ProjectMembership) error
	ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error)
	// GetActiveProjectMembership returns the user's non-revoked membership in a
	// project, or an error if none exists.
	GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error)
	// ListStaleInvitedMemberships returns memberships still in `invited` state
	// that were invited before the cutoff.
	ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error)

	// In-app notifications (ADR-024).
	CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error)
	// ListNotifications returns a user's notifications newest-first; when
	// unreadOnly is set, only unread ones. limit caps the result (0 = default).
	ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadNotifications(ctx context.Context, userID uint) (int64, error)
	// MarkNotificationRead marks one notification read, scoped to its owner.
	MarkNotificationRead(ctx context.Context, id, userID uint) error
	MarkAllNotificationsRead(ctx context.Context, userID uint) error
	// ListUserProjectMemberships returns all membership rows for a single user,
	// newest first (powers the per-user assignments view).
	ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error)
	// CountProjectMembershipsByUsers returns per-user membership tallies (active
	// and non-revoked total) for the given user IDs in one grouped query.
	CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]MembershipCounts, error)

	// Secret Management
	CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	GetSecret(ctx context.Context, id uint) (*models.SecretNode, error)
	GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error)
	UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	DeleteSecret(ctx context.Context, id uint) error
	// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033).
	RestoreSecret(ctx context.Context, id uint) error
	// GetSecretIncludingDeleted loads a secret even if soft-deleted (Unscoped),
	// so the restore route can resolve a deleted secret's scope (ADR-033).
	GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error)
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*models.SecretNode, int64, error)
	// ListOrphanedSecrets returns a project's live secrets whose owner is no longer
	// a live user (the owner was deleted/soft-deleted) — offboarding hygiene, so an
	// admin can re-assign ownership. Scoped to the project via the environment JOIN.
	ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error)
	// GetSecretTags returns a secret's tag names (sorted). SetSecretTags replaces a
	// secret's tags wholesale, upserting Tag rows by name — secret organization/search.
	GetSecretTags(ctx context.Context, secretID uint) ([]string, error)
	SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error
	// ListProjectSecretsForDrift returns one lightweight row per secret in the
	// project (folders excluded, secrets in soft-deleted environments excluded),
	// carrying just the fields cross-environment drift detection pivots on:
	// environment id, name, type, and whether expiration / max_reads are set. No
	// secret values are read.
	ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]DriftSecretRow, error)
	GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error)
	CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error)
	// SetSecretCertNotAfter caches a certificate-typed secret's parsed leaf expiry
	// (ADR-056), a targeted column update with no other side effects.
	SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error
	IncrementSecretReadCount(ctx context.Context, versionID uint) error
	// TryIncrementSecretReadCount atomically increments a version's read count only
	// while it is still below maxReads, in a single conditional UPDATE. Returns true
	// when the increment happened (the read is within the cap), false when the cap is
	// already reached (or the version is gone). This is the race-free gate for
	// max-reads enforcement: concurrent reads can never collectively exceed the cap.
	TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error)

	// Secret Sharing Management
	CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	DeleteShareRecord(ctx context.Context, shareID uint) error
	ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error)
	ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error)
	ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error)
	ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error)
	ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error)
	CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error)
	// DeleteExpiredShareRecords removes time-bound shares whose ExpiresAt is non-NULL
	// and at or before the cutoff, returning the removed rows so the caller can audit
	// each expiry. Server-side only (run by the JIT expiry scheduler).
	DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error)

	// User Management
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	// CreateUserWithRoleGrants creates the user and applies all role grants in a
	// single transaction (ADR-028 atomic provisioning); on any failure nothing is
	// persisted.
	CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []RoleGrant) (*models.User, error)
	GetUser(ctx context.Context, id uint) (*models.User, error)
	// LockUserForUpdate re-reads a user by ID inside a WithTransaction, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a read-modify-write on the row serializes against concurrent writers
	// across replicas. On backends without row locks (SQLite) it is a plain read, and
	// the caller is responsible for its own process-level serialization. Returns the
	// typed ErrUserNotFound when the user is absent. Use this — not GetUser — whenever
	// a transaction increments or conditionally mutates per-user counters (e.g. the
	// login-lockout failed-attempt count) that must not lose updates under concurrency.
	LockUserForUpdate(ctx context.Context, id uint) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) (*models.User, error)
	// UpdateLastLogin stamps the user's last_login_at column without touching any
	// other field (no updated_at bump). Called on every successful login.
	UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error
	DeleteUser(ctx context.Context, id uint) error
	RestoreUser(ctx context.Context, id uint) error
	// PurgeDeleted*Before hard-delete soft-deleted rows whose deleted_at is
	// older than `before`, returning the number purged (ADR-032). Irreversible.
	PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error)
	PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error)
	// Delete*Before hard-delete compliance records past their retention window
	// (ISO A.5.33 / GDPR), returning the number removed. Unlike the soft-delete
	// purge these age out live records by a time column, never touch active rows,
	// and cascade to dependent rows where noted. Irreversible.
	DeleteAnomalyAlertsBefore(ctx context.Context, before time.Time) (int64, error)
	// DeleteClosedAccessReviewsBefore removes closed campaigns (closed_at < before)
	// and their snapshot items, returning (campaigns, items) removed.
	DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (campaigns int64, items int64, err error)
	// DeleteExpiredBreakGlassBefore removes non-active activations (created_at < before).
	DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error)
	// DeleteResolvedAccessRequestsBefore removes terminal-state requests (resolved_at
	// < before) and their approval records, returning (requests, approvals) removed.
	DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (requests int64, approvals int64, err error)
	ListUsers(ctx context.Context, filter *UserFilter) ([]*models.User, int64, error)
	// ListUsersInStateBefore returns users whose account_state equals state and
	// who were created before the cutoff (ADR-025 stale-account warnings).
	ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	// GetUserByExternalID resolves a SCIM-provisioned user by the IdP's externalId
	// (RFC 7644). Returns the not-found error when no user carries that external id.
	GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error)
	GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)

	// Password history (ADR-025 history_count). AddPasswordHistory records a
	// bcrypt hash; RecentPasswordHashes returns the most recent `limit` hashes
	// (newest first); PrunePasswordHistory keeps only the newest `keep` rows.
	AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error
	RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error)
	PrunePasswordHistory(ctx context.Context, userID uint, keep int) error

	// Group Management
	CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	GetGroup(ctx context.Context, id uint) (*models.Group, error)
	UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	DeleteGroup(ctx context.Context, id uint) error
	// RestoreGroup clears a soft-deleted group's deleted_at (with its grants/members).
	RestoreGroup(ctx context.Context, id uint) error
	ListGroups(ctx context.Context) ([]*models.Group, error)
	AddUserToGroup(ctx context.Context, userID, groupID uint) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error
	ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)

	// Permission Management
	CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error

	// Role Management
	CreateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	GetRole(ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	DeleteRole(ctx context.Context, id uint) error
	ListRoles(ctx context.Context) ([]*models.Role, error)

	// RBAC Operations.
	// AssignRole/RemoveRole bind a role to a user at the given Scope
	// (zero Scope = global). GetUserRoleIDsAt / GetUserGroupRoleIDsAt return the
	// role IDs that apply at a target scope (directly, or via group membership),
	// and RoleSetHasPermission reports whether any of those roles grants a
	// permission. Together they back core.Authorize.
	AssignRole(ctx context.Context, userID, roleID uint, scope Scope) error
	// AssignRoleWithExpiry binds a time-bound role to a user (just-in-time access):
	// the grant stops authorizing the moment expiresAt passes (the auth queries
	// filter on it) and is later swept by DeleteExpiredRoleGrants.
	AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope Scope, expiresAt time.Time) error
	RemoveRole(ctx context.Context, userID, roleID uint, scope Scope) error
	GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error)
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserRoleIDsExact(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	// IsProjectMember reports whether the user holds a LIVE role grant scoped to the
	// project itself (project_id = projectID), directly or via a group — i.e. real
	// membership. A global/install-wide role (project_id = 0) does NOT count.
	IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
	CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]*Permission, error)
	// GetUserGroupPermissions returns the permissions a user holds via GROUP
	// membership (group → group_roles → role_permissions), scope-agnostically and
	// across all of the user's groups — the counterpart to GetUserPermissions, which
	// covers only direct user_roles. Callers that need a user's full effective
	// permission set (e.g. SoD conflict detection) must union both, mirroring how
	// Authorize unions direct and group-inherited roles.
	GetUserGroupPermissions(ctx context.Context, userID uint) ([]*Permission, error)

	// Permission queries
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermission(ctx context.Context, id uint) (*models.Permission, error)
	GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error)
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error

	// Keyorix Connect per-reference grants (ADR-045). ListConnectRefGrantsByConnector
	// returns the grants scoped to one connector (the enforcement path);
	// ListConnectRefGrants returns all grants (management/listing).
	ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error)
	ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error)
	CreateConnectRefGrant(ctx context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error)
	DeleteConnectRefGrant(ctx context.Context, id uint) error

	// Group-Role assignments. Assign/Remove bind a role to a group at the given
	// Scope (zero Scope = global).
	GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error)
	// GetGroupRoleGrants is GetGroupRoles plus each grant's time-bound expiry
	// (nil = permanent), so callers can surface remaining time on a JIT grant.
	GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*GroupRoleGrant, error)
	// ListGroupRoleAssignments returns every role grant held by a group across ALL
	// scopes (unlike ListProjectRoleAssignments, which is scoped to one project) —
	// used to evaluate the admin-rank ceiling before adding a member to the group,
	// and the last-install-administrator invariant before removing one or deleting
	// the group outright.
	ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]RoleAssignment, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// AssignRoleToGroupWithExpiry binds a time-bound role to a group; see
	// AssignRoleWithExpiry.
	AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope Scope, expiresAt time.Time) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	// DeleteExpiredRoleGrants removes user/group role grants whose ExpiresAt is at
	// or before `before`, returning the removed grants so the caller can audit each
	// expiry. Backs the JIT access-expiry scheduler.
	DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]RoleAssignment, error)

	// Stats Snapshots
	SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error
	GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error)

	// Audit Logging
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	// MostAccessedSecrets returns the most-read secrets (optionally scoped to a
	// project) in the window since `since`, ordered by read count descending,
	// capped at `limit`. Backs the usage-analytics dashboard.
	MostAccessedSecrets(ctx context.Context, projectID *uint, since time.Time, limit int) ([]SecretUsageStat, error)
	// UnusedSecrets returns secrets (optionally scoped to a project) with no read
	// access since `notReadSince` — including never-read secrets — ordered
	// never-read first, then oldest last read.
	UnusedSecrets(ctx context.Context, projectID *uint, notReadSince time.Time) ([]UnusedSecretStat, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
	// ListUnalertedAnomalyAlerts returns alerts not yet pushed out (alerted=false),
	// and MarkAnomalyAlertAlerted flags one as pushed — for proactive alerting.
	ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error)
	MarkAnomalyAlertAlerted(ctx context.Context, id uint) error
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*models.AuditEvent, int64, error)
	GetRBACAuditLogs(ctx context.Context, filter *RBACAuditFilter) ([]*RBACAuditLog, int64, error)
	// AuditRetentionStats returns the total audit event count and the oldest /
	// newest event timestamps. Keyorix never purges audit events, so these raw
	// aggregates let an operator demonstrate how far back the trail reaches
	// (NIS2 mandates 12 months of retention). Oldest/Newest are nil on an empty
	// table.
	AuditRetentionStats(ctx context.Context) (*AuditRetentionStats, error)
	// VerifyAuditChain re-walks the tamper-evidence hash chain (ADR-029) over
	// audit_events and reports whether it is intact. The first divergence —
	// modified field, deleted/inserted row, or broken linkage — is reported
	// with the offending event id. A leading run of pre-ADR-029 rows with empty
	// hashes is counted as an unchained legacy prefix, not a failure.
	VerifyAuditChain(ctx context.Context) (*AuditChainVerification, error)
	// CreateAuditCheckpoint appends a signed checkpoint of the chain head (ADR-029).
	CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error
	// UpdateAuditCheckpointAnchor stores the external-notary anchor (RFC 3161 token,
	// asserted time, provider) on an existing checkpoint row (ADR-029); the signed
	// fields stay immutable.
	UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error
	// LatestAuditCheckpoint returns the most recently written checkpoint, or
	// (nil, nil) when none exists yet.
	LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error)
	// AuditEntryHashByID returns the entry_hash of the audit row with the given
	// id; found is false when no such row exists (e.g. it was truncated away).
	AuditEntryHashByID(ctx context.Context, id uint) (hash string, found bool, err error)
	// GetSystemMetadata returns the value stored for key; found is false when the key
	// has never been set. A small singleton key/value store for server-managed state.
	GetSystemMetadata(ctx context.Context, key string) (value string, found bool, err error)
	// SetSystemMetadata upserts a system-metadata key/value (last write wins).
	SetSystemMetadata(ctx context.Context, key, value string) error
	GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error)
	// CountImpersonatedActions returns the number of impersonated audit events
	// recorded for actingAs by impersonator since `since`, excluding the
	// impersonation.start/impersonation.end markers themselves. Used to report
	// the action count on an impersonation.end event.
	CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error)

	// Session Management
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	GetSession(ctx context.Context, token string) (*models.Session, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
	ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error)
	// EnforceSessionLimit deletes a user's oldest sessions beyond the `keep` most-recent
	// (by created_at), bounding concurrent sessions per user. No-op when under the cap.
	EnforceSessionLimit(ctx context.Context, userID uint, keep int) error
	DeleteSession(ctx context.Context, id uint) error
	// DeleteSessionsForUserExcept removes every session owned by userID except the
	// one with id exceptID. Used to drop other sessions on a password change.
	DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error
	// ListSessionTokenHashesForUser returns the stored session_token values (SHA-256
	// hashes — equal to the auth-cache key) for every session owned by or impersonating
	// userID, so a state change can evict them from the auth cache immediately.
	ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error)
	// TouchSession bumps last_seen_at only when it is older than the given staleness
	// window (no-op otherwise) so the auth hot path is not turned into a write per request.
	TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error
	CleanupExpiredSessions(ctx context.Context) error

	// MFA / TOTP (per-user two-factor authentication).
	UpsertMFASecret(ctx context.Context, s *models.MFASecret) error
	GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error)
	ActivateMFASecret(ctx context.Context, userID uint) error
	// MarkTOTPStepUsed atomically records that the given TOTP time-step was accepted for
	// userID, returning true only if it was newly consumed (step strictly greater than
	// the stored last-used step). A false return means the code is a replay.
	MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error)
	DeleteMFAForUser(ctx context.Context, userID uint) error // clears secret + recovery codes
	SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error
	// ConsumeMFARecoveryCode marks a matching unused code used and reports whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	// CountUnusedMFARecoveryCodes returns how many of the user's recovery codes remain unused.
	CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error)
	// DeleteMFARecoveryCodes removes all of the user's recovery codes (the regenerate flow replaces them).
	DeleteMFARecoveryCodes(ctx context.Context, userID uint) error
	// Dynamic secrets (ADR-035).
	CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error)
	GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error)
	UpdateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) error
	// CountDynamicSecretConfigsByClassification returns install-wide config counts
	// keyed by classification label ("" = unclassified) for the compliance posture.
	CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error)
	CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error)
	GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error)
	ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error)
	// CountActiveLeases returns how many leases from configID are currently active —
	// used to enforce the config's MaxActiveLeases ceiling.
	CountActiveLeases(ctx context.Context, configID uint) (int64, error)
	UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error
	ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error)

	CreateMFAChallenge(ctx context.Context, c *models.MFAChallenge) error
	// ConsumeMFAChallenge atomically finds an unused, unexpired challenge by token
	// hash, marks it used, and returns it (or an error if none).
	ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	// GetActiveMFAChallenge finds an unused, unexpired challenge by token hash
	// WITHOUT consuming it (used to resolve the user at WebAuthn login-begin; the
	// challenge is consumed later, atomically, at login-finish).
	GetActiveMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)

	// WebAuthn / passkeys (ADR-036).
	CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error)
	GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error)
	UpdateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error
	CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error)
	SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error
	CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error
	// ConsumeWebAuthnSession atomically finds an unused, unexpired ceremony session
	// by token hash, marks it used, and returns it (or an error if none).
	ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error)

	// Personal Access Token Management (ADR-027) — user-owned bearer credentials.
	CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error)
	// ListActivePersonalAccessTokens returns every non-revoked PAT across all users —
	// the deployment-wide view for token-hygiene auditing (stale / expired-but-active).
	ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, id uint) error
	// RevokeAllPersonalAccessTokensForUser revokes every active PAT for a user and returns
	// their token hashes (for immediate auth-cache eviction). Used on a password change/
	// reset so PATs die with the password.
	RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error)
	TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error

	// Setup Token Management (ADR-028) — single-use, hashed-at-rest credential-delivery tokens.
	CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error)
	// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash).
	GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error)
	// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
	// superseded, so reissuing ("resend") atomically kills the prior link.
	SupersedeActiveSetupTokens(ctx context.Context, purpose, email string) error
	// MarkSetupTokenConsumed transitions active → consumed only if the token is still
	// active, stamping consumedAt. It reports whether the transition happened, so a
	// concurrent replay (state already consumed/expired/superseded) is rejected.
	MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error)
	// MarkSetupTokenExpired transitions active → expired (lazy expiry on read).
	MarkSetupTokenExpired(ctx context.Context, id uint) error
	// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff,
	// backing resend throttling / daily caps.
	CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error)

	// API Client Management
	CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error)
	GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error)
	RevokeAPIClient(ctx context.Context, clientID string) error
	ListAPIClients(ctx context.Context) ([]*models.APIClient, error)
	UpdateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error)

	// API Token Management
	CreateAPIToken(ctx context.Context, token *models.APIToken) (*models.APIToken, error)
	GetAPIToken(ctx context.Context, id uint) (*models.APIToken, error)
	ListAPITokens(ctx context.Context, clientID *uint) ([]*models.APIToken, error)
	RevokeAPIToken(ctx context.Context, id uint) error

	// Rotation Policy Management
	CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error)
	ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error)
	UpdateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	DeleteRotationPolicy(ctx context.Context, id uint) error

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*StorageStats, error)
}

// SecretFilter defines filtering options for secret queries
type SecretFilter struct {
	ProjectID     *uint
	EnvironmentID *uint
	Type          *string
	Tags          []string
	CreatedBy     *string
	// OwnerID, when set, restricts to secrets owned by that user (owner_id) — the
	// canonical ownership the permission model uses (CheckSecretPermission), as
	// opposed to the mutable created_by username string.
	OwnerID       *uint
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	// ExpiresBefore, when set, restricts to secrets with a non-null expiration
	// earlier than the given time (i.e. already expired or expiring before it).
	ExpiresBefore *time.Time
	// Classification, when set, restricts to secrets with that data-classification
	// label (A.5.12). Use the sentinel "unclassified" to match the empty label.
	Classification *string
	Page           int
	PageSize       int
	// IncludeDeleted, when true, also returns soft-deleted secrets (ADR-033) —
	// for a restore UI. Default false: GORM auto-scopes deleted_at IS NULL.
	IncludeDeleted bool
	// DeletedOnly, when true, returns ONLY soft-deleted secrets (deleted_at IS NOT
	// NULL) — the recycle-bin / restore view. Implies reaching past GORM's
	// soft-delete scope. Takes precedence over IncludeDeleted.
	DeletedOnly bool
}

// DriftSecretRow is one secret's drift-relevant projection: which environment it
// lives in, its name (the cross-environment key), its type, and whether it has
// an expiration / max-reads cap set. Used to build the per-key × per-environment
// presence matrix for cross-environment drift detection.
type DriftSecretRow struct {
	EnvironmentID uint
	Name          string
	Type          string
	HasExpiration bool
	HasMaxReads   bool
}

// UserFilter defines filtering options for user queries
type UserFilter struct {
	Search       *string // OR match across username and email (LIKE %search%)
	Username     *string
	Email        *string
	IsActive     *bool
	CreatedAfter *time.Time
	// InactiveSince, when set, returns only users who have not logged in since the
	// given time — i.e. last_login_at IS NULL OR last_login_at < InactiveSince.
	InactiveSince  *time.Time
	IncludeDeleted bool // when true, also return soft-deleted users
	Page           int
	PageSize       int
	// Offset, when > 0, sets the row offset directly (overriding the Page-derived
	// offset). Used for SCIM startIndex paging, where the window is an arbitrary 1-based
	// item offset that need not align to a Page boundary.
	Offset int
}

// MembershipCounts holds a user's project-membership tallies: Active counts
// memberships in the `active` state; Total counts all non-revoked memberships.
type MembershipCounts struct {
	Active int
	Total  int
}

// AuditFilter defines filtering options for audit log queries
type AuditFilter struct {
	ProjectID *uint
	UserID    *uint
	// SecretID restricts to events about a specific secret (secret_node_id).
	SecretID *uint
	Action   *string
	// Actions matches any of several event types (event_type IN). Used to pull a
	// related family of events together, e.g. the RBAC audit log (role.*).
	Actions  []string
	Resource *string
	Success  *bool
	// ActorType filters by acting-principal kind: "user" or "machine_identity"
	// (also "system"). Nil = all actor types. (ADR-023)
	ActorType *string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int

	// Cursor pagination for incremental SIEM export. When AfterID is set the
	// query returns events with id > *AfterID in ascending id order (a stable
	// forward cursor), ignoring Page. Use with the /audit/export endpoint.
	AfterID   *uint
	Ascending bool
}

// RBACAuditFilter defines filtering options for RBAC audit log queries
type RBACAuditFilter struct {
	UserID     *uint
	Action     *string
	TargetType *string
	TargetID   *uint
	StartTime  *time.Time
	EndTime    *time.Time
	Page       int
	PageSize   int
}

// Scope identifies the project/environment a role assignment or an
// authorization check applies to. It uses a 0 = global/unspecified sentinel,
// matching the stored user_roles/group_roles columns:
//
//	{0, 0}  global — every project and environment
//	{P, 0}  all environments in project P
//	{P, E}  only environment E of project P
//
// A stored assignment authorizes a target scope when its project is global or
// equal AND its environment is global or equal (see GetUserRoleIDsAt).
type Scope struct {
	ProjectID     uint
	EnvironmentID uint
}

// RoleGrant is a single role-to-scope grant applied atomically alongside a user
// creation (ADR-028 atomic provisioning).
type RoleGrant struct {
	RoleID uint
	Scope  Scope
}

// Permission represents a fine-grained permission
type Permission struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// RBACAuditLog represents an RBAC audit log entry
type RBACAuditLog struct {
	ID         uint      `json:"id"`
	UserID     *uint     `json:"user_id"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   *uint     `json:"target_id"`
	TargetName string    `json:"target_name"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	Success    bool      `json:"success"`
	Timestamp  time.Time `json:"timestamp"`
}

// StorageStats provides statistics about the storage system
type StorageStats struct {
	TotalSecrets   int64      `json:"total_secrets"`
	TotalUsers     int64      `json:"total_users"`
	TotalRoles     int64      `json:"total_roles"`
	TotalSessions  int64      `json:"total_sessions"`
	TotalAuditLogs int64      `json:"total_audit_logs"`
	DatabaseSize   int64      `json:"database_size_bytes"`
	LastBackup     *time.Time `json:"last_backup"`
}

// ProjectWithCounts is returned by ListProjectsWithCounts, adding aggregate
// counts so the frontend project list page can show secret/env totals.
type ProjectWithCounts struct {
	ID               uint   `json:"ID"`
	Name             string `json:"Name"`
	Description      string `json:"Description"`
	SecretCount      int64  `json:"secret_count"`
	EnvironmentCount int64  `json:"environment_count"`
	LastActivity     string `json:"last_activity,omitempty"` // most recent of project update or any secret change
	Deleted          bool   `json:"deleted"`                 // true when soft-deleted (only returned when includeDeleted)
	DeletedAt        string `json:"deleted_at,omitempty"`    // RFC3339 timestamp when soft-deleted
}

// SecretUsageStat is one row of the most-accessed-secrets report.
type SecretUsageStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	ReadCount     int64      `json:"read_count"`
	LastRead      *time.Time `json:"last_read"`
}

// AuditRetentionStats holds the raw aggregates backing the audit-retention
// coverage report: how many audit events exist and the timestamps of the
// oldest and newest. Oldest/Newest are nil when the audit table is empty.
type AuditRetentionStats struct {
	TotalEvents int64
	Oldest      *time.Time
	Newest      *time.Time
}

// AuditChainVerification is the verdict of re-walking the audit hash chain
// (ADR-029). Valid is true when every chained event's hash and linkage check
// out. On failure, FirstBrokenID and Reason identify the first divergence.
type AuditChainVerification struct {
	// Valid is true when the chained suffix is intact end to end.
	Valid bool
	// ChainedEvents is the number of hash-chained events verified.
	ChainedEvents int64
	// UnchainedEvents is the leading run of legacy rows (pre-ADR-029, empty
	// hashes) skipped before the chain begins.
	UnchainedEvents int64
	// FirstBrokenID is the id of the first event that failed verification, nil
	// when Valid.
	FirstBrokenID *uint
	// Reason is a human-readable description of the first failure, empty when
	// Valid.
	Reason string
	// HeadHash is the entry_hash of the last chained event (the chain head),
	// genesis when there are no chained events. HeadID is its id. Surfaced so an
	// external monitor can record (ChainedEvents, HeadHash) and detect tail-
	// truncation or a genesis re-seed — which an unanchored on-box re-walk cannot
	// catch on its own (ADR-029): a shorter-but-self-consistent chain still
	// verifies, so the count dropping or the head changing for a known prefix is
	// the off-box tamper signal.
	HeadHash string
	HeadID   uint

	// Checkpointed is true when the live chain was additionally verified against
	// a signed in-DB checkpoint (ADR-029) — an on-box anchor a DBA cannot forge.
	// When a valid checkpoint exists and the chain has dropped below it (or the
	// checkpointed head changed), Valid is false and CheckpointReason explains it.
	// CheckpointReason also carries non-fatal notes (e.g. a checkpoint signed
	// under a superseded key version, which is recorded but not enforced).
	Checkpointed     bool
	CheckpointReason string
}

// UnusedSecretStat is one row of the unused-secrets report. LastRead is nil when
// the secret has never been read.
type UnusedSecretStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	LastRead      *time.Time `json:"last_read"`
}

// ProjectMember is a user who holds a role at a project's scope (ADR-021).
type ProjectMember struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	RoleID      uint   `json:"role_id"`
	RoleName    string `json:"role_name"`
}

// RoleAssignment is one principal↔role grant at a scope — the raw rows behind an
// access review (ISO 27001 A.5.18). Unlike ProjectMember it does NOT collapse a
// principal to a single role: a user/group with several roles at a scope yields
// several RoleAssignments. PrincipalType is "user" or "group".
type RoleAssignment struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id"`
	ProjectID     uint   `json:"project_id"`
	EnvironmentID uint   `json:"environment_id"`
}

// GroupRoleGrant is a role assigned to a group together with the grant's optional
// time-bound expiry (nil = permanent). Mirrors a models.Role plus expires_at so the
// group-roles API can show remaining time on a just-in-time grant.
type GroupRoleGrant struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
