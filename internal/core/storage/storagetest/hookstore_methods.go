// Per-method plumbing for HookStore (see hookstore.go). Mechanically derived from storage.Storage;
// ResolveUserPermissionAt, ResolveMachinePermissionAt and GetSessionAuthLiveness are hand-written there.

package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// StoreHooks holds one optional override per hooked storage.Storage method.
// A nil field delegates to the inner store (HookStore.Storage). `next` is the
// store the receiver wraps (the transaction handle inside WithTransaction).
type StoreHooks struct {
	// WithTransaction overrides the default transaction handling (see HookStore.WithTransaction).
	WithTransaction func(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error
	// WrapTx makes WithTransaction hand the callback a HookStore over the transaction handle carrying these same hooks, so a fault also fires inside the transaction. When false the callback gets the inner store's raw transaction handle, as a promoted method did.
	WrapTx                                    bool
	ActivateMFASecret                         func(next storage.Storage, ctx context.Context, userID uint, secretEnc []byte) (bool, error)
	AddUserToGroup                            func(next storage.Storage, ctx context.Context, userID uint, groupID uint, projectID uint) error
	AdvanceWebAuthnCredentialCounter          func(next storage.Storage, ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (bool, error)
	AssignPermissionToRole                    func(next storage.Storage, ctx context.Context, roleID uint, permissionID uint) error
	AssignRole                                func(next storage.Storage, ctx context.Context, userID uint, roleID uint, scope storage.Scope) error
	AssignRoleToGroup                         func(next storage.Storage, ctx context.Context, groupID uint, roleID uint, scope storage.Scope) error
	AssignRoleWithExpiry                      func(next storage.Storage, ctx context.Context, userID uint, roleID uint, scope storage.Scope, expiresAt time.Time) error
	ClaimPendingAuditEvent                    func(next storage.Storage, ctx context.Context, id uint) (bool, error)
	ClearProjectSecretOwnership               func(next storage.Storage, ctx context.Context, userID uint, projectID uint) error
	ConsumeMFAChallenge                       func(next storage.Storage, ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	ConsumeMFARecoveryCode                    func(next storage.Storage, ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	ConsumeWebAuthnSession                    func(next storage.Storage, ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error)
	CountPendingAuditEvents                   func(next storage.Storage, ctx context.Context) (int64, error)
	DeleteEnvironment                         func(next storage.Storage, ctx context.Context, id uint) error
	OldestPendingAuditEventAt                 func(next storage.Storage, ctx context.Context) (time.Time, bool, error)
	CountRecentLoginAttempts                  func(next storage.Storage, ctx context.Context, ip string, since time.Time) (int64, error)
	CountWebAuthnCredentials                  func(next storage.Storage, ctx context.Context, userID uint) (int64, error)
	CreateAccessRequestApproval               func(next storage.Storage, ctx context.Context, a *models.AccessRequestApproval) error
	CreateAccessReviewItems                   func(next storage.Storage, ctx context.Context, items []*models.AccessReviewItem) error
	CreateAnomalyAlert                        func(next storage.Storage, ctx context.Context, alert *models.AnomalyAlert) error
	CreateEnvironment                         func(next storage.Storage, ctx context.Context, env *models.Environment) (*models.Environment, error)
	CreateMFARecoveryCodes                    func(next storage.Storage, ctx context.Context, userID uint, codeHashes []string) error
	CreateMFAStepUpGrant                      func(next storage.Storage, ctx context.Context, grant *models.MFAStepUpGrant) error
	CreateNotification                        func(next storage.Storage, ctx context.Context, n *models.Notification) (*models.Notification, error)
	CreateOrUpdateSecretACL                   func(next storage.Storage, ctx context.Context, acl *models.SecretACL) error
	CreatePendingAuditEvent                   func(next storage.Storage, ctx context.Context, p *models.PendingAuditEvent) error
	CreateProject                             func(next storage.Storage, ctx context.Context, project *models.Project) (*models.Project, error)
	CreateProjectMembership                   func(next storage.Storage, ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error)
	CreateRotationPolicy                      func(next storage.Storage, ctx context.Context, p *models.RotationPolicy) error
	CreateSecretAccessLog                     func(next storage.Storage, ctx context.Context, log *models.SecretAccessLog) error
	CreateSecret                              func(next storage.Storage, ctx context.Context, secret *models.SecretNode, plaintextValue ...string) (*models.SecretNode, error)
	CreateSecretDependencyExclusive           func(next storage.Storage, ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)
	CreateSecretVersion                       func(next storage.Storage, ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error)
	CreateSession                             func(next storage.Storage, ctx context.Context, session *models.Session) (*models.Session, error)
	CreateSetupToken                          func(next storage.Storage, ctx context.Context, t *models.SetupToken) (*models.SetupToken, error)
	CreateWebAuthnCredential                  func(next storage.Storage, ctx context.Context, c *models.WebAuthnCredential) error
	CreateWebAuthnSession                     func(next storage.Storage, ctx context.Context, s *models.WebAuthnSession) error
	DeleteGroup                               func(next storage.Storage, ctx context.Context, id uint) error
	DeleteMFAForUser                          func(next storage.Storage, ctx context.Context, userID uint) error
	DeleteMFARecoveryCodes                    func(next storage.Storage, ctx context.Context, userID uint) error
	DeleteProject                             func(next storage.Storage, ctx context.Context, id uint) error
	DeleteProjectIfEmpty                      func(next storage.Storage, ctx context.Context, id uint) (int, error)
	DeleteRotationPolicy                      func(next storage.Storage, ctx context.Context, id uint) error
	DeleteSecretACL                           func(next storage.Storage, ctx context.Context, id uint) error
	DeleteSecretACLsByUserAndProject          func(next storage.Storage, ctx context.Context, userID uint, projectID uint) error
	DeleteSessionsForUserExcept               func(next storage.Storage, ctx context.Context, userID uint, exceptID uint) error
	DeleteWebAuthnCredential                  func(next storage.Storage, ctx context.Context, userID uint, id uint) error
	DisableWebAuthnCredential                 func(next storage.Storage, ctx context.Context, id uint) (bool, error)
	EnforceSessionLimit                       func(next storage.Storage, ctx context.Context, userID uint, keep int) error
	GetActiveLegalHold                        func(next storage.Storage, ctx context.Context) (*models.LegalHold, error)
	GetAuditLogs                              func(next storage.Storage, ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error)
	GetDynamicSecretConfig                    func(next storage.Storage, ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	GetEnvironment                            func(next storage.Storage, ctx context.Context, id uint) (*models.Environment, error)
	GetGroupRoles                             func(next storage.Storage, ctx context.Context, groupID uint) ([]*models.Role, error)
	GetLatestSecretVersion                    func(next storage.Storage, ctx context.Context, secretID uint) (*models.SecretVersion, error)
	GetMFASecret                              func(next storage.Storage, ctx context.Context, userID uint) (*models.MFASecret, error)
	GetMachineRoleIDsAt                       func(next storage.Storage, ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error)
	GetMachineRoleScopes                      func(next storage.Storage, ctx context.Context, machineID uint) ([]storage.Scope, error)
	GetRole                                   func(next storage.Storage, ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName                             func(next storage.Storage, ctx context.Context, name string) (*models.Role, error)
	GetRolePermissions                        func(next storage.Storage, ctx context.Context, roleID uint) ([]*models.Permission, error)
	GetSecret                                 func(next storage.Storage, ctx context.Context, id uint) (*models.SecretNode, error)
	GetSecretACL                              func(next storage.Storage, ctx context.Context, secretID uint, userID uint) (*models.SecretACL, error)
	GetSecretAncestors                        func(next storage.Storage, ctx context.Context, nodeID uint) ([]uint, error)
	GetSecretByName                           func(next storage.Storage, ctx context.Context, name string, projectID uint, environmentID uint) (*models.SecretNode, error)
	GetSession                                func(next storage.Storage, ctx context.Context, token string) (*models.Session, error)
	GetSessionAuthLiveness                    func(next storage.Storage, ctx context.Context, userID uint, sessionID uint) (*storage.SessionAuthLiveness, error)
	GetSessionByID                            func(next storage.Storage, ctx context.Context, id uint) (*models.Session, error)
	GetStats                                  func(next storage.Storage, ctx context.Context) (*storage.StorageStats, error)
	GetUser                                   func(next storage.Storage, ctx context.Context, id uint) (*models.User, error)
	GetUserByUsername                         func(next storage.Storage, ctx context.Context, username string) (*models.User, error)
	GetUserGroupRoleIDsAt                     func(next storage.Storage, ctx context.Context, userID uint, scope storage.Scope) ([]uint, error)
	GetUserGroupsAt                           func(next storage.Storage, ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error)
	GetUserPermissions                        func(next storage.Storage, ctx context.Context, userID uint) ([]*storage.Permission, error)
	GetUserRoleIDsAt                          func(next storage.Storage, ctx context.Context, userID uint, scope storage.Scope) ([]uint, error)
	GetUserRoleScopes                         func(next storage.Storage, ctx context.Context, userID uint) ([]storage.Scope, error)
	GetUserRoles                              func(next storage.Storage, ctx context.Context, userID uint) ([]*models.Role, error)
	GetWebAuthnCredentialByCredID             func(next storage.Storage, ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error)
	LastUserRoleManagementActivity            func(next storage.Storage, ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	LastUserSecretDeletionActivity            func(next storage.Storage, ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	LastUserSecretWriteActivity               func(next storage.Storage, ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	ListAdminBypassRoleIDs                    func(next storage.Storage, ctx context.Context) ([]uint, error)
	ListAllUserRoleGrants                     func(next storage.Storage, ctx context.Context) ([]*models.UserRole, error)
	ListDynamicSecretConfigs                  func(next storage.Storage, ctx context.Context, projectID uint, environmentID uint) ([]*models.DynamicSecretConfig, error)
	ListDynamicSecretLeases                   func(next storage.Storage, ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error)
	ListGlobalAdminAssignmentsForUpdate       func(next storage.Storage, ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error)
	ListGroupMembers                          func(next storage.Storage, ctx context.Context, groupID uint) ([]*models.User, error)
	ListGroups                                func(next storage.Storage, ctx context.Context) ([]*models.Group, error)
	ListPendingAuditEvents                    func(next storage.Storage, ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error)
	ListProjectMembers                        func(next storage.Storage, ctx context.Context, projectID uint) ([]storage.ProjectMember, error)
	ListProjectRoleAssignments                func(next storage.Storage, ctx context.Context, projectID uint) ([]storage.RoleAssignment, error)
	ListProjects                              func(next storage.Storage, ctx context.Context) ([]*models.Project, error)
	ListRiskExceptions                        func(next storage.Storage, ctx context.Context, activeOnly bool) ([]*models.RiskException, error)
	ListRotationPolicies                      func(next storage.Storage, ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error)
	ListSecretACLs                            func(next storage.Storage, ctx context.Context, secretID uint) ([]*models.SecretACL, error)
	ListSecretAccessLogs                      func(next storage.Storage, ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	ListSecretIDsAccessedSince                func(next storage.Storage, ctx context.Context, since time.Time) ([]uint, error)
	ListSecrets                               func(next storage.Storage, ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error)
	ListSessionTokenHashesForUser             func(next storage.Storage, ctx context.Context, userID uint) ([]string, error)
	ListSharesByOwner                         func(next storage.Storage, ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesBySecret                        func(next storage.Storage, ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByUser                          func(next storage.Storage, ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSoDPolicies                           func(next storage.Storage, ctx context.Context) ([]*models.SoDPolicy, error)
	ListUnreviewedBreakGlassActivationsBefore func(next storage.Storage, ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error)
	ListUsers                                 func(next storage.Storage, ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error)
	ListWebAuthnCredentials                   func(next storage.Storage, ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error)
	LockMachineIdentityForUpdate              func(next storage.Storage, ctx context.Context, id uint) (*models.MachineIdentity, error)
	LockNamedKeyInTx                          func(next storage.Storage, ctx context.Context, lockKey string) error
	LockUserForUpdate                         func(next storage.Storage, ctx context.Context, id uint) (*models.User, error)
	LogAuditEvent                             func(next storage.Storage, ctx context.Context, event *models.AuditEvent) error
	LogAuditEventWithAccessLog                func(next storage.Storage, ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error
	MarkTOTPStepUsed                          func(next storage.Storage, ctx context.Context, userID uint, step int64) (bool, error)
	RecordDynamicSecretLeaseRevocation        func(next storage.Storage, ctx context.Context, leaseID string, status string, revokeReason string, revokeError string, revokedAt *time.Time) (bool, error)
	RecordLoginAttempt                        func(next storage.Storage, ctx context.Context, ip string, at time.Time) error
	RecordPendingAuditEventFailure            func(next storage.Storage, ctx context.Context, id uint, reason string) error
	ReleaseLoginAttempt                       func(next storage.Storage, ctx context.Context, id uint) error
	RemoveAllProjectRoleGrants                func(next storage.Storage, ctx context.Context, userID uint, projectID uint) error
	RemoveRole                                func(next storage.Storage, ctx context.Context, userID uint, roleID uint, scope storage.Scope) error
	RemoveRoleFromGroup                       func(next storage.Storage, ctx context.Context, groupID uint, roleID uint, scope storage.Scope) error
	RemoveUserFromGroup                       func(next storage.Storage, ctx context.Context, userID uint, groupID uint, projectID uint) error
	ReserveLoginAttempt                       func(next storage.Storage, ctx context.Context, ip string, at time.Time, key string) (uint, error)
	ResolveMachinePermissionAt                func(next storage.Storage, ctx context.Context, machineID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error)
	ResolveUserPermissionAt                   func(next storage.Storage, ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error)
	RestoreGroup                              func(next storage.Storage, ctx context.Context, id uint) error
	RestoreSecret                             func(next storage.Storage, ctx context.Context, id uint) error
	RevokeMachineIdentityCredential           func(next storage.Storage, ctx context.Context, projectID uint, credentialID uint) error
	RoleSetBypassesPermissionChecks           func(next storage.Storage, ctx context.Context, roleIDs []uint) (bool, error)
	RoleSetHasPermission                      func(next storage.Storage, ctx context.Context, roleIDs []uint, permission string) (bool, error)
	RotateSession                             func(next storage.Storage, ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error)
	SetAccountState                           func(next storage.Storage, ctx context.Context, id uint, state string, updatedAt time.Time) error
	SetSecretTags                             func(next storage.Storage, ctx context.Context, secretID uint, tagNames []string) error
	SetSystemMetadata                         func(next storage.Storage, ctx context.Context, key string, value string) error
	SetUserMFAEnabled                         func(next storage.Storage, ctx context.Context, userID uint, enabled bool) error
	SetUserWebAuthnEnabled                    func(next storage.Storage, ctx context.Context, userID uint, enabled bool) error
	SuspendMachineIdentitiesForDeletedProject func(next storage.Storage, ctx context.Context, id uint) ([]*models.MachineIdentity, error)
	UpdateLastLogin                           func(next storage.Storage, ctx context.Context, userID uint, loginAt time.Time) error
	UpdateLoginLockoutState                   func(next storage.Storage, ctx context.Context, id uint, attempts int, lastFailedAt *time.Time, lockedUntil *time.Time, lockoutCount int) error
	UpdateRotationPolicyFields                func(next storage.Storage, ctx context.Context, id uint, f storage.RotationPolicyFieldUpdate, updatedAt time.Time) (bool, error)
	UpdateSecretFields                        func(next storage.Storage, ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error)
	UpdateUser                                func(next storage.Storage, ctx context.Context, user *models.User) (*models.User, error)
	VerifyAuditChain                          func(next storage.Storage, ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error)
	VerifyAuditChainSegment                   func(next storage.Storage, ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error)
	WithNamedLock                             func(next storage.Storage, ctx context.Context, lockKey string, fn func(ctx context.Context) error) error
}
