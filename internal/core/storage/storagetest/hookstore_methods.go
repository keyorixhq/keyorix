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
	AssignRoleWithExpiry                      func(next storage.Storage, ctx context.Context, userID uint, roleID uint, scope storage.Scope, expiresAt time.Time) error
	ClaimPendingAuditEvent                    func(next storage.Storage, ctx context.Context, id uint) (bool, error)
	ClearProjectSecretOwnership               func(next storage.Storage, ctx context.Context, userID uint, projectID uint) error
	ConsumeMFAChallenge                       func(next storage.Storage, ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	ConsumeMFARecoveryCode                    func(next storage.Storage, ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	ConsumeWebAuthnSession                    func(next storage.Storage, ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error)
	CountPendingAuditEvents                   func(next storage.Storage, ctx context.Context) (int64, error)
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

func (hs *HookStore) ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (bool, error) {
	if hk := hs.h.ActivateMFASecret; hk != nil {
		return hk(hs.Storage, ctx, userID, secretEnc)
	}
	return hs.Storage.ActivateMFASecret(ctx, userID, secretEnc)
}

func (hs *HookStore) AddUserToGroup(ctx context.Context, userID uint, groupID uint, projectID uint) error {
	if hk := hs.h.AddUserToGroup; hk != nil {
		return hk(hs.Storage, ctx, userID, groupID, projectID)
	}
	return hs.Storage.AddUserToGroup(ctx, userID, groupID, projectID)
}

func (hs *HookStore) AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (bool, error) {
	if hk := hs.h.AdvanceWebAuthnCredentialCounter; hk != nil {
		return hk(hs.Storage, ctx, credentialID, userID, newBlob, newSignCount, lastUsedAt)
	}
	return hs.Storage.AdvanceWebAuthnCredentialCounter(ctx, credentialID, userID, newBlob, newSignCount, lastUsedAt)
}

func (hs *HookStore) AssignPermissionToRole(ctx context.Context, roleID uint, permissionID uint) error {
	if hk := hs.h.AssignPermissionToRole; hk != nil {
		return hk(hs.Storage, ctx, roleID, permissionID)
	}
	return hs.Storage.AssignPermissionToRole(ctx, roleID, permissionID)
}

func (hs *HookStore) AssignRole(ctx context.Context, userID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.AssignRole; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope)
	}
	return hs.Storage.AssignRole(ctx, userID, roleID, scope)
}

func (hs *HookStore) AssignRoleWithExpiry(ctx context.Context, userID uint, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	if hk := hs.h.AssignRoleWithExpiry; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope, expiresAt)
	}
	return hs.Storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt)
}

func (hs *HookStore) ClaimPendingAuditEvent(ctx context.Context, id uint) (bool, error) {
	if hk := hs.h.ClaimPendingAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.ClaimPendingAuditEvent(ctx, id)
}

func (hs *HookStore) ClearProjectSecretOwnership(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.ClearProjectSecretOwnership; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.ClearProjectSecretOwnership(ctx, userID, projectID)
}

func (hs *HookStore) ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	if hk := hs.h.ConsumeMFAChallenge; hk != nil {
		return hk(hs.Storage, ctx, tokenHash, now)
	}
	return hs.Storage.ConsumeMFAChallenge(ctx, tokenHash, now)
}

func (hs *HookStore) ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error) {
	if hk := hs.h.ConsumeMFARecoveryCode; hk != nil {
		return hk(hs.Storage, ctx, userID, codeHash, now)
	}
	return hs.Storage.ConsumeMFARecoveryCode(ctx, userID, codeHash, now)
}

func (hs *HookStore) ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error) {
	if hk := hs.h.ConsumeWebAuthnSession; hk != nil {
		return hk(hs.Storage, ctx, tokenHash, now)
	}
	return hs.Storage.ConsumeWebAuthnSession(ctx, tokenHash, now)
}

func (hs *HookStore) CountPendingAuditEvents(ctx context.Context) (int64, error) {
	if hk := hs.h.CountPendingAuditEvents; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.CountPendingAuditEvents(ctx)
}

func (hs *HookStore) OldestPendingAuditEventAt(ctx context.Context) (time.Time, bool, error) {
	if hk := hs.h.OldestPendingAuditEventAt; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.OldestPendingAuditEventAt(ctx)
}

func (hs *HookStore) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	if hk := hs.h.CountRecentLoginAttempts; hk != nil {
		return hk(hs.Storage, ctx, ip, since)
	}
	return hs.Storage.CountRecentLoginAttempts(ctx, ip, since)
}

func (hs *HookStore) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	if hk := hs.h.CountWebAuthnCredentials; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.CountWebAuthnCredentials(ctx, userID)
}

func (hs *HookStore) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	if hk := hs.h.CreateAccessRequestApproval; hk != nil {
		return hk(hs.Storage, ctx, a)
	}
	return hs.Storage.CreateAccessRequestApproval(ctx, a)
}

func (hs *HookStore) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if hk := hs.h.CreateAccessReviewItems; hk != nil {
		return hk(hs.Storage, ctx, items)
	}
	return hs.Storage.CreateAccessReviewItems(ctx, items)
}

func (hs *HookStore) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	if hk := hs.h.CreateAnomalyAlert; hk != nil {
		return hk(hs.Storage, ctx, alert)
	}
	return hs.Storage.CreateAnomalyAlert(ctx, alert)
}

func (hs *HookStore) CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error) {
	if hk := hs.h.CreateEnvironment; hk != nil {
		return hk(hs.Storage, ctx, env)
	}
	return hs.Storage.CreateEnvironment(ctx, env)
}

func (hs *HookStore) CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error {
	if hk := hs.h.CreateMFARecoveryCodes; hk != nil {
		return hk(hs.Storage, ctx, userID, codeHashes)
	}
	return hs.Storage.CreateMFARecoveryCodes(ctx, userID, codeHashes)
}

func (hs *HookStore) CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error {
	if hk := hs.h.CreateMFAStepUpGrant; hk != nil {
		return hk(hs.Storage, ctx, grant)
	}
	return hs.Storage.CreateMFAStepUpGrant(ctx, grant)
}

func (hs *HookStore) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	if hk := hs.h.CreateNotification; hk != nil {
		return hk(hs.Storage, ctx, n)
	}
	return hs.Storage.CreateNotification(ctx, n)
}

func (hs *HookStore) CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error {
	if hk := hs.h.CreateOrUpdateSecretACL; hk != nil {
		return hk(hs.Storage, ctx, acl)
	}
	return hs.Storage.CreateOrUpdateSecretACL(ctx, acl)
}

func (hs *HookStore) CreatePendingAuditEvent(ctx context.Context, p *models.PendingAuditEvent) error {
	if hk := hs.h.CreatePendingAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, p)
	}
	return hs.Storage.CreatePendingAuditEvent(ctx, p)
}

func (hs *HookStore) CreateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if hk := hs.h.CreateProject; hk != nil {
		return hk(hs.Storage, ctx, project)
	}
	return hs.Storage.CreateProject(ctx, project)
}

func (hs *HookStore) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	if hk := hs.h.CreateProjectMembership; hk != nil {
		return hk(hs.Storage, ctx, m)
	}
	return hs.Storage.CreateProjectMembership(ctx, m)
}

func (hs *HookStore) CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	if hk := hs.h.CreateRotationPolicy; hk != nil {
		return hk(hs.Storage, ctx, p)
	}
	return hs.Storage.CreateRotationPolicy(ctx, p)
}

func (hs *HookStore) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	if hk := hs.h.CreateSecretAccessLog; hk != nil {
		return hk(hs.Storage, ctx, log)
	}
	return hs.Storage.CreateSecretAccessLog(ctx, log)
}

func (hs *HookStore) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if hk := hs.h.CreateSecretVersion; hk != nil {
		return hk(hs.Storage, ctx, version)
	}
	return hs.Storage.CreateSecretVersion(ctx, version)
}

func (hs *HookStore) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if hk := hs.h.CreateSession; hk != nil {
		return hk(hs.Storage, ctx, session)
	}
	return hs.Storage.CreateSession(ctx, session)
}

func (hs *HookStore) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	if hk := hs.h.CreateSetupToken; hk != nil {
		return hk(hs.Storage, ctx, t)
	}
	return hs.Storage.CreateSetupToken(ctx, t)
}

func (hs *HookStore) CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	if hk := hs.h.CreateWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, c)
	}
	return hs.Storage.CreateWebAuthnCredential(ctx, c)
}

func (hs *HookStore) CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error {
	if hk := hs.h.CreateWebAuthnSession; hk != nil {
		return hk(hs.Storage, ctx, s)
	}
	return hs.Storage.CreateWebAuthnSession(ctx, s)
}

func (hs *HookStore) DeleteGroup(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteGroup; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteGroup(ctx, id)
}

func (hs *HookStore) DeleteMFAForUser(ctx context.Context, userID uint) error {
	if hk := hs.h.DeleteMFAForUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.DeleteMFAForUser(ctx, userID)
}

func (hs *HookStore) DeleteMFARecoveryCodes(ctx context.Context, userID uint) error {
	if hk := hs.h.DeleteMFARecoveryCodes; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.DeleteMFARecoveryCodes(ctx, userID)
}

func (hs *HookStore) DeleteProject(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteProject; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteProject(ctx, id)
}

func (hs *HookStore) DeleteProjectIfEmpty(ctx context.Context, id uint) (int, error) {
	if hk := hs.h.DeleteProjectIfEmpty; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteProjectIfEmpty(ctx, id)
}

func (hs *HookStore) DeleteRotationPolicy(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteRotationPolicy; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteRotationPolicy(ctx, id)
}

func (hs *HookStore) DeleteSecretACL(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteSecretACL; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteSecretACL(ctx, id)
}

func (hs *HookStore) DeleteSecretACLsByUserAndProject(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.DeleteSecretACLsByUserAndProject; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.DeleteSecretACLsByUserAndProject(ctx, userID, projectID)
}

func (hs *HookStore) DeleteSessionsForUserExcept(ctx context.Context, userID uint, exceptID uint) error {
	if hk := hs.h.DeleteSessionsForUserExcept; hk != nil {
		return hk(hs.Storage, ctx, userID, exceptID)
	}
	return hs.Storage.DeleteSessionsForUserExcept(ctx, userID, exceptID)
}

func (hs *HookStore) DeleteWebAuthnCredential(ctx context.Context, userID uint, id uint) error {
	if hk := hs.h.DeleteWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, userID, id)
	}
	return hs.Storage.DeleteWebAuthnCredential(ctx, userID, id)
}

func (hs *HookStore) DisableWebAuthnCredential(ctx context.Context, id uint) (bool, error) {
	if hk := hs.h.DisableWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DisableWebAuthnCredential(ctx, id)
}

func (hs *HookStore) EnforceSessionLimit(ctx context.Context, userID uint, keep int) error {
	if hk := hs.h.EnforceSessionLimit; hk != nil {
		return hk(hs.Storage, ctx, userID, keep)
	}
	return hs.Storage.EnforceSessionLimit(ctx, userID, keep)
}

func (hs *HookStore) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	if hk := hs.h.GetActiveLegalHold; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.GetActiveLegalHold(ctx)
}

func (hs *HookStore) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	if hk := hs.h.GetAuditLogs; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.GetAuditLogs(ctx, filter)
}

func (hs *HookStore) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	if hk := hs.h.GetDynamicSecretConfig; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetDynamicSecretConfig(ctx, id)
}

func (hs *HookStore) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	if hk := hs.h.GetEnvironment; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetEnvironment(ctx, id)
}

func (hs *HookStore) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	if hk := hs.h.GetGroupRoles; hk != nil {
		return hk(hs.Storage, ctx, groupID)
	}
	return hs.Storage.GetGroupRoles(ctx, groupID)
}

func (hs *HookStore) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if hk := hs.h.GetLatestSecretVersion; hk != nil {
		return hk(hs.Storage, ctx, secretID)
	}
	return hs.Storage.GetLatestSecretVersion(ctx, secretID)
}

func (hs *HookStore) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	if hk := hs.h.GetMFASecret; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetMFASecret(ctx, userID)
}

func (hs *HookStore) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetMachineRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, machineID, scope)
	}
	return hs.Storage.GetMachineRoleIDsAt(ctx, machineID, scope)
}

func (hs *HookStore) GetMachineRoleScopes(ctx context.Context, machineID uint) ([]storage.Scope, error) {
	if hk := hs.h.GetMachineRoleScopes; hk != nil {
		return hk(hs.Storage, ctx, machineID)
	}
	return hs.Storage.GetMachineRoleScopes(ctx, machineID)
}

func (hs *HookStore) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if hk := hs.h.GetRole; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetRole(ctx, id)
}

func (hs *HookStore) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	if hk := hs.h.GetRoleByName; hk != nil {
		return hk(hs.Storage, ctx, name)
	}
	return hs.Storage.GetRoleByName(ctx, name)
}

func (hs *HookStore) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	if hk := hs.h.GetRolePermissions; hk != nil {
		return hk(hs.Storage, ctx, roleID)
	}
	return hs.Storage.GetRolePermissions(ctx, roleID)
}

func (hs *HookStore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if hk := hs.h.GetSecret; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetSecret(ctx, id)
}

func (hs *HookStore) GetSecretACL(ctx context.Context, secretID uint, userID uint) (*models.SecretACL, error) {
	if hk := hs.h.GetSecretACL; hk != nil {
		return hk(hs.Storage, ctx, secretID, userID)
	}
	return hs.Storage.GetSecretACL(ctx, secretID, userID)
}

func (hs *HookStore) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	if hk := hs.h.GetSecretAncestors; hk != nil {
		return hk(hs.Storage, ctx, nodeID)
	}
	return hs.Storage.GetSecretAncestors(ctx, nodeID)
}

func (hs *HookStore) GetSecretByName(ctx context.Context, name string, projectID uint, environmentID uint) (*models.SecretNode, error) {
	if hk := hs.h.GetSecretByName; hk != nil {
		return hk(hs.Storage, ctx, name, projectID, environmentID)
	}
	return hs.Storage.GetSecretByName(ctx, name, projectID, environmentID)
}

func (hs *HookStore) GetSession(ctx context.Context, token string) (*models.Session, error) {
	if hk := hs.h.GetSession; hk != nil {
		return hk(hs.Storage, ctx, token)
	}
	return hs.Storage.GetSession(ctx, token)
}

func (hs *HookStore) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	if hk := hs.h.GetSessionByID; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetSessionByID(ctx, id)
}

func (hs *HookStore) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	if hk := hs.h.GetStats; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.GetStats(ctx)
}

func (hs *HookStore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if hk := hs.h.GetUser; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetUser(ctx, id)
}

func (hs *HookStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if hk := hs.h.GetUserByUsername; hk != nil {
		return hk(hs.Storage, ctx, username)
	}
	return hs.Storage.GetUserByUsername(ctx, username)
}

func (hs *HookStore) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetUserGroupRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserGroupRoleIDsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserGroupsAt(ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error) {
	if hk := hs.h.GetUserGroupsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserGroupsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	if hk := hs.h.GetUserPermissions; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserPermissions(ctx, userID)
}

func (hs *HookStore) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetUserRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserRoleIDsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	if hk := hs.h.GetUserRoleScopes; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserRoleScopes(ctx, userID)
}

func (hs *HookStore) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	if hk := hs.h.GetUserRoles; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserRoles(ctx, userID)
}

func (hs *HookStore) GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	if hk := hs.h.GetWebAuthnCredentialByCredID; hk != nil {
		return hk(hs.Storage, ctx, credentialID, userID)
	}
	return hs.Storage.GetWebAuthnCredentialByCredID(ctx, credentialID, userID)
}

func (hs *HookStore) LastUserRoleManagementActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserRoleManagementActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserRoleManagementActivity(ctx, projectID, since)
}

func (hs *HookStore) LastUserSecretDeletionActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserSecretDeletionActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserSecretDeletionActivity(ctx, projectID, since)
}

func (hs *HookStore) LastUserSecretWriteActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	if hk := hs.h.LastUserSecretWriteActivity; hk != nil {
		return hk(hs.Storage, ctx, projectID, since)
	}
	return hs.Storage.LastUserSecretWriteActivity(ctx, projectID, since)
}

func (hs *HookStore) ListAdminBypassRoleIDs(ctx context.Context) ([]uint, error) {
	if hk := hs.h.ListAdminBypassRoleIDs; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListAdminBypassRoleIDs(ctx)
}

func (hs *HookStore) ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error) {
	if hk := hs.h.ListAllUserRoleGrants; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListAllUserRoleGrants(ctx)
}

func (hs *HookStore) ListDynamicSecretConfigs(ctx context.Context, projectID uint, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	if hk := hs.h.ListDynamicSecretConfigs; hk != nil {
		return hk(hs.Storage, ctx, projectID, environmentID)
	}
	return hs.Storage.ListDynamicSecretConfigs(ctx, projectID, environmentID)
}

func (hs *HookStore) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	if hk := hs.h.ListDynamicSecretLeases; hk != nil {
		return hk(hs.Storage, ctx, configID)
	}
	return hs.Storage.ListDynamicSecretLeases(ctx, configID)
}

func (hs *HookStore) ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error) {
	if hk := hs.h.ListGlobalAdminAssignmentsForUpdate; hk != nil {
		return hk(hs.Storage, ctx, adminRoleIDs)
	}
	return hs.Storage.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
}

func (hs *HookStore) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if hk := hs.h.ListGroupMembers; hk != nil {
		return hk(hs.Storage, ctx, groupID)
	}
	return hs.Storage.ListGroupMembers(ctx, groupID)
}

func (hs *HookStore) ListGroups(ctx context.Context) ([]*models.Group, error) {
	if hk := hs.h.ListGroups; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListGroups(ctx)
}

func (hs *HookStore) ListPendingAuditEvents(ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error) {
	if hk := hs.h.ListPendingAuditEvents; hk != nil {
		return hk(hs.Storage, ctx, afterID, limit)
	}
	return hs.Storage.ListPendingAuditEvents(ctx, afterID, limit)
}

func (hs *HookStore) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	if hk := hs.h.ListProjectMembers; hk != nil {
		return hk(hs.Storage, ctx, projectID)
	}
	return hs.Storage.ListProjectMembers(ctx, projectID)
}

func (hs *HookStore) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	if hk := hs.h.ListProjectRoleAssignments; hk != nil {
		return hk(hs.Storage, ctx, projectID)
	}
	return hs.Storage.ListProjectRoleAssignments(ctx, projectID)
}

func (hs *HookStore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	if hk := hs.h.ListProjects; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListProjects(ctx)
}

func (hs *HookStore) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	if hk := hs.h.ListRiskExceptions; hk != nil {
		return hk(hs.Storage, ctx, activeOnly)
	}
	return hs.Storage.ListRiskExceptions(ctx, activeOnly)
}

func (hs *HookStore) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	if hk := hs.h.ListRotationPolicies; hk != nil {
		return hk(hs.Storage, ctx, projectID, environmentID)
	}
	return hs.Storage.ListRotationPolicies(ctx, projectID, environmentID)
}

func (hs *HookStore) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	if hk := hs.h.ListSecretACLs; hk != nil {
		return hk(hs.Storage, ctx, secretID)
	}
	return hs.Storage.ListSecretACLs(ctx, secretID)
}

func (hs *HookStore) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	if hk := hs.h.ListSecretAccessLogs; hk != nil {
		return hk(hs.Storage, ctx, secretID, since)
	}
	return hs.Storage.ListSecretAccessLogs(ctx, secretID, since)
}

func (hs *HookStore) ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error) {
	if hk := hs.h.ListSecretIDsAccessedSince; hk != nil {
		return hk(hs.Storage, ctx, since)
	}
	return hs.Storage.ListSecretIDsAccessedSince(ctx, since)
}

func (hs *HookStore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if hk := hs.h.ListSecrets; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.ListSecrets(ctx, filter)
}

func (hs *HookStore) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	if hk := hs.h.ListSessionTokenHashesForUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.ListSessionTokenHashesForUser(ctx, userID)
}

func (hs *HookStore) ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesByOwner; hk != nil {
		return hk(hs.Storage, ctx, ownerID, now)
	}
	return hs.Storage.ListSharesByOwner(ctx, ownerID, now)
}

func (hs *HookStore) ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesBySecret; hk != nil {
		return hk(hs.Storage, ctx, secretID, now)
	}
	return hs.Storage.ListSharesBySecret(ctx, secretID, now)
}

func (hs *HookStore) ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesByUser; hk != nil {
		return hk(hs.Storage, ctx, userID, now)
	}
	return hs.Storage.ListSharesByUser(ctx, userID, now)
}

func (hs *HookStore) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	if hk := hs.h.ListSoDPolicies; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListSoDPolicies(ctx)
}

func (hs *HookStore) ListUnreviewedBreakGlassActivationsBefore(ctx context.Context, cutoff time.Time) ([]*models.BreakGlassActivation, error) {
	if hk := hs.h.ListUnreviewedBreakGlassActivationsBefore; hk != nil {
		return hk(hs.Storage, ctx, cutoff)
	}
	return hs.Storage.ListUnreviewedBreakGlassActivationsBefore(ctx, cutoff)
}

func (hs *HookStore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if hk := hs.h.ListUsers; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.ListUsers(ctx, filter)
}

func (hs *HookStore) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	if hk := hs.h.ListWebAuthnCredentials; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.ListWebAuthnCredentials(ctx, userID)
}

func (hs *HookStore) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	if hk := hs.h.LockUserForUpdate; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.LockUserForUpdate(ctx, id)
}

func (hs *HookStore) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	if hk := hs.h.LogAuditEvent; hk != nil {
		return hk(hs.Storage, ctx, event)
	}
	return hs.Storage.LogAuditEvent(ctx, event)
}

func (hs *HookStore) LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	if hk := hs.h.LogAuditEventWithAccessLog; hk != nil {
		return hk(hs.Storage, ctx, event, accessLog)
	}
	return hs.Storage.LogAuditEventWithAccessLog(ctx, event, accessLog)
}

func (hs *HookStore) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if hk := hs.h.MarkTOTPStepUsed; hk != nil {
		return hk(hs.Storage, ctx, userID, step)
	}
	return hs.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

func (hs *HookStore) RecordDynamicSecretLeaseRevocation(ctx context.Context, leaseID string, status string, revokeReason string, revokeError string, revokedAt *time.Time) (bool, error) {
	if hk := hs.h.RecordDynamicSecretLeaseRevocation; hk != nil {
		return hk(hs.Storage, ctx, leaseID, status, revokeReason, revokeError, revokedAt)
	}
	return hs.Storage.RecordDynamicSecretLeaseRevocation(ctx, leaseID, status, revokeReason, revokeError, revokedAt)
}

func (hs *HookStore) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	if hk := hs.h.RecordLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, ip, at)
	}
	return hs.Storage.RecordLoginAttempt(ctx, ip, at)
}

func (hs *HookStore) RecordPendingAuditEventFailure(ctx context.Context, id uint, reason string) error {
	if hk := hs.h.RecordPendingAuditEventFailure; hk != nil {
		return hk(hs.Storage, ctx, id, reason)
	}
	return hs.Storage.RecordPendingAuditEventFailure(ctx, id, reason)
}

func (hs *HookStore) ReleaseLoginAttempt(ctx context.Context, id uint) error {
	if hk := hs.h.ReleaseLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.ReleaseLoginAttempt(ctx, id)
}

func (hs *HookStore) RemoveAllProjectRoleGrants(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.RemoveAllProjectRoleGrants; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.RemoveAllProjectRoleGrants(ctx, userID, projectID)
}

func (hs *HookStore) RemoveRole(ctx context.Context, userID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.RemoveRole; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope)
	}
	return hs.Storage.RemoveRole(ctx, userID, roleID, scope)
}

func (hs *HookStore) RemoveRoleFromGroup(ctx context.Context, groupID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.RemoveRoleFromGroup; hk != nil {
		return hk(hs.Storage, ctx, groupID, roleID, scope)
	}
	return hs.Storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope)
}

func (hs *HookStore) RemoveUserFromGroup(ctx context.Context, userID uint, groupID uint, projectID uint) error {
	if hk := hs.h.RemoveUserFromGroup; hk != nil {
		return hk(hs.Storage, ctx, userID, groupID, projectID)
	}
	return hs.Storage.RemoveUserFromGroup(ctx, userID, groupID, projectID)
}

func (hs *HookStore) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (uint, error) {
	if hk := hs.h.ReserveLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, ip, at, key)
	}
	return hs.Storage.ReserveLoginAttempt(ctx, ip, at, key)
}

func (hs *HookStore) RestoreGroup(ctx context.Context, id uint) error {
	if hk := hs.h.RestoreGroup; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.RestoreGroup(ctx, id)
}

func (hs *HookStore) RevokeMachineIdentityCredential(ctx context.Context, projectID uint, credentialID uint) error {
	if hk := hs.h.RevokeMachineIdentityCredential; hk != nil {
		return hk(hs.Storage, ctx, projectID, credentialID)
	}
	return hs.Storage.RevokeMachineIdentityCredential(ctx, projectID, credentialID)
}

func (hs *HookStore) RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error) {
	if hk := hs.h.RoleSetBypassesPermissionChecks; hk != nil {
		return hk(hs.Storage, ctx, roleIDs)
	}
	return hs.Storage.RoleSetBypassesPermissionChecks(ctx, roleIDs)
}

func (hs *HookStore) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	if hk := hs.h.RoleSetHasPermission; hk != nil {
		return hk(hs.Storage, ctx, roleIDs, permission)
	}
	return hs.Storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

func (hs *HookStore) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	if hk := hs.h.RotateSession; hk != nil {
		return hk(hs.Storage, ctx, oldID, newSession, now)
	}
	return hs.Storage.RotateSession(ctx, oldID, newSession, now)
}

func (hs *HookStore) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	if hk := hs.h.SetAccountState; hk != nil {
		return hk(hs.Storage, ctx, id, state, updatedAt)
	}
	return hs.Storage.SetAccountState(ctx, id, state, updatedAt)
}

func (hs *HookStore) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	if hk := hs.h.SetSecretTags; hk != nil {
		return hk(hs.Storage, ctx, secretID, tagNames)
	}
	return hs.Storage.SetSecretTags(ctx, secretID, tagNames)
}

func (hs *HookStore) SetSystemMetadata(ctx context.Context, key string, value string) error {
	if hk := hs.h.SetSystemMetadata; hk != nil {
		return hk(hs.Storage, ctx, key, value)
	}
	return hs.Storage.SetSystemMetadata(ctx, key, value)
}

func (hs *HookStore) SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error {
	if hk := hs.h.SetUserMFAEnabled; hk != nil {
		return hk(hs.Storage, ctx, userID, enabled)
	}
	return hs.Storage.SetUserMFAEnabled(ctx, userID, enabled)
}

func (hs *HookStore) SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error {
	if hk := hs.h.SetUserWebAuthnEnabled; hk != nil {
		return hk(hs.Storage, ctx, userID, enabled)
	}
	return hs.Storage.SetUserWebAuthnEnabled(ctx, userID, enabled)
}

func (hs *HookStore) SuspendMachineIdentitiesForDeletedProject(ctx context.Context, id uint) ([]*models.MachineIdentity, error) {
	if hk := hs.h.SuspendMachineIdentitiesForDeletedProject; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.SuspendMachineIdentitiesForDeletedProject(ctx, id)
}

func (hs *HookStore) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	if hk := hs.h.UpdateLastLogin; hk != nil {
		return hk(hs.Storage, ctx, userID, loginAt)
	}
	return hs.Storage.UpdateLastLogin(ctx, userID, loginAt)
}

func (hs *HookStore) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt *time.Time, lockedUntil *time.Time, lockoutCount int) error {
	if hk := hs.h.UpdateLoginLockoutState; hk != nil {
		return hk(hs.Storage, ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
	}
	return hs.Storage.UpdateLoginLockoutState(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
}

func (hs *HookStore) UpdateRotationPolicyFields(ctx context.Context, id uint, f storage.RotationPolicyFieldUpdate, updatedAt time.Time) (bool, error) {
	if hk := hs.h.UpdateRotationPolicyFields; hk != nil {
		return hk(hs.Storage, ctx, id, f, updatedAt)
	}
	return hs.Storage.UpdateRotationPolicyFields(ctx, id, f, updatedAt)
}

func (hs *HookStore) UpdateSecretFields(ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
	if hk := hs.h.UpdateSecretFields; hk != nil {
		return hk(hs.Storage, ctx, id, f)
	}
	return hs.Storage.UpdateSecretFields(ctx, id, f)
}

func (hs *HookStore) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if hk := hs.h.UpdateUser; hk != nil {
		return hk(hs.Storage, ctx, user)
	}
	return hs.Storage.UpdateUser(ctx, user)
}

func (hs *HookStore) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	if hk := hs.h.VerifyAuditChain; hk != nil {
		return hk(hs.Storage, ctx, anchor)
	}
	return hs.Storage.VerifyAuditChain(ctx, anchor)
}

func (hs *HookStore) VerifyAuditChainSegment(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	if hk := hs.h.VerifyAuditChainSegment; hk != nil {
		return hk(hs.Storage, ctx, seg)
	}
	return hs.Storage.VerifyAuditChainSegment(ctx, seg)
}

func (hs *HookStore) WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
	if hk := hs.h.WithNamedLock; hk != nil {
		return hk(hs.Storage, ctx, lockKey, fn)
	}
	return hs.Storage.WithNamedLock(ctx, lockKey, fn)
}
