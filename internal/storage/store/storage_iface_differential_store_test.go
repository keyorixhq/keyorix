package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ifaceStore is exactly the storage surface this harness drives, not the whole
// storage.Storage (a repo guard forbids embedding that in a test double). The red-proof
// tests wrap it to break one method on one backend.
type ifaceStore interface {
	CreateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	DeleteProject(ctx context.Context, id uint) error
	GetProjectByName(ctx context.Context, name string) (*models.Project, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	GetEnvironment(ctx context.Context, id uint) (*models.Environment, error)
	DeleteEnvironment(ctx context.Context, id uint) error
	RestoreEnvironment(ctx context.Context, projectID, id uint) error
	ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error)
	CreateUser(ctx context.Context, user *models.User, passwordHash ...string) (*models.User, error)
	CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	DeleteGroup(ctx context.Context, id uint) error
	RestoreGroup(ctx context.Context, id uint) error
	GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)
	ListAllUserGroupMemberships(ctx context.Context) ([]storage.UserGroupMembership, error)
	AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error
	ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)
	ListGroupMembersAt(ctx context.Context, groupID uint, scope storage.Scope) ([]*models.User, error)
	CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error)
	GetRole(ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	DeleteRole(ctx context.Context, id uint) (storage.RoleDeleteCascadeCounts, error)
	ListRoles(ctx context.Context) ([]*models.Role, error)
	CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error)
	GetPermission(ctx context.Context, id uint) (*models.Permission, error)
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error
	GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
	AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error
	AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error
	RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error)
	GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error)
	ListUserRoleGrants(ctx context.Context, userID uint) ([]storage.UserRoleGrant, error)
	ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error)
	ListExpiringUserRoles(ctx context.Context, before time.Time) ([]models.UserRole, error)
	DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error
	AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error
	GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error)
	GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error)
	ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error)
	GetUserGroupsAt(ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error)
	CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error)
	GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error)
	TransitionProjectMembershipState(ctx context.Context, m *models.ProjectMembership, fromState string) (bool, error)
	ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error)
	GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error)
	ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error)
	ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error)
	CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error)
	IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error)
	ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error)
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	GetSession(ctx context.Context, token string) (*models.Session, error)
	GetSessionAny(ctx context.Context, token string) (*models.Session, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
	ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error)
	EnforceSessionLimit(ctx context.Context, userID uint, keep int) error
	RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error)
	ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error)
	DeleteSessionsByFamily(ctx context.Context, familyID string) error
	TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error
	CleanupExpiredSessions(ctx context.Context) error
	CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, id uint) error
	ListExpiringPATs(ctx context.Context, before time.Time) ([]models.PersonalAccessToken, error)
	ListExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]*models.PersonalAccessToken, error)
	BulkRevokeExpiredPATsByUser(ctx context.Context, userID uint, now time.Time) ([]string, error)
	CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error)
	GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error)
	SupersedeActiveSetupTokens(ctx context.Context, purpose, email string, projectID *uint) error
	MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error)
	CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error)
	UpsertMFASecret(ctx context.Context, s *models.MFASecret) error
	GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error)
	ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (bool, error)
	MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error)
	ReleaseTOTPStepIfUnchanged(ctx context.Context, userID uint, step int64) (bool, error)
	CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error
	ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error)
	CountUnusedMFARecoveryCodes(ctx context.Context, userID uint) (int, error)
	UpsertMFAStepupToken(ctx context.Context, userID uint, expiresAt time.Time) error
	HasActiveMFAStepup(ctx context.Context, userID uint) (bool, error)
	CreateMFAChallenge(ctx context.Context, c *models.MFAChallenge) error
	ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error)
	CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error
	GetActiveMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (*models.MFAStepUpGrant, error)
	PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error)
	GetSystemMetadata(ctx context.Context, key string) (string, bool, error)
	SetSystemMetadata(ctx context.Context, key, value string) error
	CompareAndSetSystemMetadata(ctx context.Context, key, old string, oldFound bool, value string) (bool, error)
	RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error
	CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error)
	PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error)
	ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (uint, error)
	ReleaseLoginAttempt(ctx context.Context, id uint) error
	CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error)
	ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadNotifications(ctx context.Context, userID uint) (int64, error)
	HasUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (bool, error)
	GetUnreadNotification(ctx context.Context, userID uint, nType string, projectID uint) (*models.Notification, error)
	MarkNotificationRead(ctx context.Context, id, userID uint) error
	MarkAllNotificationsRead(ctx context.Context, userID uint) error
	ListScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope, unreadOnly bool, limit int) ([]*models.Notification, error)
	CountUnreadScopedNotifications(ctx context.Context, userID uint, scope storage.NotificationScope) (int64, error)
	MarkAllScopedNotificationsRead(ctx context.Context, userID uint, scope storage.NotificationScope) error
	ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id uint) (*models.NotificationChannel, error)
	GetNotificationChannelByName(ctx context.Context, name string) (*models.NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	UpdateNotificationChannel(ctx context.Context, ch *models.NotificationChannel) error
	DeleteNotificationChannel(ctx context.Context, id uint) error
	UpdateNotificationRetryPolicy(ctx context.Context, channelID uint, maxRetries, backoffMs int) error
	CreateSecretTemplate(ctx context.Context, t *models.SecretTemplate) error
	GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error)
	GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error)
	ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error)
	UpdateSecretTemplateFields(ctx context.Context, id uint, f storage.SecretTemplateFieldUpdate, updatedAt time.Time) (bool, error)
	DeleteSecretTemplate(ctx context.Context, id uint) error
	CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error
	ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error)
	ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error)
	GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error)
	DeleteSecretACL(ctx context.Context, id uint) error
	DeleteSecretACLsByUserAndProject(ctx context.Context, userID, projectID uint) error
	CreateSecret(ctx context.Context, n *models.SecretNode, tags ...string) (*models.SecretNode, error)
	ListSecrets(ctx context.Context, f *storage.SecretFilter) ([]*models.SecretNode, int64, error)
	CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	DeleteShareRecord(ctx context.Context, shareID uint) error
	ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error)
	ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error)
	CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error)
	DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error)
	ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error)
	CreateConnectRefGrant(ctx context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error)
	ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error)
	ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error)
	DeleteConnectRefGrant(ctx context.Context, id uint) error
	CreateConnectorProjectBinding(ctx context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error)
	GetConnectorProjectBinding(ctx context.Context, connector string) (*models.ConnectorProjectBinding, error)
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error)
	ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error)
	GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]storage.ProjectUsageStat, error)
	GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error)
}

// ifaceOpModes is the number of modes each op dispatches on, in ifaceOps order.
var ifaceOpModes = []int{
	4, 5, 5, 8, 7, 6, 6, 8, 6, 5, 10, 4, 4, 6, 5, 5, 6, 8, 5, 6, 1, 3, 3,
}

// ifaceStep encodes one four-byte step of a program.
func ifaceStep(op, mode, a, b int) []byte {
	return []byte{byte(op), byte(mode), byte(a), byte(b)}
}

func ifaceProgram(steps ...[]byte) []byte { return slices.Concat(steps...) }

// ifaceSeeds registers seed programs: one for every (op, mode), so the seed corpus
// reaches every op, and boundary programs for the shapes the families were chosen for.
func ifaceSeeds(f *testing.F) {
	for op, modes := range ifaceOpModes {
		var prog []byte
		for m := range modes {
			// A create first (mode 0 of most families) so later modes find a row at
			// handle 0; a=b=0 selects that row and the same name again.
			prog = append(prog, ifaceStep(op, 0, 0, 0)...)
			prog = append(prog, ifaceStep(op, m, 0, 0)...)
			if len(prog) >= 12*4 {
				f.Add(slices.Clone(prog), "seedAlpha", "seedBeta")
				prog = nil
			}
		}
		if prog != nil {
			f.Add(slices.Clone(prog), "seedAlpha", "seedBeta")
		}
		// The same family with a second name and row selection.
		f.Add(ifaceProgram(ifaceStep(op, 0, 1, 0), ifaceStep(op, 0, 2, 1), ifaceStep(op, 1, 1, 1), ifaceStep(op, 2, 2, 1), ifaceStep(op, 3, 1, 1)), "seedAlpha", "seedBeta")
	}
	// The name pool's normalisation and case twins, in each family's unique or name path.
	for _, op := range []int{opIdxRole, opIdxPerm, opIdxChannel, opIdxTemplate, opIdxPAT, opIdxSysMeta, opIdxRegressionProjectName} {
		f.Add(ifaceProgram(ifaceStep(op, 0, 0, 1), ifaceStep(op, 1, 0, 0), ifaceStep(op, 0, 1, 0)), "café", "café")
		f.Add(ifaceProgram(ifaceStep(op, 0, 0, 1), ifaceStep(op, 1, 0, 0)), "Straße", "STRASSE")
	}
	// Expiry and time-window boundaries, with zoned bounds: a is the zone selector.
	f.Add(ifaceProgram(
		ifaceStep(opIdxUserRole, 1, 0, 2), ifaceStep(opIdxUserRole, 1, 1<<6, 3), ifaceStep(opIdxUserRole, 6, 1<<6, 2), ifaceStep(opIdxUserRole, 7, 2<<6, 3),
		ifaceStep(opIdxPAT, 0, 1<<6, 6), ifaceStep(opIdxPAT, 4, 2<<6, 6),
		ifaceStep(opIdxShare, 0, 2, 9), ifaceStep(opIdxShare, 5, 1<<6, 9), ifaceStep(opIdxShare, 4, 2<<6, 8),
		ifaceStep(opIdxLoginAttempt, 0, 1<<6, 2), ifaceStep(opIdxMFA, 6, 1<<6, 9), ifaceStep(opIdxMFA, 7, 2<<6, 9),
	), "", "")
	// Audit search, keyset and ascending reads.
	f.Add(ifaceProgram(
		ifaceStep(opIdxAudit, 0, 0, 0), ifaceStep(opIdxAudit, 0, 1, 1), ifaceStep(opIdxAudit, 0, 2, 2),
		ifaceStep(opIdxAudit, 1, 0, 2), ifaceStep(opIdxAudit, 2, 0, 0), ifaceStep(opIdxAudit, 2, 0, 1),
		ifaceStep(opIdxAudit, 3, 0, 0), ifaceStep(opIdxAudit, 4, 0, 0), ifaceStep(opIdxAudit, 5, 0, 3),
	), "ÄÖ", "u0")
	f.Add(ifaceProgram(
		ifaceStep(opIdxNotification, 0, 0, 0), ifaceStep(opIdxNotification, 0, 0, 1), ifaceStep(opIdxNotification, 0, 0, 2),
		ifaceStep(opIdxNotification, 1, 0, 0), ifaceStep(opIdxNotification, 1, 0, 3), ifaceStep(opIdxNotification, 1, 1, 4),
		ifaceStep(opIdxNotification, 4, 0, 0), ifaceStep(opIdxNotification, 3, 0, 0), ifaceStep(opIdxNotification, 2, 0, 0),
	), "t", "m")
	f.Add(ifaceProgram(ifaceStep(opIdxRegressionExpiryPagination, 0, 3, 1), ifaceStep(opIdxRegressionProjectName, 1, 1, 2)), "Proj", "proj")
}
