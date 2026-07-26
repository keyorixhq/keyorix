package store

const (
	// apiAuditLogsPath is the server's GET /api/v1/audit/logs route (GetAuditLogs).
	apiAuditLogsPath = "/api/v1/audit/logs"
	// apiAuditRBACLogsPath is the server's GET /api/v1/audit/rbac-logs route (GetRBACAuditLogs).
	apiAuditRBACLogsPath = "/api/v1/audit/rbac-logs"
	// apiAuditIngestPath is the system-write proxy route that persists a
	// single AuditEvent from a remote-storage follower (#r122-A).
	apiAuditIngestPath = "/api/v1/system/audit/event"
	apiSecretsPath = "/api/v1/secrets" // #nosec G101 -- API path constant, not a hardcoded credential
	apiUsersPath = "/api/v1/users"
	sqlIncrReadCount = "read_count + 1"
	sqlJoinGroups = "JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL"
	sqlJoinRolePerms = "JOIN role_permissions ON permissions.id = role_permissions.permission_id"
	sqlJoinUserGroups = "JOIN user_groups ON user_groups.group_id = group_roles.group_id"
	sqlOrderCreatedAtDesc = "created_at DESC"
	sqlOrderIDAsc = "id ASC"
	sqlWhereDeletedBefore = "deleted_at IS NOT NULL AND deleted_at < ?"
	sqlWhereExpired = "expires_at IS NOT NULL AND expires_at <= ?"
	sqlWhereGRNotExpired = "group_roles.expires_at IS NULL OR group_roles.expires_at > ?"
	sqlWhereGroupRoleEnv = "group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?"
	sqlWhereID = "id = ?"
	sqlWhereIDsDeletedBefore = "id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?"
	sqlWhereIsSecret = "s.is_secret = ?" // #nosec G101 -- SQL predicate fragment, not a hardcoded credential
	sqlWhereProjectID = "project_id = ?"
	sqlWhereSecretNodeID = "secret_node_id = ?" // #nosec G101 -- SQL predicate fragment, not a hardcoded credential
	sqlWhereShareActive = "secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL"
	sqlWhereUGUserID = "user_groups.user_id = ?"
	sqlWhereURNotExpired = "user_roles.expires_at IS NULL OR user_roles.expires_at > ?"
	sqlWhereURUserID = "user_roles.user_id = ?"
	sqlWhereUserID = "user_id = ?"
	sqlWhereUserIDIn = "user_id IN (?)"
	sqlWhereUserRoleEnv = "user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?"
)
