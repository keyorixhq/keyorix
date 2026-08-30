package store

// This file registers remote_rbac.go's intentionally-permanent remoteUnsupported
// stubs into remoteUnsupportedAllowlist (declared in
// remote_unsupported_completeness_test.go). See that file's NEW FEATURE PATTERN
// doc comment — new entries belong in a feature-scoped file like this one, not in
// the shared registry.

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListAllGroupRoleGrants": {statusIntentional,
			"#G25: the group-grant counterpart to ListAllUserRoleGrants (already " +
				"allowlisted above with the same reasoning) — a raw, unscoped grant-table " +
				"dump. Its sole caller, core.GetPermissionBaseline (a hub-side compliance " +
				"export), already calls ListAllUserRoleGrants first and fails closed under " +
				"storage.type: remote before this method is ever reached"},
		"GetProjectByName": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- its only real caller, repo-wide, " +
				"was server/main.go's resolveConnectorOwnership at boot time, which calls " +
				"storage.Storage methods directly against coreService.Storage() (never " +
				"RemoteStorage, since ADR-083's validateRemoteStorageNotServer rejects " +
				"storage.type: remote for any server process). Its only real HTTP caller was " +
				"its own /system proxy handler, GetProjectByNameProxy " +
				"(server/http/handlers/project_catalog_proxy.go), now removed."},
		"ListGlobalAdminAssignmentsForUpdate": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- RemoveUserRole used to call it as " +
				"a separate read before RemoveRole inside a WithTransaction closure, dead since " +
				"#525 replaced that two-call sequence with RemoveGlobalAdminRoleGuarded's single " +
				"atomic conditional write. Its only real caller, repo-wide, was its own /system " +
				"proxy handler, ListGlobalAdminAssignmentsSnapshotProxy " +
				"(server/http/handlers/rbac_role_grants_proxy.go), now removed."},
	})
}
