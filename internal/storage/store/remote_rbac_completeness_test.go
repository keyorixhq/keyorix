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
	})
}
