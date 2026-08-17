package store

// This file registers remote_users.go's ListAllUserGroupMemberships
// remoteUnsupported stub into remoteUnsupportedAllowlist (declared in
// remote_unsupported_completeness_test.go). See that file's NEW FEATURE
// PATTERN doc comment — new entries belong in a feature-scoped file like this
// one, not in the shared registry.

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListAllUserGroupMemberships": {statusIntentional,
			"#G44: the batch-load counterpart to GetUserGroups (which IS remote-" +
				"implemented), used only by core.GetPermissionBaseline — a raw, " +
				"unscoped membership-table dump. That caller already calls " +
				"ListAllUserRoleGrants/ListAllGroupRoleGrants first (both already " +
				"allowlisted above with the same reasoning) and fails closed under " +
				"storage.type: remote before this method is ever reached"},
	})
}
