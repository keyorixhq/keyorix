package store

func init() {
	// GetUserGroupsAt/ListGroupMembersAt (#G01) back scope-aware group-membership
	// checks (CheckGroupPermissions' group-share resolution, resolveGroupAdminMembers'
	// last-global-admin guards) that only ever run against the server's own
	// KeyorixCore over a LocalStorage backend — a downstream server in
	// storage.type: remote mode never reaches these checks itself (it proxies the
	// underlying CRUD calls its own upstream authorizes), so there is no remote
	// wire route to implement yet.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetUserGroupsAt":   {statusIntentional, "scope-aware group-membership check backing CheckGroupPermissions; only reached from local-backend authorization, no remote-storage caller today"},
		"ListGroupMembersAt": {statusIntentional, "scope-aware group-membership check backing the last-global-admin guards; only reached from local-backend authorization, no remote-storage caller today"},
	})
}
