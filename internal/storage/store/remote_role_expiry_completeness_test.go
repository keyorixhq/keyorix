package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListExpiringUserRoles": {statusIntentional,
			"role-expiry scanning is a server-internal background job running only against LocalStorage; no self-scoped API route exposes raw UserRole rows to a remote client"},
	})
}
