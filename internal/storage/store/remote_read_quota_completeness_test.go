package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListSecretsWithQuota": {statusIntentional,
			"read-quota scanning is a server-internal background job running only against LocalStorage; no self-scoped API route exposes raw SecretNode quota fields to a remote client"},
	})
}
