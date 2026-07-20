package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListExpiringPATs": {statusIntentional,
			"token-expiry scanning is a server-internal background job running only against LocalStorage; no self-scoped API route exposes raw PAT rows to a remote client"},
		"ListExpiringMachineCredentials": {statusIntentional,
			"token-expiry scanning is a server-internal background job running only against LocalStorage; no self-scoped API route exposes raw machine credential rows to a remote client"},
	})
}
