package store

func init() {
	// Secret template management — the REST API (/api/v1/secret-templates) is the
	// remote surface. The CLI uses common.RemoteClient directly against those
	// endpoints; the storage layer is only ever reached from the server-side handler
	// which always runs against LocalStorage.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateSecretTemplate":    {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
		"GetSecretTemplate":       {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
		"GetSecretTemplateByName": {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
		"ListSecretTemplates":     {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
		"UpdateSecretTemplate":    {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
		"DeleteSecretTemplate":    {statusIntentional, "secret template CRUD is managed via /api/v1/secret-templates; raw storage call never reached from a remote-storage caller"},
	})
}
