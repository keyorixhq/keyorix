package store

func init() {
	// Secret read aggregation — the GET /api/v1/secrets/{id}/read-summary endpoint
	// is served by a handler running against LocalStorage on the server side.
	// A remote (CLI) caller hits the HTTP endpoint directly, not the raw storage
	// method, so GetSecretReadCounts is never reached from a RemoteStorage caller.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetSecretReadCounts": {statusIntentional, "secret read aggregation runs server-side via GET /api/v1/secrets/{id}/read-summary; raw storage call never reached from a remote-storage caller"},
	})
}
