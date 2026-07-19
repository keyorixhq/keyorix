package store

// remote_version_comments_completeness_test.go registers the intentionally-permanent
// remoteUnsupported stubs introduced by the secret-version-comments feature.
//
// The comment write path (CreateSecretVersionComment) and the list/delete paths
// are always invoked through the HTTP handler against LocalStorage on the server
// side. A RemoteStorage client never calls these directly — the CLI uses the HTTP
// API instead (POST/GET/DELETE /api/v1/secrets/{id}/versions/{versionId}/comments).

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateSecretVersionComment": {statusIntentional,
			"version comment writes are server-side only; the CLI uses the HTTP handler via POST /api/v1/secrets/{id}/versions/{versionId}/comments"},
		"ListSecretVersionComments": {statusIntentional,
			"version comment reads are server-side only; the CLI uses the HTTP handler via GET /api/v1/secrets/{id}/versions/{versionId}/comments"},
		"DeleteSecretVersionComment": {statusIntentional,
			"version comment deletes are server-side only; the CLI uses the HTTP handler via DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}"},
	})
}
