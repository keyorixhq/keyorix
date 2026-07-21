package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"SetRetentionOverride": {statusIntentional,
			"per-secret retention override is always set server-side via PATCH /api/v1/secrets/{id}/retention; a remote-storage client never calls this method directly"},
	})
}
