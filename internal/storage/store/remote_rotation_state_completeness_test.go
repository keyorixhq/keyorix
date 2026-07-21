package store

func init() {
	// Rotation state methods are server-side only: the rotation executor
	// (GetRotationPolicyBySecret / UpdateRotationState) runs exclusively in the
	// server process against LocalStorage. The rotation state is exposed to remote
	// callers via GET /api/v1/secrets/{id}/rotation-state (the HTTP handler), not
	// through the raw storage interface.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetRotationPolicyBySecret": {statusIntentional, "rotation state lookup runs server-side only; remote callers use GET /api/v1/secrets/{id}/rotation-state"},
		"UpdateRotationState":       {statusIntentional, "rotation executor runs server-side only; no REST route exposes raw state mutation to remote callers"},
	})
}
