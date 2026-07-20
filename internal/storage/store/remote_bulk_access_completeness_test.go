package store

// remote_bulk_access_completeness_test.go registers the intentionally-permanent
// remoteUnsupported stubs introduced by the bulk-access-approve feature.
//
// The rejection-reason template CRUD and the multi-ID access-request lookup are
// always invoked through the HTTP handlers against LocalStorage on the server
// side. A RemoteStorage client never calls these directly — the CLI uses the
// HTTP endpoints instead (POST/GET/DELETE /api/v1/rejection-reason-templates,
// POST /api/v1/access-requests/bulk-approve, POST /api/v1/access-requests/bulk-reject).

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateRejectionReasonTemplate": {statusIntentional,
			"rejection-reason template writes are server-side only; the CLI uses the HTTP handler via POST /api/v1/rejection-reason-templates"},
		"ListRejectionReasonTemplates": {statusIntentional,
			"rejection-reason template reads are server-side only; the CLI uses the HTTP handler via GET /api/v1/rejection-reason-templates"},
		"DeleteRejectionReasonTemplate": {statusIntentional,
			"rejection-reason template deletes are server-side only; the CLI uses the HTTP handler via DELETE /api/v1/rejection-reason-templates/{id}"},
		"ListAccessRequestsByIDs": {statusIntentional,
			"multi-ID access-request lookup is a server-side helper for bulk-approve/reject; remote callers use the HTTP bulk-approve/reject endpoints instead"},
	})
}
