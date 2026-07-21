package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListInactiveUsers": {statusIntentional,
			"the inactivity auto-suspension job runs server-side; the CLI trigger POSTs to POST /api/v1/admin/jobs/suspend-inactive-users rather than this raw storage method"},
	})
}
