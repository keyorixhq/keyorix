package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetBillingReport": {statusIntentional,
			"billing report queries run server-side; admin callers use GET /api/v1/admin/billing/report"},
	})
}
