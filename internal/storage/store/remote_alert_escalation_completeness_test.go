package store

func init() {
	// Alert escalation policy management — the REST API (/api/v1/alert-escalation-policies)
	// is the remote surface. The CLI uses common.RemoteClient directly against those
	// endpoints; the storage layer is only ever reached from the server-side handler
	// which always runs against LocalStorage.
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateAlertEscalationPolicy":           {statusIntentional, "alert escalation policy CRUD is managed via /api/v1/alert-escalation-policies; raw storage call never reached from a remote-storage caller"},
		"GetAlertEscalationPolicy":              {statusIntentional, "alert escalation policy CRUD is managed via /api/v1/alert-escalation-policies; raw storage call never reached from a remote-storage caller"},
		"ListAlertEscalationPolicies":           {statusIntentional, "alert escalation policy CRUD is managed via /api/v1/alert-escalation-policies; raw storage call never reached from a remote-storage caller"},
		"UpdateAlertEscalationPolicy":           {statusIntentional, "alert escalation policy CRUD is managed via /api/v1/alert-escalation-policies; raw storage call never reached from a remote-storage caller"},
		"DeleteAlertEscalationPolicy":           {statusIntentional, "alert escalation policy CRUD is managed via /api/v1/alert-escalation-policies; raw storage call never reached from a remote-storage caller"},
		"ListUnacknowledgedAnomalyAlertsBefore": {statusIntentional, "escalation runner executes server-side only; raw storage call never reached from a remote-storage caller"},
	})
}
