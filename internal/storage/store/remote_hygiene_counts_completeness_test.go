package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		// Credential hygiene trend snapshots — all server-side only.
		"SaveHygieneTrendSnapshot": {statusIntentional,
			"hygiene trend snapshots are written server-side by RecordHygieneTrendPoint; no remote caller ever invokes this directly"},
		"ListHygieneTrendSnapshots": {statusIntentional,
			"hygiene trend snapshot reads are server-side only; GetHygieneTrends is a server-only handler"},
		"CountStalePATs": {statusIntentional,
			"stale-PAT count is computed server-side as part of RecordHygieneTrendPoint; no remote caller ever invokes this directly"},
		"CountExpiredPATs": {statusIntentional,
			"expired-PAT count is computed server-side as part of RecordHygieneTrendPoint; no remote caller ever invokes this directly"},
		"CountStaleMachineCredentials": {statusIntentional,
			"stale-machine-credential count is computed server-side as part of RecordHygieneTrendPoint; no remote caller ever invokes this directly"},
	})
}
