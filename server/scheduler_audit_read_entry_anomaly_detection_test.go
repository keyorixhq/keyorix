package main

// anomaly_detection reads secret_access_logs only inside its scan window.
func init() {
	registerSchedulerAuditRead(schedulerAuditRead{
		Job:    "anomaly_detection",
		Tables: []string{"secret_access_logs"},
		Bounds: []auditReadBoundKind{boundTimeWindow},
		Why: "ListSecretIDsAccessedSince, ListSecretAccessLogs (also LIMIT maxSecretAccessLogRows) and " +
			"PrincipalSecretFirstSeen all filter access_time >= since on the access_time index (BRIN on Postgres) / " +
			"_secret_time_action (plans pinned by TestAnomalyQueries_UseTheirIndexes). since is the persisted mark of the " +
			"last successful pass, capped to a 24h catch-up (INV-CORE-42), or the detector's baseline window.",
	})
}
