// model_timestamp_hostzone_exceptions_test.go -- the rows TestEveryModelTimestampStampIsUTC accepts
// (HOSTZONE-TIME-NOV-1). Key: "<repo path>:<Func>:<Field>". A row says why the host-zone stamp is
// safe, naming the test that pins it, or that the site is a real defect tracked outside this change.
// A row that matches no hit any more fails the guard: delete it with the fix.

package guards

func init() {
	// Harmless: the stamp stays host-zone in memory, the write normalises it. Each is pinned by
	// TestHostZoneStamps_CoreHarmlessSitesStayUTC (internal/core/hostzone_model_stamps_test.go), which
	// turns red if the normalisation goes away.
	registerModelTimestampException("internal/core/anomaly_config.go:UpdateAnomalyConfig:UpdatedAt",
		"SaveAnomalyConfig is Save(struct): GORM's UPDATE restamps updated_at from NowFunc (UTC) over this value and writes it back into the struct, so the conflict-insert fallback stores UTC too")
	registerModelTimestampException("internal/core/secret_templates.go:UpdateSecretTemplate:UpdatedAt",
		"UpdateSecretTemplateFields stores updated_at.UTC() (local_secret_templates.go)")
	registerModelTimestampException("internal/core/secrets.go:UpdateSecret:UpdatedAt",
		"UpdateSecretFields stores updated_at.UTC() (local_secrets.go); the in-memory stamp is only read back as an instant")
	registerModelTimestampException("internal/core/secrets.go:rotateSecret:UpdatedAt",
		"UpdateSecretFields stores updated_at.UTC() and utcPtr(last_rotated_at) from the same now (local_secrets.go)")

	// Harmless: the value is never written as it stands.
	registerModelTimestampException("internal/storage/models/share_validation.go:ValidateShareUpdate:UpdatedAt",
		"UpdateShareRecord writes updated_at from existing.UpdatedAt = time.Now().UTC() (local_sharing.go), not from this stamp; covered by the UpdateShareRecord writer of TestHookBypassTimeWriters_StoreUTCOnNonUTCHost")
	registerModelTimestampException("internal/storage/store/local_anomaly_config.go:defaultAnomalyConfig:UpdatedAt",
		"the default is returned by GetAnomalyConfig and never saved by the store (TestDefaultAnomalyConfigIsNeverPersisted); a save goes through core UpdateAnomalyConfig, which restamps")
	registerModelTimestampException("server/admin/recovery_key.go:runRotateRecoveryKey:CreatedAt",
		"SetRecoveryKeyRecord stores CreatedAt.UTC() and utcPtr(RotatedAt) (local_recovery_key.go)")

	// Tracked: a real defect of the same class, outside the files HOSTZONE-TIME-NOV-1 may edit, proven
	// on SQLite (secret_versions.created_at stored "... +0900 JST m=+..." after CreateSecret on a
	// TZ=Asia/Tokyo host). Remove the row together with the .UTC() fix.
	registerModelTimestampException("internal/core/secrets_versions.go:storeSecretVersion:CreatedAt",
		"tracked, real: HOSTZONE-TIME-NOV-1 LEFTOVERS (secret_versions.created_at)")
}
