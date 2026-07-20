package models

// AllTestModels returns every GORM model that SQLite-backed integration and
// handler tests must AutoMigrate.
//
// This is the single source of truth for the test schema: server/http/integration_test.go
// and any other SQLite-backed test fixture calls models.AllTestModels() instead of
// maintaining its own copy of the list, so adding a new model only requires touching
// this file — not every test helper that creates an in-memory DB.
//
// When adding a new model: append it here and nowhere else (as far as integration-test
// schema setup is concerned). The compiler will catch missing struct names.
func AllTestModels() []any {
	return []any{
		&SecretNode{},
		&SecretVersion{},
		&User{},
		&Role{},
		&UserRole{},
		&Group{},
		&UserGroup{},
		&GroupRole{},
		&ShareRecord{},
		&AuditEvent{},
		&Session{},
		&Project{},
		&Environment{},
		&Permission{},
		&RolePermission{},
		&SystemMetadata{},
		&LoginAttempt{},
		&PasswordHistory{},
		&PersonalAccessToken{},
		&Tag{},
		&SecretTag{},
		&ProjectInvitation{},
		&DynamicSecretConfig{},
		&DynamicSecretLease{},
		&Notification{},
		&SetupToken{},
		&ProjectMembership{},
		&MFASecret{},
		&MFARecoveryCode{},
		&MFAChallenge{},
		&SecretDependency{},
		&MachineIdentity{},
		&MachineIdentityCredential{},
		&MachineIdentityRole{},
		&MachineIdentityOIDCBinding{},
		&WebAuthnCredential{},
		&WebAuthnSession{},
		&LegalHold{},
		&AccessReviewCampaign{},
		&AccessReviewItem{},
		&BreakGlassActivation{},
		&RiskException{},
		&SoDPolicy{},
		&ConnectRefGrant{},
		&AnomalyAlert{},
		&AccessRequest{},
		&AccessRequestApproval{},
		&SSOLoginState{},
		&SchedulerLockLease{},
		&SecretACL{},
		&RotationPolicy{},
		&NotificationChannel{},
		&AlertEscalationPolicy{},
		&AnomalyConfigRecord{},
		&StatsSnapshot{},
		&DeploymentStatsSnapshot{},
		&CompliancePostureSnapshot{},
		&SecretAccessSchedule{},
		&HygieneTrendSnapshot{},
		&SecretVersionComment{},
	}
}
