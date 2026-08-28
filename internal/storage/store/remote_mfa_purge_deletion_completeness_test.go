package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ActivateMFASecret": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): ActivateMFASecretProxy deleted -- " +
				"no live caller. See remoteReachabilityRegistry's entry for the full two-ground reasoning " +
				"(server-only vs. no-CLI-command-yet) and what reviving this would require."},
		"SetUserMFAEnabled": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): SetUserMFAEnabledProxy deleted -- " +
				"no live caller. See remoteReachabilityRegistry's entry for the full two-ground reasoning."},
		"CreateMFARecoveryCodes": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): CreateMFARecoveryCodesProxy deleted " +
				"-- no live caller. See remoteReachabilityRegistry's entry for the full two-ground reasoning."},
		"DeleteMFAForUser": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): DeleteMFAForUserProxy deleted -- " +
				"no live caller. See remoteReachabilityRegistry's entry for the full two-ground reasoning."},
		"DeleteMFARecoveryCodes": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): DeleteMFARecoveryCodesProxy deleted " +
				"-- no live caller. See remoteReachabilityRegistry's entry for the full two-ground reasoning."},
		"PurgeDeletedUsersBefore": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): PurgeDeletedUsersBeforeProxy " +
				"deleted -- no live caller. See remoteReachabilityRegistry's entry for the full two-ground " +
				"reasoning (server-only vs. no-CLI-command-yet) and what reviving this would require."},
		"PurgeDeletedProjectsBefore": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): PurgeDeletedProjectsBeforeProxy " +
				"deleted -- no live caller. See remoteReachabilityRegistry's entry for the full two-ground " +
				"reasoning."},
		"PurgeDeletedEnvironmentsBefore": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): PurgeDeletedEnvironmentsBeforeProxy " +
				"deleted -- no live caller. See remoteReachabilityRegistry's entry for the full two-ground " +
				"reasoning."},
		"PurgeDeletedSecretsBefore": {statusIntentional,
			"#1593/G80 Wave 2 (docs/adr-089-mfa-purge-relay-deletion.md): PurgeDeletedSecretsBeforeProxy " +
				"deleted -- no live caller. See remoteReachabilityRegistry's entry for the full two-ground " +
				"reasoning."},
	})
}
