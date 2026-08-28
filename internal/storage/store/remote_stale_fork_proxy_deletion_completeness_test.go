package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"UpdateMachineIdentity": {statusIntentional,
			"#1585 (docs/adr-090-stale-fork-proxy-deletion.md): UpdateMachineIdentityProxy deleted -- no live " +
				"caller. See remoteReachabilityRegistry's entry for the full reasoning (core.ClassifyMachineIdentity " +
				"was fixed under G42 to call TransitionMachineIdentityState instead)."},
		"UpdateProjectMembership": {statusIntentional,
			"#1586 (docs/adr-090-stale-fork-proxy-deletion.md): UpdateMembershipProxy deleted -- no live caller. " +
				"See remoteReachabilityRegistry's entry for the full reasoning (membership_lifecycle.go's " +
				"TransitionMembership was fixed under G42 to call TransitionProjectMembershipState instead)."},
		"CreateSecretDependency": {statusIntentional,
			"#1587 (docs/adr-090-stale-fork-proxy-deletion.md): CreateSecretDependencyProxy deleted -- no live " +
				"caller. See remoteReachabilityRegistry's entry for the full reasoning (AddSecretDependency already " +
				"calls CreateSecretDependencyExclusive directly, citing #260)."},
	})
}
