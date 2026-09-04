package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateSecretDependency": {statusIntentional,
			"#1587 (docs/adr-090-stale-fork-proxy-deletion.md): CreateSecretDependencyProxy deleted -- no live " +
				"caller. See remoteReachabilityRegistry's entry for the full reasoning (AddSecretDependency already " +
				"calls CreateSecretDependencyExclusive directly, citing #260)."},
	})
}
