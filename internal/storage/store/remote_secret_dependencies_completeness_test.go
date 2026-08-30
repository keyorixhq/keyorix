package store

// This file registers remote_secret_dependencies.go's intentionally-permanent
// remoteUnsupported stubs into remoteUnsupportedAllowlist (declared in
// remote_unsupported_completeness_test.go). See that file's NEW FEATURE
// PATTERN doc comment — new entries belong in a feature-scoped file like this
// one, not in the shared registry. (CreateSecretDependency and
// DeleteSecretDependency are already allowlisted elsewhere -- see
// remote_stale_fork_proxy_deletion_completeness_test.go and
// remote_unsupported_widened_registry_test.go respectively.)

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"ListSecretDependenciesForProjectForUpdate": {statusIntentional,
			"#1480: zero internal/core caller confirmed -- AddSecretDependency used to call it " +
				"as a separate read before CreateSecretDependency inside a WithTransaction " +
				"closure, dead since #260 replaced that two-call sequence with " +
				"CreateSecretDependencyExclusive's single atomic conditional write. Its only " +
				"real caller, repo-wide, was its own /system proxy handler, " +
				"ListSecretDependenciesForProjectSnapshotProxy " +
				"(server/http/handlers/secret_dependencies_proxy.go), now removed."},
	})
}
