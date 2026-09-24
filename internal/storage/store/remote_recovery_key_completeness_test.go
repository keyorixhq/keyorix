// remote_recovery_key_completeness_test.go — registry entries for the two
// RemoteStorage recovery-key stubs (remote_audit.go), per
// remote_unsupported_completeness_test.go's own convention: "New features:
// create remote_<feature>_completeness_test.go and call addRemoteUnsupported
// in an init() there — do NOT edit either registry file."
package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetRecoveryKeyRecord": {statusIntentional, "docs/design-b2-recover-admin.md §3: `keyorix-server admin recover-admin`/`recovery-key rotate` are local, host-side admin CLI subcommands (ADR-108 §B) with no HTTP/gRPC route — they never dispatch through the network API, and only ever run against a directly-reachable local/postgres backend, by design. No caller reaches this stub under storage.type: remote because no caller reaches this stub AT ALL under that topology: the admin command tree itself only opens local/postgres storage directly (server/admin's loadConfig+storage.NewStorageFactory), never a RemoteStorage-backed core."},
		"SetRecoveryKeyRecord": {statusIntentional, "Same grounds as GetRecoveryKeyRecord above — the two are always called together from the same admin CLI code path."},
	})

	// remoteReachabilityRegistry (remote_reachability_registry_test.go) is a
	// package-level map declared as a literal in that file; populating it
	// from this file's own init() is ordinary Go (multiple init()s in one
	// package all run before tests), and keeps this feature's two entries
	// out of that giant hand-maintained literal, matching the
	// addRemoteUnsupported per-feature-file convention above.
	reason := "Same reachability grounds as this file's addRemoteUnsupported entries above: " +
		"the admin CLI command tree that calls this method has no HTTP/gRPC route and never " +
		"constructs a RemoteStorage-backed core, so no path under storage.type: remote reaches " +
		"it at all — dead by construction, not by tracing a guarded caller."
	remoteReachabilityRegistry["GetRecoveryKeyRecord"] = reachabilityEntry{reachabilityDead, reason}
	remoteReachabilityRegistry["SetRecoveryKeyRecord"] = reachabilityEntry{reachabilityDead, reason}
}
