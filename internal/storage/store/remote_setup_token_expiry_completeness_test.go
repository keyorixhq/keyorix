package store

// Registers GetSetupTokenByID (#1622) into remoteUnsupportedAllowlist,
// per remote_unsupported_registry_test.go's own "NEW FEATURE PATTERN" note:
// a new file per feature, not an edit to the shared registry, so parallel
// feature branches don't conflict on it.

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"GetSetupTokenByID": {statusIntentional,
			"#1622: added so KeyorixCore.ExpireSetupTokenByID (the fix for " +
				"ExpireSetupTokenProxy's raw-storage audit-trail bypass) can resolve " +
				"purpose/subject detail for its audit write. Only ever called hub-side " +
				"-- server/http/handlers is always LocalStorage-backed " +
				"(validateRemoteStorageNotServer forbids the reverse), so no " +
				"RemoteStorage caller can ever reach this method."},
	})
}
