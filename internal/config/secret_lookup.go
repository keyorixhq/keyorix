package config

// LookupSecretEnv is secretenv.Lookup answered from the *_FILE boot snapshot Load
// took (secretSnapshot): the bytes the permission and duplicate-secret checks
// judged, not a fresh read of whatever the path names now. A name the snapshot
// does not hold, or whose environment changed since Load, is resolved live.
//
// Server code that needs a secret whose variable has a *_FILE form calls this
// instead of secretenv.Lookup (CONFIG-TRUTH-1, #3830);
// TestNoLiveSecretenvLookupOfFileCapableVars in server/ enforces it.
func LookupSecretEnv(name string) (value string, found bool, err error) {
	return secretSnapshot.Lookup(name)
}
