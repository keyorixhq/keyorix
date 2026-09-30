package storage

import "fmt"

// EnvironmentSecretGuardLockKey is the WithNamedLock key serializing every
// operation that creates or re-activates a secret_nodes row against
// DeleteEnvironment's active-secret guard, per environment (SESSION-AT
// AT1/AT3). Exported from this shared interface package (not duplicated in
// internal/core and internal/storage/store, which both already import it)
// so the two sides can never drift apart -- a coordinator review on PR
// #2353 caught exactly that risk in an earlier version of this fix, where
// the key was computed by an identical but independently-maintained
// function in each package.
//
// Every write that can leave a secret_nodes row pointing at a deleted
// environment must acquire this lock AND re-verify the environment still
// exists INSIDE the locked section, not just take the lock -- see
// DeleteEnvironment's own doc comment (internal/storage/store/local_secrets.go)
// for why both are required (the lock alone still allows the legitimate
// ordering "delete wins first, commits; create then acquires the lock and
// blindly inserts anyway").
func EnvironmentSecretGuardLockKey(environmentID uint) string {
	return fmt.Sprintf("environment-secret-guard:%d", environmentID)
}
