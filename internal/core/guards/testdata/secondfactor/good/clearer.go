// Fixture for TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite: a caller
// that the test's fixture allowlist names, and a function with no call at all.
// Never compiled (testdata).
package good

import "context"

type factorStore interface {
	DeleteMFAForUser(ctx context.Context, userID uint) error
}

func allowedReset(ctx context.Context, st factorStore, uid uint) error {
	return st.DeleteMFAForUser(ctx, uid)
}

func unrelated(ctx context.Context, st factorStore, uid uint) error {
	return nil
}
