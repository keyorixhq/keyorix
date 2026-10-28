// Fixture for TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite: call sites
// that clear a second factor outside the reset flow. Never compiled (testdata).
package bad

import "context"

type factorStore interface {
	DeleteMFAForUser(ctx context.Context, userID uint) error
	DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error
}

// BackdoorStore is a test double that wipes factors on demand.
type BackdoorStore struct{ inner factorStore }

func (b *BackdoorStore) WipeFactors(ctx context.Context, uid uint, credIDs []uint) error {
	if err := b.inner.DeleteMFAForUser(ctx, uid); err != nil {
		return err
	}
	for _, id := range credIDs {
		if err := b.inner.DeleteWebAuthnCredential(ctx, uid, id); err != nil {
			return err
		}
	}
	return nil
}

// quietReset clears TOTP without the reset flow, keeping the password.
func quietReset(ctx context.Context, st factorStore, uid uint) error {
	return st.DeleteMFAForUser(ctx, uid)
}
