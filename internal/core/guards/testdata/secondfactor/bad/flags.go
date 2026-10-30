// Fixture for TestSecondFactorClearerGuard_RejectsAnUnlistedCallSite: a second
// factor switched off by its flag (the factor rows survive, the login stops
// asking for them) outside the reset flow. Never compiled (testdata).
package bad

import "context"

type flagStore interface {
	SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error
	SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error
	PutUserRow(ctx context.Context, u *user) error
}

type user struct{ MFAEnabled, WebAuthnEnabled bool }

// flagsOff turns both flags off through their setters.
func flagsOff(ctx context.Context, st flagStore, uid uint) error {
	if err := st.SetUserMFAEnabled(ctx, uid, false); err != nil {
		return err
	}
	return st.SetUserWebAuthnEnabled(ctx, uid, false)
}

// flagFromInput passes a value the scan cannot prove is true.
func flagFromInput(ctx context.Context, st flagStore, uid uint, on bool) error {
	return st.SetUserMFAEnabled(ctx, uid, on)
}

// fullRowClear clears the flag on the row and writes the whole row back (the
// UpdateUser shape; named otherwise so the full-row-write guard, which scans
// testdata by method name, does not count this fixture).
func fullRowClear(ctx context.Context, st flagStore, u *user) error {
	u.MFAEnabled = false
	return st.PutUserRow(ctx, u)
}

// enable only ever turns a factor on: not reported.
func enable(ctx context.Context, st flagStore, u *user) error {
	u.WebAuthnEnabled = true
	return st.SetUserMFAEnabled(ctx, 1, true)
}
