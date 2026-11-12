// cta_review_user_row_narrow_cases_test.go — FIX-USER-ROW-NARROW-1 (#2653, #2654).
//
// The interleavings of #2653/#2654 and their residue, as cases run on both
// backends by cta_review_user_row_narrow_postgres_test.go and
// cta_review_user_row_narrow_sqlite_test.go (two-replica ctaReview fixture).
//
// Every case forces the same order: replica A reads the target user with no
// lock (UpdateUser's GetUser, or UpdateOwnProfile's re-auth read), replica B's
// complete competing operation commits on its own connection, then A writes.
// The competing write must survive A's write.
//
// The hook point is after A's unlocked read, not before A's UPDATE (where
// beforeA hooks): UpdateUser now re-reads the row under LockUserForUpdate
// inside its write transaction, so at the UPDATE A holds the row lock (and on
// SQLite the database write lock), and B, run synchronously from there, would
// deadlock against A. The window that remains is the one between the unlocked
// read and the transaction, and that is where the bug lived.
package core

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// afterAUnlockedUserRead registers a one-shot hook on replica A's own *gorm.DB:
// right after A's nth query that loaded user userID outside a transaction,
// run concurrent (replica B's operation) to completion. Returns how many such
// reads A made in total, so a case can check it hooked the read it meant to.
func (f *ctaReview) afterAUnlockedUserRead(userID uint, nth int, concurrent func()) (reads func() int) {
	f.t.Helper()
	n := 0
	fn := func(tx *gorm.DB) {
		if tx.Error != nil {
			return
		}
		if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); inTx {
			return
		}
		u, ok := tx.Statement.Dest.(*models.User)
		if !ok || u.ID != userID {
			return
		}
		n++
		if n == nth {
			concurrent()
		}
	}
	require.NoError(f.t, f.dbA.Callback().Query().After("gorm:query").Register("user-row-narrow:after-read", fn))
	return func() int { return n }
}

// userRowNarrowWriter is replica A's operation: a profile edit.
type userRowNarrowWriter struct {
	name string
	// unlockedReads is how many times the operation reads the target outside a
	// transaction; the competing write is forced after the last one (the
	// window right before A's write) unless a case says otherwise.
	unlockedReads int
	run           func(f *ctaReview, target *models.User) error
}

// userRowNarrowCompetitor is replica B's operation and what must survive it.
type userRowNarrowCompetitor struct {
	name    string
	prepare func(f *ctaReview, target *models.User) func() error
	survive func(t *testing.T, before, after *models.User)
}

func userRowNarrowWriters() []userRowNarrowWriter {
	return []userRowNarrowWriter{
		{name: "AdminUpdateUserDisplayName", unlockedReads: 1, run: func(f *ctaReview, u *models.User) error {
			_, err := f.coreA.UpdateUser(f.ctx, &UpdateUserRequest{ID: u.ID, ActorID: f.adminID, DisplayName: "renamed"})
			return err
		}},
		// What the gRPC/CLI/HTTP clients that resend every field do.
		{name: "AdminUpdateUserEchoAllFields", unlockedReads: 1, run: func(f *ctaReview, u *models.User) error {
			_, err := f.coreA.UpdateUser(f.ctx, &UpdateUserRequest{
				ID: u.ID, ActorID: f.adminID, Username: u.Username, Email: u.Email, DisplayName: "renamed",
			})
			return err
		}},
		// Session only, no re-auth (#2654).
		{name: "OwnProfileDisplayName", unlockedReads: 1, run: func(f *ctaReview, u *models.User) error {
			_, err := f.coreA.UpdateOwnProfile(f.ctx, u.ID, "renamed", "", "")
			return err
		}},
		// What the web My Account page sends: the display name plus the
		// unchanged email (web/src/services/account.ts). Still session only.
		{name: "OwnProfileWebShape", unlockedReads: 2, run: func(f *ctaReview, u *models.User) error {
			_, err := f.coreA.UpdateOwnProfile(f.ctx, u.ID, "renamed", u.Email, "")
			return err
		}},
	}
}

func userRowNarrowCompetitors() []userRowNarrowCompetitor {
	return []userRowNarrowCompetitor{
		{name: "ChangePassword", prepare: func(f *ctaReview, u *models.User) func() error {
			return func() error {
				return f.coreB.ChangePassword(f.ctx, u.ID, "UserPass123!xyz-long-enough", "NewUserPass456!abc-long-enough", "")
			}
		}, survive: func(t *testing.T, before, after *models.User) {
			assert.NotEqual(t, before.PasswordHash, after.PasswordHash, "the OLD password hash is live again after a successful password change")
		}},
		{name: "SuspendUser", prepare: func(f *ctaReview, u *models.User) func() error {
			return func() error { return f.coreB.SuspendUser(f.ctx, f.adminID, u.ID) }
		}, survive: func(t *testing.T, _, after *models.User) {
			assert.Equal(t, AccountSuspended, after.AccountState, "a suspension that reported success was silently reverted")
		}},
		{name: "ActivateMFA", prepare: func(f *ctaReview, u *models.User) func() error {
			_, secret, err := f.setup.BeginMFAEnrollment(f.ctx, u.ID)
			require.NoError(f.t, err)
			return func() error {
				code, err := totp.GenerateCode(secret, time.Now())
				if err != nil {
					return err
				}
				_, err = f.coreB.ActivateMFA(f.ctx, u.ID, code, "UserPass123!xyz-long-enough", "")
				return err
			}
		}, survive: func(t *testing.T, _, after *models.User) {
			assert.True(t, after.MFAEnabled, "an MFA enable that reported success was silently reverted")
		}},
		// The residue #2785 left open: the profile columns themselves. The email
		// is the password-reset and SSO-linking anchor.
		{name: "AdminChangesEmail", prepare: func(f *ctaReview, u *models.User) func() error {
			return func() error {
				_, err := f.coreB.UpdateUser(f.ctx, &UpdateUserRequest{ID: u.ID, ActorID: f.adminID, Email: "fixed-" + u.Email})
				return err
			}
		}, survive: func(t *testing.T, before, after *models.User) {
			assert.Equal(t, "fixed-"+before.Email, after.Email, "an email change that reported success was silently reverted")
		}},
		{name: "AdminChangesUsername", prepare: func(f *ctaReview, u *models.User) func() error {
			return func() error {
				_, err := f.coreB.UpdateUser(f.ctx, &UpdateUserRequest{ID: u.ID, ActorID: f.adminID, Username: u.Username + "-renamed"})
				return err
			}
		}, survive: func(t *testing.T, before, after *models.User) {
			assert.Equal(t, before.Username+"-renamed", after.Username, "a username change that reported success was silently reverted")
		}},
	}
}

// runUserRowNarrowMatrix runs every writer against every competitor, each on a
// fresh fixture from newFixture.
func runUserRowNarrowMatrix(t *testing.T, newFixture func(t *testing.T) *ctaReview) {
	for _, w := range userRowNarrowWriters() {
		for _, c := range userRowNarrowCompetitors() {
			if w.name == "AdminUpdateUserEchoAllFields" && (c.name == "AdminChangesEmail" || c.name == "AdminChangesUsername") {
				// The request sets that field itself: last writer wins, and that is
				// the request's explicit value, not a stale one.
				continue
			}
			t.Run(w.name+"_vs_"+c.name, func(t *testing.T) {
				f := newFixture(t)
				runUserRowNarrowCase(t, f, w, c, w.unlockedReads)
			})
		}
	}
}

func runUserRowNarrowCase(t *testing.T, f *ctaReview, w userRowNarrowWriter, c userRowNarrowCompetitor, nth int) {
	t.Helper()
	target := f.user("rownarrow", "project_viewer")
	var before models.User
	require.NoError(t, f.setupDB.First(&before, target.ID).Error)

	competitor := c.prepare(f, &before)
	var errB error
	fired := false
	reads := f.afterAUnlockedUserRead(target.ID, nth, func() { fired = true; errB = competitor() })
	errA := w.run(f, &before)
	t.Logf("%s (A) err=%v, %s (B) err=%v, A's unlocked reads of the target=%d", w.name, errA, c.name, errB, reads())
	require.True(t, fired, "the hook must have run B after A's unlocked read %d", nth)
	require.Equal(t, w.unlockedReads, reads(), "A's unlocked reads changed: the case no longer hooks the read right before A's write")
	require.NoError(t, errB, "the competing write itself reported success")
	require.NoError(t, errA, "A's profile edit does not conflict with B's write and must succeed")

	var after models.User
	require.NoError(t, f.setupDB.First(&after, target.ID).Error)
	assert.Equal(t, "renamed", after.DisplayName, "A's own change must be persisted")
	c.survive(t, &before, &after)
}

// runUserRowNarrowEmailBetweenReads is #2654's re-auth half: the web-shaped
// own-profile edit (display name + unchanged email) decides "the email is not
// changing, no re-auth" on its first read; an email change commits; UpdateUser's
// second read then sees a different email and must not write the request's
// (old) one back, which would be an email change that skipped re-auth.
func runUserRowNarrowEmailBetweenReads(t *testing.T, f *ctaReview) {
	t.Helper()
	var webShape, emailChange = userRowNarrowWriters()[3], userRowNarrowCompetitors()[3]
	require.Equal(t, "OwnProfileWebShape", webShape.name)
	require.Equal(t, "AdminChangesEmail", emailChange.name)
	runUserRowNarrowCase(t, f, webShape, emailChange, 1)
}

// runUserRowNarrowActiveConflict pins what must NOT change: a concurrent
// deactivation between A's read and A's write is still detected
// (ErrUserActiveStateConflict) and is not reverted.
func runUserRowNarrowActiveConflict(t *testing.T, f *ctaReview) {
	t.Helper()
	target := f.user("rownarrow-active", "project_viewer")
	inactive := false
	var errB error
	fired := false
	f.afterAUnlockedUserRead(target.ID, 1, func() {
		fired = true
		_, errB = f.coreB.UpdateUser(f.ctx, &UpdateUserRequest{ID: target.ID, ActorID: f.adminID, IsActive: &inactive})
	})
	_, errA := f.coreA.UpdateUser(f.ctx, &UpdateUserRequest{ID: target.ID, ActorID: f.adminID, DisplayName: "renamed"})
	require.True(t, fired)
	require.NoError(t, errB)
	require.ErrorIs(t, errA, ErrUserActiveStateConflict, "a concurrent deactivation must still be detected")

	var after models.User
	require.NoError(t, f.setupDB.First(&after, target.ID).Error)
	assert.False(t, after.IsActive, "the concurrent deactivation was reverted")
	assert.Equal(t, target.DisplayName, after.DisplayName, "the refused edit must not have been written")
}
