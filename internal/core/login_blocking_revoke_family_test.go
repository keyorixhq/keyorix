package core

// login_blocking_revoke_family_test.go — REVOKE-GUARDS-NOV-1 item 1.
//
// The family guard for "a transition that blocks login revokes every credential
// the user holds". #2855 (DeprovisionSCIMUser revoked sessions but not PATs) and
// #3419 (UpdateSCIMUser's deactivation, same gap) were each found one transition
// at a time; every login-blocking transition now runs through the one table
// below, against the same seeded credential set and the same assertions:
//
//   - every session the user owns, and every impersonation session the user
//     STARTED (impersonated_by = user, keyed to the target's user_id), is deleted;
//   - every personal access token of the user is revoked (revoked = true, not
//     merely inert while the account is blocked: ReactivateUser and RestoreUser
//     revoke nothing, so an unrevoked row comes back to life on a restore);
//   - every MFA step-up grant of the user is gone;
//   - every one of those session and PAT hashes was TOMBSTONED in the auth cache
//     (SetTokenCacheInvalidator), not merely cleared;
//   - exactly one audit row of the transition's own event type was written.
//
// Completeness of the table is not left to this file: guards/login_blocking_
// transition_registry_guard_test.go finds every function in internal/core that
// writes account_state or is_active and fails until it is either a row here or
// classified as a transition that never blocks login.
//
// The setAccountState rows are derived from validAccountStates filtered by
// AccountLoginBlocked, so a new blocked state gets its own row without an edit
// here.
//
// What this does not check: the post-commit failure paths (a failed listing or
// revoke, the ERRLOSS-REVOKE-1 fallbacks) — those have their own fault tests
// (update_user_deactivation_cleanup_tx_test.go, session_eviction tests).

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// loginBlockingTransition is one row of the family table. run drives the
// transition as actorID against userID (a SCIM-managed, active user with no
// roles); event is the audit event type it must write exactly once.
type loginBlockingTransition struct {
	name  string
	event string
	run   func(ctx context.Context, t *testing.T, w *txClosureWorld, actorID, userID uint, username string) error
}

// loginBlockingTransitions is the table. Row names are referenced by
// guards/login_blocking_transition_registry_guard_test.go: renaming one means
// renaming it there too.
func loginBlockingTransitions() []loginBlockingTransition {
	rows := []loginBlockingTransition{
		{name: "SuspendUser", event: "account.suspended", run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
			return w.c.SuspendUser(ctx, actorID, userID)
		}},
		{name: "DeleteUser", event: EventUserDeleted, run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
			return w.c.DeleteUser(ctx, actorID, userID)
		}},
		{name: "DeprovisionSCIMUser", event: EventSCIMUserDeprovisioned, run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
			return w.c.DeprovisionSCIMUser(ctx, actorID, userID)
		}},
		{name: "UpdateSCIMUser/deactivate", event: EventSCIMUserUpdated, run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
			inactive := false
			_, err := w.c.UpdateSCIMUser(ctx, actorID, userID, nil, nil, &inactive)
			return err
		}},
		{name: "UpdateUser/deactivate", event: EventUserUpdated, run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
			inactive := false
			_, err := w.c.UpdateUser(ctx, &UpdateUserRequest{ID: userID, ActorID: actorID, IsActive: &inactive})
			return err
		}},
		{name: "MigrateUserToMachine/suspendSource", event: "account.suspended", run: func(ctx context.Context, t *testing.T, w *txClosureWorld, actorID, _ uint, username string) error {
			p, err := w.c.CreateProject(ctx, "migrate-"+username, "")
			require.NoError(t, err)
			_, err = w.c.MigrateUserToMachine(ctx, username, p.ID, "", "", actorID, 0, true)
			return err
		}},
	}
	// setAccountState with every state that blocks login, derived from the
	// canonical set so a new blocked state is covered without an edit here.
	var blocked []string
	for s := range validAccountStates {
		if AccountLoginBlocked(0, s) {
			blocked = append(blocked, s)
		}
	}
	slices.Sort(blocked)
	for _, s := range blocked {
		event := "account.state_" + s
		rows = append(rows, loginBlockingTransition{name: "setAccountState/" + s, event: event,
			run: func(ctx context.Context, _ *testing.T, w *txClosureWorld, actorID, userID uint, _ string) error {
				return w.c.setAccountState(ctx, actorID, userID, s, event)
			}})
	}
	return rows
}

// TestLoginBlockingTransitions_SetAccountStateRowsCoverEveryBlockedState is the
// vacuity check for the derived rows: the canonical set has at least the two
// blocked states ADR-025 names, so an empty derivation cannot pass silently.
func TestLoginBlockingTransitions_SetAccountStateRowsCoverEveryBlockedState(t *testing.T) {
	var got []string
	for _, r := range loginBlockingTransitions() {
		if s, ok := strings.CutPrefix(r.name, "setAccountState/"); ok {
			got = append(got, s)
		}
	}
	require.Subset(t, got, []string{AccountSuspended, AccountDeprovisioned})
}

// blockedUserCredentials is what seedLoginBlockedTarget planted for one user.
type blockedUserCredentials struct {
	userID, otherID uint
	username        string
	sessionHashes   []string // stored session_token values (= auth-cache keys)
	patHashes       []string
}

// seedLoginBlockedTarget creates an active, SCIM-managed user with no roles and
// gives it every credential kind a login-blocking transition must remove: two
// own sessions, a session in which an admin impersonates the user, a session in
// which the user impersonates someone else, two PATs and two step-up grants.
func seedLoginBlockedTarget(t *testing.T, w *txClosureWorld, actorID uint, name string) blockedUserCredentials {
	t.Helper()
	u := &models.User{Username: name, UsernameFolded: name, Email: name + "@example.com",
		EmailFolded: name + "@example.com", IsActive: true, AccountState: AccountActive, ExternalID: "idp|" + name}
	require.NoError(t, w.db.Create(u).Error)
	other := &models.User{Username: name + "-other", UsernameFolded: name + "-other", Email: name + "-other@example.com",
		EmailFolded: name + "-other@example.com", IsActive: true, AccountState: AccountActive}
	require.NoError(t, w.db.Create(other).Error)

	exp := time.Now().Add(time.Hour)
	now := time.Now()
	uid, aid := u.ID, actorID
	sessions := []models.Session{
		{UserID: uid, SessionToken: name + "-sess-1", ExpiresAt: &exp},
		{UserID: uid, SessionToken: name + "-sess-2", ExpiresAt: &exp},
		// An admin impersonating the user: keyed to the user's user_id.
		{UserID: uid, SessionToken: name + "-sess-impersonated", ExpiresAt: &exp, ImpersonatedBy: &aid, ImpersonationStartedAt: &now},
		// The user impersonating someone else: keyed to the OTHER user's user_id.
		{UserID: other.ID, SessionToken: name + "-sess-impersonating", ExpiresAt: &exp, ImpersonatedBy: &uid, ImpersonationStartedAt: &now},
	}
	creds := blockedUserCredentials{userID: uid, otherID: other.ID, username: name}
	for i := range sessions {
		require.NoError(t, w.db.Create(&sessions[i]).Error)
		creds.sessionHashes = append(creds.sessionHashes, sessions[i].SessionToken)
	}
	for i := range 2 {
		h := fmt.Sprintf("%s-pat-%d", name, i)
		require.NoError(t, w.db.Create(&models.PersonalAccessToken{UserID: uid, Name: h, TokenHash: h}).Error)
		creds.patHashes = append(creds.patHashes, h)
	}
	for _, p := range []models.MFAStepUpPurpose{models.MFAStepUpPurposeReauth, models.MFAStepUpPurposeRestrictedSecretRead} {
		require.NoError(t, w.db.Create(&models.MFAStepUpGrant{UserID: uid, Purpose: p, ExpiresAt: exp}).Error)
	}
	return creds
}

// tombstoneRecorder stands in for the HTTP auth cache's invalidator.
type tombstoneRecorder struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (r *tombstoneRecorder) invalidate(h string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[h] = true
}

func (r *tombstoneRecorder) has(h string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[h]
}

// loginBlockedViolations returns every property of the family a transition
// broke for creds, as one line each (empty: the transition is correct). It is
// a function, not inline require calls, so the calibration test below can run
// it against planted broken transitions and see it fire.
func loginBlockedViolations(t *testing.T, w *txClosureWorld, rec *tombstoneRecorder, creds blockedUserCredentials, event string, auditBefore int64) []string {
	t.Helper()
	uid := creds.userID
	var out []string

	// Precondition of every check below: the account is now login-blocked.
	var after models.User
	require.NoError(t, w.db.Unscoped().First(&after, uid).Error)
	if after.IsActive && !AccountLoginBlocked(uid, after.AccountState) {
		out = append(out, fmt.Sprintf("login not blocked (is_active=%v, account_state=%q)", after.IsActive, after.AccountState))
	}

	var sessions int64
	require.NoError(t, w.db.Model(&models.Session{}).
		Where("user_id = ? OR impersonated_by = ?", uid, uid).Count(&sessions).Error)
	if sessions != 0 {
		out = append(out, fmt.Sprintf("%d session(s) of the user (own or impersonating) left in storage", sessions))
	}

	var livePATs int64
	require.NoError(t, w.db.Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", uid, false).Count(&livePATs).Error)
	if livePATs != 0 {
		out = append(out, fmt.Sprintf("%d PAT(s) left unrevoked (they come back on RestoreUser/ReactivateUser)", livePATs))
	}

	var grants int64
	require.NoError(t, w.db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", uid).Count(&grants).Error)
	if grants != 0 {
		out = append(out, fmt.Sprintf("%d MFA step-up grant(s) left", grants))
	}

	for _, h := range append(slices.Clone(creds.sessionHashes), creds.patHashes...) {
		if !rec.has(h) {
			out = append(out, fmt.Sprintf("credential hash %q not tombstoned in the auth cache", h))
		}
	}

	// The other user is untouched: only the user's impersonation of it went.
	var otherUser models.User
	require.NoError(t, w.db.First(&otherUser, creds.otherID).Error)
	if !otherUser.IsActive {
		out = append(out, "the impersonated user was deactivated too")
	}

	if n := w.auditCount(t, event); n != auditBefore+1 {
		out = append(out, fmt.Sprintf("%d %q audit row(s) written, want exactly 1", n-auditBefore, event))
	}
	return out
}

func newLoginBlockingWorld(t *testing.T, w *txClosureWorld) (*tombstoneRecorder, uint) {
	t.Helper()
	rec := &tombstoneRecorder{seen: map[string]bool{}}
	w.c.SetTokenCacheInvalidator(rec.invalidate)
	actor := &models.User{Username: "lbt-actor", UsernameFolded: "lbt-actor", Email: "lbt-actor@example.com",
		EmailFolded: "lbt-actor@example.com", IsActive: true, AccountState: AccountActive}
	require.NoError(t, w.db.Create(actor).Error)
	return rec, actor.ID
}

// TestLoginBlockingTransitions_RevokeEveryCredential drives every row on
// write-gated SQLite and (with KEYORIX_TEST_PG_DSN) Postgres.
func TestLoginBlockingTransitions_RevokeEveryCredential(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		rec, actorID := newLoginBlockingWorld(t, w)
		for i, tr := range loginBlockingTransitions() {
			t.Run(tr.name, func(t *testing.T) {
				creds := seedLoginBlockedTarget(t, w, actorID, fmt.Sprintf("lbt%d", i))
				auditBefore := w.auditCount(t, tr.event)
				require.NoError(t, tr.run(ctx, t, w, actorID, creds.userID, creds.username))
				require.Empty(t, loginBlockedViolations(t, w, rec, creds, tr.event, auditBefore),
					"%s: a login-blocking transition must revoke every credential of the user", tr.name)
			})
		}
	})
}

// TestLoginBlockingTransitions_Calibration runs the checker against planted
// broken transitions, so a green table is evidence and not a checker that
// cannot fire. "sessions_only" is the shape of the real #2855 / #3419 defect
// (sessions deleted and evicted, PATs left live); "state_only" is a new
// transition that writes the blocked state and nothing else; "no_audit" does
// everything right but writes no audit row.
func TestLoginBlockingTransitions_Calibration(t *testing.T) {
	w := newGatedSQLiteWorld(t)
	ctx := context.Background()
	rec, actorID := newLoginBlockingWorld(t, w)
	const event = "account.calibration"
	block := func(t *testing.T, uid uint) {
		require.NoError(t, w.db.Model(&models.User{}).Where("id = ?", uid).
			Updates(map[string]any{"account_state": AccountSuspended}).Error)
	}
	audit := func(t *testing.T) {
		require.NoError(t, w.db.Create(&models.AuditEvent{EventType: event, EventTime: time.Now()}).Error)
	}
	for _, tc := range []struct {
		name    string
		plant   func(t *testing.T, creds blockedUserCredentials)
		mustSay []string
	}{
		{"sessions_only", func(t *testing.T, creds blockedUserCredentials) {
			block(t, creds.userID)
			require.NoError(t, w.fs.DeleteSessionsForUserExcept(ctx, creds.userID, 0))
			purgeStepUpGrants(ctx, w.fs, creds.userID)
			w.c.invalidateTokenCache(creds.sessionHashes...)
			audit(t)
		}, []string{"PAT(s) left unrevoked", "not tombstoned"}},
		{"state_only", func(t *testing.T, creds blockedUserCredentials) {
			block(t, creds.userID)
			audit(t)
		}, []string{"session(s) of the user", "PAT(s) left unrevoked", "step-up grant(s) left", "not tombstoned"}},
		{"no_audit", func(t *testing.T, creds blockedUserCredentials) {
			block(t, creds.userID)
			require.NoError(t, w.fs.DeleteSessionsForUserExcept(ctx, creds.userID, 0))
			hashes, err := w.fs.RevokeAllPersonalAccessTokensForUser(ctx, creds.userID)
			require.NoError(t, err)
			purgeStepUpGrants(ctx, w.fs, creds.userID)
			w.c.invalidateTokenCache(append(slices.Clone(creds.sessionHashes), hashes...)...)
		}, []string{"audit row(s) written, want exactly 1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := seedLoginBlockedTarget(t, w, actorID, "cal-"+tc.name)
			before := w.auditCount(t, event)
			tc.plant(t, creds)
			got := strings.Join(loginBlockedViolations(t, w, rec, creds, event, before), "\n")
			require.NotEmpty(t, got, "the checker passed a planted broken transition")
			for _, want := range tc.mustSay {
				require.Contains(t, got, want)
			}
		})
	}
	// Green direction: the same checker passes a correct planted transition.
	t.Run("correct", func(t *testing.T) {
		creds := seedLoginBlockedTarget(t, w, actorID, "cal-correct")
		before := w.auditCount(t, event)
		block(t, creds.userID)
		require.NoError(t, w.fs.DeleteSessionsForUserExcept(ctx, creds.userID, 0))
		hashes, err := w.fs.RevokeAllPersonalAccessTokensForUser(ctx, creds.userID)
		require.NoError(t, err)
		purgeStepUpGrants(ctx, w.fs, creds.userID)
		w.c.invalidateTokenCache(append(slices.Clone(creds.sessionHashes), hashes...)...)
		audit(t)
		require.Empty(t, loginBlockedViolations(t, w, rec, creds, event, before))
	})
}
