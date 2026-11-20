// cta_review_liveness_race_loop_postgres_test.go — LIVENESS-IN-TX-NOV-1: the
// UNFORCED half of the child-insert vs parent-delete proofs for #2646, #2647,
// #2649, #2652 and #2656.
//
// The TestCTAReview_* tests in concurrency_check_then_act_exempt_review_postgres_test.go
// each force ONE interleaving with a one-shot GORM hook (B's delete immediately
// before, or immediately after, A's child write). They prove each window is
// closed, but only at the points a hook can reach. The tests here force no
// order: replica A's child write and replica B's parent delete are released
// from a barrier, each on its own *gorm.DB pool, for livenessRaceRounds rounds
// with a fresh parent per round. B's start is offset by a step that sweeps
// across A's measured solo duration (raceOffset), and the scheduler and the
// database pick the rest of the interleaving, including the one where A's FOR
// SHARE re-check lands first and B's cascade waits for it, which the hooks
// cannot produce. Each round asserts the one
// invariant that holds under EVERY legal interleaving: once B's delete has
// committed, no live child exists under the deleted parent. A's own result is
// logged, not asserted: A may legitimately win (and then be swept by B) or
// fail closed.
//
// What this does NOT prove: that any particular round hit the narrow window.
// The forced tests are the per-window proof; these are the regression net
// against an ordering nobody wrote a hook for. Run with -race; Postgres only.
package core

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// livenessRaceRounds is the number of barrier-released races per test.
const livenessRaceRounds = 50

// raceFromBarrier runs a and b on their own goroutines, released together, and
// waits for both. offset > 0 delays b's start by offset, offset < 0 delays a's.
func raceFromBarrier(offset time.Duration, a, b func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	run := func(fn func(), delay time.Duration) {
		defer wg.Done()
		<-start
		if delay > 0 {
			time.Sleep(delay)
		}
		fn()
	}
	wg.Add(2)
	go run(a, -offset)
	go run(b, offset)
	close(start)
	wg.Wait()
}

// raceOffset spreads B's start across A's run: round i of livenessRaceRounds
// starts B from a quarter of A's solo duration BEFORE A up to the end of A's
// run, in equal steps. Released at the same instant, the cheap parent delete
// won every round against A's reads-then-write (measured: 50 of 50), so the
// barrier alone never reached the window around A's write.
func raceOffset(i int, soloA time.Duration) time.Duration {
	return raceOffsetFrom(i, soloA, soloA/4)
}

// raceOffsetFrom is raceOffset with B leading A by up to lead in the first rounds.
// IssueLease uses soloA/2: with soloA/4 its refused count was only 5 to 10 of 50
// across five -race runs, too thin a margin for requireBothOutcomes on a slow runner.
func raceOffsetFrom(i int, soloA, lead time.Duration) time.Duration {
	lo := -lead
	return lo + time.Duration(i)*(soloA-lo)/time.Duration(livenessRaceRounds)
}

// timeSolo returns how long fn takes with nothing racing it (the best of three,
// so one slow first call does not stretch the sweep).
func timeSolo(fn func()) time.Duration {
	best := time.Duration(0)
	for range 3 {
		t0 := time.Now()
		fn()
		if d := time.Since(t0); best == 0 || d < best {
			best = d
		}
	}
	return best
}

// raceTally counts how each round ended for A. The test requires both outcomes:
// a loop where A always lost, or always won, raced nothing.
type raceTally struct{ aWon, aRefused int }

func (r *raceTally) add(errA error) {
	if errA == nil {
		r.aWon++
	} else {
		r.aRefused++
	}
}

// requireBothOutcomes fails the test when every round ended the same way for A.
func (r *raceTally) requireBothOutcomes(t *testing.T, what string) {
	t.Helper()
	t.Logf("%d rounds: %s won %d (then swept by the delete), refused %d", livenessRaceRounds, what, r.aWon, r.aRefused)
	require.True(t, r.aWon > 0 && r.aRefused > 0,
		"the offset sweep never reached both orderings (won %d, refused %d): the loop raced nothing", r.aWon, r.aRefused)
}

// freshProject creates a new live project with one environment for one round.
func (f *ctaReview) freshProject(round int, tag string) (projectID, envID uint) {
	f.t.Helper()
	p, err := f.setup.CreateProject(f.ctx, fmt.Sprintf("race-%s-%d", tag, round), "")
	require.NoError(f.t, err)
	e, err := f.setup.CreateEnvironment(f.ctx, p.ID, "race-env")
	require.NoError(f.t, err)
	return p.ID, e.ID
}

// TestLivenessRace_ShareSecret_vs_DeleteSecret_Postgres: #2646.
func TestLivenessRace_ShareSecret_vs_DeleteSecret_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("race-owner", "project_admin")
	recipient := f.user("race-recipient", "project_viewer")
	share := func(secretID uint) error {
		_, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
			SecretID: secretID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
		})
		return err
	}
	n := 0
	solo := timeSolo(func() { n++; require.NoError(t, share(f.secret(fmt.Sprintf("race-share-solo-%d", n), owner.ID).ID)) })
	var tally raceTally
	for i := range livenessRaceRounds {
		s := f.secret(fmt.Sprintf("race-share-%d", i), owner.ID)
		var errA, errB error
		raceFromBarrier(raceOffset(i, solo),
			func() { errA = share(s.ID) },
			func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) },
		)
		require.NoError(t, errB, "round %d: DeleteSecret", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
			"round %d (ShareSecret err=%v): #370 violated, a live share exists on a soft-deleted secret", i, errA)
	}
	tally.requireBothOutcomes(t, "ShareSecret")
}

// TestLivenessRace_ShareSecretWithGroup_vs_DeleteSecret_Postgres: #2647.
func TestLivenessRace_ShareSecretWithGroup_vs_DeleteSecret_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("race-gowner", "project_admin")
	g := &models.Group{Name: "race-group", NameFolded: "race-group"}
	require.NoError(t, f.setupDB.Create(g).Error)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRoleToGroup(f.ctx, g.ID, viewer.ID, Scope{ProjectID: f.projectID}))
	share := func(secretID uint) error {
		_, err := f.coreA.ShareSecretWithGroup(f.ctx, &GroupShareSecretRequest{
			SecretID: secretID, GroupID: g.ID, Permission: "read", SharedBy: owner.ID,
		})
		return err
	}
	n := 0
	solo := timeSolo(func() { n++; require.NoError(t, share(f.secret(fmt.Sprintf("race-gshare-solo-%d", n), owner.ID).ID)) })
	var tally raceTally
	for i := range livenessRaceRounds {
		s := f.secret(fmt.Sprintf("race-gshare-%d", i), owner.ID)
		var errA, errB error
		raceFromBarrier(raceOffset(i, solo),
			func() { errA = share(s.ID) },
			func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) },
		)
		require.NoError(t, errB, "round %d: DeleteSecret", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
			"round %d (ShareSecretWithGroup err=%v): #370 violated, a live group share exists on a soft-deleted secret", i, errA)
	}
	tally.requireBothOutcomes(t, "ShareSecretWithGroup")
}

// TestLivenessRace_GrantSecretACL_vs_DeleteSecret_Postgres: #2649.
func TestLivenessRace_GrantSecretACL_vs_DeleteSecret_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("race-aclgrantee", "project_viewer")
	grant := func(secretID uint) error {
		return f.coreA.GrantSecretACL(f.ctx, f.adminID, secretID, grantee.ID, []string{"secrets.read"})
	}
	n := 0
	solo := timeSolo(func() { n++; require.NoError(t, grant(f.secret(fmt.Sprintf("race-acl-solo-%d", n), f.adminID).ID)) })
	var tally raceTally
	for i := range livenessRaceRounds {
		s := f.secret(fmt.Sprintf("race-acl-%d", i), f.adminID)
		var errA, errB error
		raceFromBarrier(raceOffset(i, solo),
			func() { errA = grant(s.ID) },
			func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) },
		)
		require.NoError(t, errB, "round %d: DeleteSecret", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ?", s.ID),
			"round %d (GrantSecretACL err=%v): CWE-284 cascade violated, an ACL grant exists on a soft-deleted secret", i, errA)
	}
	tally.requireBothOutcomes(t, "GrantSecretACL")
}

// TestLivenessRace_RestoreEnvironment_vs_DeleteProject_Postgres: #2656.
func TestLivenessRace_RestoreEnvironment_vs_DeleteProject_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	deletedEnv := func(round int, tag string) (uint, uint) {
		pid, eid := f.freshProject(round, tag)
		require.NoError(t, f.setup.DeleteEnvironment(f.ctx, eid))
		return pid, eid
	}
	n := 0
	solo := timeSolo(func() {
		n++
		pid, eid := deletedEnv(n, "env-solo")
		require.NoError(t, f.coreA.RestoreEnvironment(f.ctx, f.adminID, pid, eid))
	})
	var tally raceTally
	for i := range livenessRaceRounds {
		pid, eid := deletedEnv(i, "env")
		var errA, errB error
		raceFromBarrier(raceOffset(i, solo),
			func() { errA = f.coreA.RestoreEnvironment(f.ctx, f.adminID, pid, eid) },
			func() { errB = f.coreB.DeleteProject(f.ctx, 0, pid, true) },
		)
		require.NoError(t, errB, "round %d: DeleteProject", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.Environment{}, "project_id = ? AND deleted_at IS NULL", pid),
			"round %d (RestoreEnvironment err=%v): a live environment exists under a soft-deleted project", i, errA)
	}
	tally.requireBothOutcomes(t, "RestoreEnvironment")
}

// TestLivenessRace_IssueLease_vs_DeleteProject_Postgres: #2652. Two invariants:
// no lease row is still active under the deleted project and disabled config,
// and every credential the engine minted was revoked on the target (by B's
// post-commit lease revocation when A's lease committed first, or by IssueLease's
// own compensation when its write-then-check refused the lease).
func TestLivenessRace_IssueLease_vs_DeleteProject_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	config := func(round int, tag string) (uint, uint) {
		pid, eid := f.freshProject(round, tag)
		cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
			Name: fmt.Sprintf("race-%s-%d", tag, round), ProjectID: pid, EnvironmentID: eid, BackendType: "postgres",
			AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
			CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
			DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
		})
		require.NoError(t, err)
		return pid, cfg.ID
	}
	n := 0
	solo := timeSolo(func() {
		n++
		_, cfgID := config(n, "lease-solo")
		_, err := f.coreA.IssueLease(f.ctx, cfgID, 0, f.adminID)
		require.NoError(t, err)
	})
	soloIssued := len(fake.Issued) // solo leases stay live: they are outside the invariant below
	var tally raceTally
	for i := range livenessRaceRounds {
		pid, cfgID := config(i, "lease")
		var errA, errB error
		raceFromBarrier(raceOffsetFrom(i, solo, solo/2),
			func() { _, errA = f.coreA.IssueLease(f.ctx, cfgID, 0, f.adminID) },
			func() { errB = f.coreB.DeleteProject(f.ctx, 0, pid, true) },
		)
		require.NoError(t, errB, "round %d: DeleteProject", i)
		tally.add(errA)
		require.Zero(t, f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfgID, "active"),
			"round %d (IssueLease err=%v): #369 violated, an active lease exists under a deleted project and a disabled config", i, errA)
	}
	raced := fake.Issued[soloIssued:]
	for _, u := range raced {
		require.True(t, slices.Contains(fake.Revoked, u),
			"credential %s was minted on the target during a race and never revoked (minted %d, revoked %d)", u, len(raced), len(fake.Revoked))
	}
	t.Logf("raced mints %d, target revocations %d", len(raced), len(fake.Revoked))
	tally.requireBothOutcomes(t, "IssueLease")
}
