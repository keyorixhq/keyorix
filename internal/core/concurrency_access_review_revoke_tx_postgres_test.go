package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// concurrency_access_review_revoke_tx_postgres_test.go — the real-Postgres half
// of #2676.
//
// The SQLite tests (access_review_decide_atomicity_test.go) prove the rollback
// semantics. They cannot prove the thing that made this a deferred refactor
// rather than a patch: #2676's own issue text flags "named locks nested inside a
// transaction. That needs a lock-ordering review." LocalStorage.WithNamedLock
// takes a SESSION-scoped pg_advisory_lock on its OWN pooled connection, and
// WithTransaction runs on a different one, so the ordering of the two is a real
// question only Postgres can answer — on SQLite WithNamedLock is a process mutex
// and the hazard does not exist.
//
// The chosen ordering is named lock OUTSIDE, transaction INSIDE. The inverse
// deadlocks: a transaction holding the claim's row lock, then waiting on an
// advisory lock whose holder is waiting on that row. These tests exercise the
// chosen ordering under genuine contention — two reviewers on two independent
// connections, revoking two DIFFERENT items that share one
// projectAdminGuardLockKey, so each holds a transaction while contending for the
// same advisory lock.
//
// A deadlock here manifests as the test timing out rather than failing, which is
// why each racer is also bounded by its own context deadline: a hang is reported
// as a deadline-exceeded error naming this invariant, not as a 10-minute
// package-level timeout with no explanation.

// TestConcurrency_DecideAccessReviewRevoke_Postgres_NamedLockOutsideTransactionDoesNotDeadlock
// races two revokes that contend for the same project's named lock while each
// holds its own transaction.
func TestConcurrency_DecideAccessReviewRevoke_Postgres_NamedLockOutsideTransactionDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(accessReviewCampaignModels...))
	setupCore := NewKeyorixCore(localstore.NewLocalStorage(setupDB))
	setupCore.SetBootstrapToken("ar-revoke-tx-token")
	ctx := context.Background()

	boot, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "ar-revoke-tx-token",
	})
	require.NoError(t, err)
	projectID := boot.Project.ID

	reviewerB, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "ar-reviewer-b", Email: "ar-reviewer-b@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	viewerRole, err := setupCore.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)

	// TWO targets, so the campaign has two independently-revocable items. Both
	// grants are project-scoped in the SAME project, so both removals take
	// projectAdminGuardLockKey(projectID) — the contention this test needs.
	targets := make([]uint, 0, 2)
	for _, name := range []string{"ar-target-1", "ar-target-2"} {
		u, cerr := setupCore.CreateUser(ctx, &CreateUserRequest{
			Username: name, Email: name + "@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
		})
		require.NoError(t, cerr)
		require.NoError(t, setupCore.Storage().AssignRole(ctx, u.ID, viewerRole.ID, Scope{ProjectID: projectID}))
		targets = append(targets, u.ID)
	}

	open, err := setupCore.OpenAccessReviewCampaign(ctx, boot.User.ID, 0, projectID, "revoke tx race")
	require.NoError(t, err)
	campaignID := open.Campaign.ID
	detail, err := setupCore.GetAccessReviewCampaign(ctx, projectID, campaignID)
	require.NoError(t, err)

	itemFor := map[uint]uint{}
	for _, it := range detail.Items {
		if it.Source == "role" && it.RoleID == viewerRole.ID {
			itemFor[it.PrincipalID] = it.ID
		}
	}
	require.Len(t, itemFor, 2, "both targets' role grants must be campaign items")

	// Two replicas: own connection, own LocalStorage, own KeyorixCore (so own
	// accessReviewDecisionMu — the in-process mutex cannot serialize them).
	coreA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))

	// A generous per-racer deadline: this is a hang detector, not a latency
	// assertion (CLAUDE.md: timeouts detect hangs, they don't enforce speed).
	raceCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, 2)
	for i, pair := range []struct {
		core   *KeyorixCore
		actor  uint
		target uint
	}{
		{coreA, boot.User.ID, targets[0]},
		{coreB, reviewerB.ID, targets[1]},
	} {
		wg.Add(1)
		go func(idx int, c *KeyorixCore, actor, target uint) {
			defer wg.Done()
			<-start
			errs[idx] = c.DecideAccessReviewItem(raceCtx, actor, projectID, campaignID, itemFor[target], "revoke", "not needed")
		}(i, pair.core, pair.actor, pair.target)
	}
	close(start)
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "racer %d: both revokes target DIFFERENT items and must both succeed. A "+
			"deadline-exceeded error here means the named-lock-outside / transaction-inside ordering "+
			"deadlocked against itself under real Postgres advisory locks — the hazard #2676 called for a "+
			"lock-ordering review of", i)
	}

	// Both decisions must have landed, with both grants actually gone.
	verifier := localstore.NewLocalStorage(pgOpen(t, dsn))
	for _, target := range targets {
		item, ierr := verifier.GetAccessReviewItem(ctx, itemFor[target])
		require.NoError(t, ierr)
		assert.Equal(t, ReviewItemRevoked, item.Decision, "target %d's item must be revoked", target)
		grants, gerr := verifier.GetUserRoleIDsAt(ctx, target, storage.Scope{ProjectID: projectID})
		require.NoError(t, gerr)
		assert.NotContains(t, grants, viewerRole.ID, "target %d's grant must actually be gone", target)
	}
}

// TestDecideAccessReviewItem_Postgres_RevokeRollsBackClaimOnRemovalFailure is the
// rollback assertion against real Postgres rather than SQLite. It matters
// separately because Postgres aborts the whole transaction on a failing
// statement (CLAUDE.md: "catching a constraint violation after the failing
// statement is not recovery"), so a rollback path that happens to work on
// SQLite's more forgiving semantics is not evidence it works here.
func TestDecideAccessReviewItem_Postgres_RevokeRollsBackClaimOnRemovalFailure(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(accessReviewCampaignModels...))
	real := localstore.NewLocalStorage(db)
	faulty := faultstorage.NewFaultyStorage(real, nil)
	c := NewKeyorixCore(faulty)
	c.SetBootstrapToken("ar-revoke-rollback-token")
	ctx := context.Background()

	boot, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "ar-revoke-rollback-token",
	})
	require.NoError(t, err)
	projectID := boot.Project.ID

	reviewer, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "ar-rb-reviewer", Email: "ar-rb-reviewer@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "ar-rb-target", Email: "ar-rb-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	viewerRole, err := c.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRole(ctx, target.ID, viewerRole.ID, Scope{ProjectID: projectID}))

	open, err := c.OpenAccessReviewCampaign(ctx, boot.User.ID, 0, projectID, "rollback test")
	require.NoError(t, err)
	detail, err := c.GetAccessReviewCampaign(ctx, projectID, open.Campaign.ID)
	require.NoError(t, err)
	var itemID uint
	for _, it := range detail.Items {
		if it.Source == "role" && it.PrincipalID == target.ID && it.RoleID == viewerRole.ID {
			itemID = it.ID
		}
	}
	require.NotZero(t, itemID)

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	err = c.DecideAccessReviewItem(ctx, reviewer.ID, projectID, open.Campaign.ID, itemID, "revoke", "not needed")
	require.Error(t, err)
	require.True(t, faulty.Fired(), "the fault must actually have been reached")

	// Verify from an UNFAULTED connection: the claim must have rolled back with
	// the removal.
	verifier := localstore.NewLocalStorage(pgOpen(t, dsn))
	item, err := verifier.GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	assert.Equal(t, ReviewItemPending, item.Decision,
		"on Postgres too, a failed removal must roll the claim back — not leave the item stamped `revoked` "+
			"for a grant that still exists")
	grants, err := verifier.GetUserRoleIDsAt(ctx, target.ID, storage.Scope{ProjectID: projectID})
	require.NoError(t, err)
	assert.Contains(t, grants, viewerRole.ID, "the grant must still exist")

	// And the decision is retryable once the fault clears.
	faulty.Arm(nil)
	require.NoError(t, c.DecideAccessReviewItem(ctx, reviewer.ID, projectID, open.Campaign.ID, itemID, "revoke", "not needed"))
	item, err = verifier.GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	assert.Equal(t, ReviewItemRevoked, item.Decision)
}
