// cta_review_renew_vs_revoke_failed_postgres_test.go — #2698, the revoke_failed
// half (LEASE-SHARE-RACE-1).
//
// TestCTAReview_RenewLease_vs_RevokeLease_CrossReplicaPostgres covers a
// SUCCESSFUL revoke landing inside RenewLease. The more dangerous interleaving
// is a revoke whose target drop FAILED: the lease is `revoke_failed`, the
// credential is still live, and the sweep retries it once expires_at passes.
// The former full-row Save in RenewLease wrote status=active plus a LATER
// expires_at over that record, so the revoke_failed marker (the only signal an
// operator has that a credential needs dropping by hand) was lost and the sweep
// waited for the extended expiry. Renew must lose to a revoke, never the reverse.
//
// The revoke is landed inside replica A's engine.Renew, i.e. after A read the
// lease as active and before A's own write, on replica B's own connection, and
// runs to completion there (the barrier). Assertions read the lease row, not
// either call's return value. Runs on shared-file SQLite and, with
// KEYORIX_TEST_PG_DSN, on Postgres.
package core

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// renewHookEngine is a FakeEngine whose Renew first runs beforeRenew once.
type renewHookEngine struct {
	*dynamictest.FakeEngine
	once        sync.Once
	beforeRenew func()
}

func (e *renewHookEngine) Renew(ctx context.Context, adminDSN, roleName string, expiry time.Time) error {
	e.once.Do(e.beforeRenew)
	return e.FakeEngine.Renew(ctx, adminDSN, roleName, expiry)
}

func TestCTAReview_RenewLease_vs_RevokeFailed_SQLite(t *testing.T) {
	t.Parallel()
	assertRenewLosesToRevokeFailed(t, newCTAReviewSQLite(t))
}

func TestCTAReview_RenewLease_vs_RevokeFailed_CrossReplicaPostgres(t *testing.T) {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	t.Parallel()
	assertRenewLosesToRevokeFailed(t, newCTAReview(t))
}

func assertRenewLosesToRevokeFailed(t *testing.T, f *ctaReview) {
	t.Helper()
	cfg := dynCfg2698(t, f, "dyn-2698-renew-vs-revoke-failed")
	issued, err := f.setup.IssueLease(f.ctx, cfg.ID, 60, f.adminID)
	require.NoError(t, err)
	var before models.DynamicSecretLease
	require.NoError(t, f.setupDB.Where("lease_id = ?", issued.LeaseID).First(&before).Error)

	// Replica B: its target drop fails, so it records revoke_failed.
	failing := &dynamictest.FakeEngine{NativeExpiry: true, FailRevoke: true}
	f.coreB.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return failing, nil })
	var revokeErr error
	fired := false
	hook := &renewHookEngine{FakeEngine: &dynamictest.FakeEngine{NativeExpiry: true}, beforeRenew: func() {
		fired = true
		revokeErr = f.coreB.RevokeLease(f.ctx, issued.LeaseID, f.adminID, "incident")
	}}
	f.coreA.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return hook, nil })

	_, renewErr := f.coreA.RenewLease(f.ctx, issued.LeaseID, 3600, f.adminID)

	require.True(t, fired, "replica B's revoke never ran between A's read and A's write; the interleaving under test did not happen")
	require.Error(t, revokeErr, "B's target drop was set to fail; RevokeLease must report it")

	var after models.DynamicSecretLease
	require.NoError(t, f.setupDB.Where("lease_id = ?", issued.LeaseID).First(&after).Error)
	assert.Equal(t, "revoke_failed", after.Status,
		"the revoke_failed marker must survive the renewal (renew err: %v)", renewErr)
	assert.NotEmpty(t, after.RevokeError, "the revoke error recorded by B must not be erased")
	assert.Nil(t, after.RevokedAt, "a failed drop records no revoked_at")
	assert.True(t, after.ExpiresAt.Equal(before.ExpiresAt),
		"expires_at must not be extended over a revoke_failed lease (was %s, now %s)", before.ExpiresAt, after.ExpiresAt)
	assert.Error(t, renewErr, "the renewal lost to the revoke and must say so")

	// The operational consequence: the sweep retries this credential at its
	// ORIGINAL expiry, not the extended one.
	due, err := f.setup.Storage().ListExpiredActiveLeases(f.ctx, before.ExpiresAt.Add(time.Second))
	require.NoError(t, err)
	var ids []string
	for _, l := range due {
		ids = append(ids, l.LeaseID)
	}
	assert.Contains(t, ids, issued.LeaseID, "the sweep must pick the revoke_failed lease up at its original expiry")
}
