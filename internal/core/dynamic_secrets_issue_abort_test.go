package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// DYNAMIC-HOSTILE-TAILS-1 item 1: an Issue that panics AFTER the target created the
// account must not orphan it. The engine reports the name before its first target write
// (ports.ReportIssuedRole); core records and revokes it.

// reportThenPanicEngine behaves like the database engines: it names the account, the
// target creates it, then the client library panics on the reply.
type reportThenPanicEngine struct {
	*dynamictest.FakeEngine
	report bool // false: a pre-change engine that never names its account
}

func (e *reportThenPanicEngine) Issue(ctx context.Context, _, _ string, _ time.Duration) (dynamic.Credential, string, error) {
	const role = "kx_dyn_orphaned0001"
	if e.report {
		ports.ReportIssuedRole(ctx, role)
	}
	panic("parse reply from " + panicSecret)
}

func newReportPanicCore(t *testing.T, report bool) (*KeyorixCore, *dynamictest.FakeEngine, time.Time) {
	t.Helper()
	c, _, fake, now := newDynamicTestCore(t)
	eng := &reportThenPanicEngine{FakeEngine: fake, report: report}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return dynamic.Contain(eng), nil })
	return c, fake, now
}

func listLeases(t *testing.T, c *KeyorixCore, configID uint) []*models.DynamicSecretLease {
	t.Helper()
	leases, err := c.storage.ListDynamicSecretLeases(context.Background(), configID)
	require.NoError(t, err)
	return leases
}

// The revoke right after the panic fails too (the target is in the same bad state): the
// account must be in the lease record, and the sweep must revoke it once the target recovers.
func TestDynamicSecrets_IssuePanicAfterCreateIsRecordedAndSwept(t *testing.T) {
	t.Parallel()
	c, fake, now := newReportPanicCore(t, true)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	fake.FailRevoke = true
	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	assertContainedErr(t, err, "Issue")

	leases := listLeases(t, c, cfg.ID)
	require.Len(t, leases, 1, "the orphaned account is in the lease record")
	assert.Equal(t, "kx_dyn_orphaned0001", leases[0].RoleName)
	assert.Equal(t, "revoke_failed", leases[0].Status)
	assert.Empty(t, leases[0].CredentialEnc, "no credential was ever returned, none is stored")
	assert.NotContains(t, leases[0].RevokeError, "hunter2")
	assert.NotContains(t, leases[0].RevokeError, "db.internal")

	fake.FailRevoke = false
	revoked, err := c.RevokeExpiredLeases(ctx, now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
	assert.True(t, slices.Contains(fake.Revoked, "kx_dyn_orphaned0001"), "the sweep revoked the orphan: %v", fake.Revoked)
	after, err := c.storage.GetDynamicSecretLease(ctx, leases[0].LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", after.Status)
}

// When the target is reachable again by the time core cleans up, the account is dropped
// at once and no lease row is left behind (same as the existing post-mint failures).
func TestDynamicSecrets_IssuePanicAfterCreateRevokesImmediately(t *testing.T) {
	t.Parallel()
	c, fake, _ := newReportPanicCore(t, true)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	assertContainedErr(t, err, "Issue")

	assert.Equal(t, []string{"kx_dyn_orphaned0001"}, fake.Revoked)
	assert.Empty(t, listLeases(t, c, cfg.ID), "a cleanly revoked orphan leaves no lease row")
}

// An engine that never reports a name (cloud engines create no account) is not asked to
// revoke anything: core has no name to give it.
func TestDynamicSecrets_IssuePanicWithoutReportRevokesNothing(t *testing.T) {
	t.Parallel()
	c, fake, _ := newReportPanicCore(t, false)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	assertContainedErr(t, err, "Issue")
	assert.Empty(t, fake.Revoked)
	assert.Empty(t, listLeases(t, c, cfg.ID))
}
