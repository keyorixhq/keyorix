package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// THREATMODEL-VERIFY-1 (#3424, DYN-3 / DYN-4): the renew-side twins of the guards that
// dynamic_secrets_guards_test.go pins for IssueLease / RevokeLease. RenewLease carries
// the same two fail-closed checks, and without a test of its own either one could be
// dropped with every other dynamic-secret test staying green.

// TestDynamicSecrets_RenewRefusesNoNativeExpiryBackendWithoutSweeper: a lease on a
// backend with no DB-level expiry (MySQL, MongoDB, Redis) is enforced only by the
// sweeper. If the sweeper has since been switched off, a renewal would extend a
// credential nothing will ever revoke, so RenewLease must refuse before it reaches the
// target. Calibrated: with the sweeper on, the same renewal succeeds.
func TestDynamicSecrets_RenewRefusesNoNativeExpiryBackendWithoutSweeper(t *testing.T) {
	t.Parallel()
	c, _, fake, fixed := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	fake.NativeExpiry = false // mimic MySQL/MongoDB

	c.SetDynamicSweepEnabled(true)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	c.SetDynamicSweepEnabled(false)
	_, err = c.RenewLease(ctx, issued.LeaseID, 7200, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lease sweeper is disabled")
	assert.Empty(t, fake.Renewed, "the target is never asked to extend a lease nothing would revoke")

	// Calibration: the refusal is the sweeper gate, not a problem with the request.
	c.SetDynamicSweepEnabled(true)
	exp, err := c.RenewLease(ctx, issued.LeaseID, 7200, 7)
	require.NoError(t, err)
	assert.Equal(t, fixed.Add(2*time.Hour), exp)
	assert.Contains(t, fake.Renewed, issued.Username)
}

// TestDynamicSecrets_RenewRevalidatesAdminDSN: a config whose decrypted admin DSN points
// at a private or link-local address (stored while the private-network switch was on, or
// before the register-time guard existed) must be refused at RenewLease once the switch is
// off, with the engine never called and the lease unchanged.
func TestDynamicSecrets_RenewRevalidatesAdminDSN(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()

	c.SetDynamicAllowPrivateTargets(true)
	cfg, err := c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "imds-renew", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
		AdminDSN: "postgres://admin:pass@169.254.169.254:5432/app", DefaultTTLSeconds: 3600,
		CreatedBy: "alice", ActorID: testAdminActorID,
	})
	require.NoError(t, err)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	c.SetDynamicAllowPrivateTargets(false)

	_, err = c.RenewLease(ctx, issued.LeaseID, 7200, 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private or link-local")
	assert.Empty(t, fake.Renewed, "nothing is dialled: the engine was not asked to renew")

	leases, lerr := c.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, lerr)
	require.Len(t, leases, 1)
	assert.Equal(t, issued.ExpiresAt, leases[0].ExpiresAt, "a refused renewal must not move the expiry")
}
