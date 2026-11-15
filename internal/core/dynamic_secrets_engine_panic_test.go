package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// DYNAMIC-ENGINE-PANIC-1 item 3: what a client-library panic inside an engine does to
// the lease state. The engine is the production wrapper (dynamic.Contain, which
// dynamic.New applies) around an engine that panics with a message carrying a DSN.

const panicSecret = "postgres://admin:hunter2@db.internal/app"

// panickingEngine panics where a malformed target reply would panic the client. It
// embeds the fake only for the methods it does not override.
type panickingEngine struct {
	*dynamictest.FakeEngine
	panicIssue, panicRevoke, panicRenew bool
}

func (p *panickingEngine) Issue(ctx context.Context, dsn, tmpl string, ttl time.Duration) (dynamic.Credential, string, error) {
	if p.panicIssue {
		// the target already created the role when the reply parser blew up
		p.Issued = append(p.Issued, "kx_dyn_created_before_panic")
		panic("parse reply from " + panicSecret)
	}
	return p.FakeEngine.Issue(ctx, dsn, tmpl, ttl)
}

func (p *panickingEngine) Revoke(ctx context.Context, dsn, role string) error {
	if p.panicRevoke {
		panic("parse reply from " + panicSecret)
	}
	return p.FakeEngine.Revoke(ctx, dsn, role)
}

func (p *panickingEngine) Renew(ctx context.Context, dsn, role string, at time.Time) error {
	if p.panicRenew {
		panic("parse reply from " + panicSecret)
	}
	return p.FakeEngine.Renew(ctx, dsn, role, at)
}

func newPanicCore(t *testing.T) (*KeyorixCore, *gorm.DB, *panickingEngine) {
	t.Helper()
	c, db, fake, _ := newDynamicTestCore(t)
	pe := &panickingEngine{FakeEngine: fake}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return dynamic.Contain(pe), nil })
	return c, db, pe
}

// assertContainedErr: typed, names the operation, carries nothing the panic said, and
// is NOT one of the classes the handlers map to 404/409/400, so the existing
// engine-failure answer (502 on HTTP, the matching code on gRPC) applies.
func assertContainedErr(t *testing.T, err error, op string) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, dynamic.ErrEngineClientPanic), "typed containment error: %v", err)
	assert.Contains(t, err.Error(), op)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.NotContains(t, err.Error(), "db.internal")
	assert.False(t, errors.Is(err, ErrDynamicSecretNotFound))
	assert.False(t, errors.Is(err, ErrDynamicSecretPrecondition))
	assert.False(t, errors.Is(err, ErrValidation))
}

func TestDynamicSecrets_IssuePanicLeavesNoLease(t *testing.T) {
	t.Parallel()
	c, db, pe := newPanicCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	pe.panicIssue = true
	_, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	assertContainedErr(t, err, "Issue")

	// Same outcome as an ordinary Issue error: no lease row, no revoke_failed row (the
	// engine never returned the role name, so there is nothing core could name).
	var n int64
	require.NoError(t, db.Model(&models.DynamicSecretLease{}).Count(&n).Error)
	assert.Zero(t, n, "no lease row after a panicking Issue")

	// The config is still usable.
	pe.panicIssue = false
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
}

func TestDynamicSecrets_RevokePanicNeverMarksRevoked(t *testing.T) {
	t.Parallel()
	c, _, pe := newPanicCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	pe.panicRevoke = true
	assertContainedErr(t, c.RevokeLease(ctx, issued.LeaseID, 7, "manual"), "Revoke")

	// Exactly what an ordinary Revoke error leaves: revoke_failed (the sweeper retries
	// active AND revoke_failed leases), no RevokedAt, nothing from the panic stored.
	after, err := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	require.NoError(t, err)
	assert.Equal(t, "revoke_failed", after.Status)
	assert.NotEqual(t, "revoked", after.Status)
	assert.Nil(t, after.RevokedAt)
	assert.NotContains(t, after.RevokeError, "hunter2")
	assert.NotContains(t, after.RevokeError, "db.internal")

	// The retry (what the sweeper does) works once the client behaves.
	pe.panicRevoke = false
	require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "retry"))
	done, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "revoked", done.Status)
}

func TestDynamicSecrets_RenewPanicKeepsLeaseAsIs(t *testing.T) {
	t.Parallel()
	c, _, pe := newPanicCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)
	before, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)

	pe.panicRenew = true
	_, err = c.RenewLease(ctx, issued.LeaseID, 7200, 7)
	assertContainedErr(t, err, "Renew")

	after, _ := c.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
	assert.Equal(t, "active", after.Status)
	assert.True(t, before.ExpiresAt.Equal(after.ExpiresAt), "expiry untouched by a failed renew")
}
