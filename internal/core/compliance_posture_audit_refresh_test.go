// compliance_posture_audit_refresh_test.go — COMPLIANCE-TILE-NOV-1 item 2: the
// posture's audit-chain check is recomputed by a request that finds it older than
// five minutes, served from the cache before that, and a failed refresh keeps the
// previous value marked stale. All on a fake clock; the walk is the real tail
// check against a real store, counted, except where a failure is injected.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPostureRefreshCore is an incremental-verification core with one tick behind
// it (so a checkpoint exists) and the posture walk counted.
func newPostureRefreshCore(t *testing.T) (*KeyorixCore, *incrClock, *int) {
	t.Helper()
	c, _, clk := newIncrementalTestCore(t, 3)
	logIncrEvents(t, c, clk, 5)
	tickOK(t, c)
	walks := new(int)
	c.auditPostureWalk = func(ctx context.Context) (*AuditVerifyReport, error) {
		*walks++
		return c.VerifyAuditChainIncremental(ctx)
	}
	return c, clk, walks
}

// postureSnapshot builds the audit part of a posture the way GetCompliancePosture
// does (fillAuditSnapshot, then applyAuditIntegrityPosture). The whole posture
// needs tables this fixture does not migrate.
func postureSnapshot(t *testing.T, c *KeyorixCore) *CompliancePosture {
	t.Helper()
	snap := &complianceSnapshot{}
	c.fillAuditSnapshot(context.Background(), snap)
	require.NoError(t, snap.auditChainErr, "a refresh problem must never fail the page")
	p := &CompliancePosture{}
	applyAuditIntegrityPosture(p, snap)
	return p
}

func postureAudit(t *testing.T, c *KeyorixCore) AuditIntegrityPosture {
	t.Helper()
	return postureSnapshot(t, c).AuditIntegrity
}

func TestPostureAuditCheck_StaleValueIsRefreshed(t *testing.T) {
	t.Parallel()
	c, clk, walks := newPostureRefreshCore(t)

	first := postureAudit(t, c)
	require.Equal(t, 1, *walks, "an empty cache walks once")
	require.Equal(t, clk.t, *first.LastCheckedAt, "the check is stamped with the walk time, not the scheduler tick")

	// Events written after the tick, then six minutes: the tile must catch up with
	// what `audit verify` would walk now.
	logIncrEvents(t, c, clk, 20)
	clk.t = clk.t.Add(6 * time.Minute)
	want := incrVerify(t, c)
	require.Greater(t, want.ChainedEvents, first.ChainedEvents)

	got := postureAudit(t, c)
	assert.Equal(t, 2, *walks, "a value older than five minutes is recomputed")
	assert.Equal(t, want.ChainedEvents, got.ChainedEvents, "the tile agrees with audit verify")
	assert.Equal(t, clk.t, *got.LastCheckedAt)
	assert.False(t, got.Stale)
}

func TestPostureAuditCheck_FreshValueIsServedFromCache(t *testing.T) {
	t.Parallel()
	c, clk, walks := newPostureRefreshCore(t)

	first := postureAudit(t, c)
	logIncrEvents(t, c, clk, 20)

	// 90 seconds: past the one-minute freshness window (so the tile says stale and
	// counts the newer events from the cheap head lookup) but inside five minutes:
	// no second walk.
	clk.t = clk.t.Add(90 * time.Second)
	got := postureAudit(t, c)
	assert.Equal(t, 1, *walks, "inside five minutes nothing is recomputed")
	assert.Equal(t, first.ChainedEvents, got.ChainedEvents)
	assert.True(t, got.Stale)
	assert.EqualValues(t, 20, got.EventsSinceCheck, "the newer events are counted, not verified")

	// Exactly five minutes is still the cache; one second more is not.
	clk.t = clk.t.Add(5*time.Minute - 90*time.Second)
	postureAudit(t, c)
	assert.Equal(t, 1, *walks)
	clk.t = clk.t.Add(time.Second)
	postureAudit(t, c)
	assert.Equal(t, 2, *walks)
}

func TestPostureAuditCheck_FailedRefreshKeepsLastValueAndMarksItStale(t *testing.T) {
	t.Parallel()
	c, clk, walks := newPostureRefreshCore(t)

	before := postureAudit(t, c)
	logIncrEvents(t, c, clk, 20)

	failing := true
	c.auditPostureWalk = func(ctx context.Context) (*AuditVerifyReport, error) {
		*walks++
		if failing {
			return nil, errors.New("database is locked")
		}
		return c.VerifyAuditChainIncremental(ctx)
	}

	clk.t = clk.t.Add(6 * time.Minute)
	p := postureSnapshot(t, c)
	got := p.AuditIntegrity
	assert.Equal(t, before.ChainedEvents, got.ChainedEvents, "the last value is kept")
	assert.Equal(t, before.VerificationStatus, got.VerificationStatus)
	assert.True(t, got.Stale, "and marked stale")
	assert.EqualValues(t, 20, got.EventsSinceCheck)
	assert.False(t, p.Degraded, "a stale tile is not a degraded snapshot: its value is known, only old")
	failedWalks := *walks

	// The failure is not retried on every page load...
	clk.t = clk.t.Add(time.Minute)
	assert.True(t, postureAudit(t, c).Stale)
	assert.Equal(t, failedWalks, *walks)

	// ...but after the window, and once the walk works again the tile recovers.
	failing = false
	clk.t = clk.t.Add(5 * time.Minute)
	got = postureAudit(t, c)
	assert.Equal(t, failedWalks+1, *walks)
	assert.False(t, got.Stale)
	assert.Greater(t, got.ChainedEvents, before.ChainedEvents)
}

func TestPostureAuditCheck_FailedFirstRefreshFallsBackToPersistedState(t *testing.T) {
	t.Parallel()
	c, _, _ := newPostureRefreshCore(t)
	c.auditPostureWalk = func(context.Context) (*AuditVerifyReport, error) {
		return nil, errors.New("database is locked")
	}

	got := postureAudit(t, c)
	assert.True(t, got.Stale)
	assert.NotZero(t, got.ChainedEvents, "the scheduler's recorded check is still shown")
}

func TestPostureAuditCheck_AbandonedRequestDoesNotPoisonTheCache(t *testing.T) {
	t.Parallel()
	c, clk, walks := newPostureRefreshCore(t)
	postureAudit(t, c)
	clk.t = clk.t.Add(6 * time.Minute)

	// The client hangs up mid-walk: that is not a verdict on the check, so the
	// next request must walk again instead of waiting out the retry window.
	ctx, cancel := context.WithCancel(context.Background())
	c.auditPostureWalk = func(context.Context) (*AuditVerifyReport, error) {
		*walks++
		cancel()
		return nil, ctx.Err()
	}
	_, refreshFailed, err := c.auditPostureReport(ctx)
	require.NoError(t, err)
	assert.True(t, refreshFailed, "this caller still gets the old value, marked stale")
	assert.Equal(t, 2, *walks)

	c.auditPostureWalk = func(ctx context.Context) (*AuditVerifyReport, error) {
		*walks++
		return c.VerifyAuditChainIncremental(ctx)
	}
	_, refreshFailed, err = c.auditPostureReport(context.Background())
	require.NoError(t, err)
	assert.False(t, refreshFailed)
	assert.Equal(t, 3, *walks, "the abandoned attempt was not remembered")
}
