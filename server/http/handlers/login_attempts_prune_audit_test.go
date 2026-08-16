// login_attempts_prune_audit_test.go — CORE-RATE-003 regression test.
//
// PruneLoginAttemptsProxy (POST /api/v1/system/login-attempts/prune) used to
// pass an attacker-controlled `before` from the request body straight to
// storage.Storage.PruneLoginAttempts with no ceiling and no audit trail: any
// principal holding system.write could supply a far-future `before` (e.g.
// "2099-01-01T00:00:00Z") and wipe the ENTIRE login_attempts table on demand
// — every IP's failed-login counter reset to zero, and the only record a
// brute-force campaign was ever attempted from any address erased, silently.
//
// This test proves the fix at the effective enforcement point (the proxy
// handler, now routed through core.KeyorixCore.PruneLoginAttempts): a
// far-future `before` cannot remove a row still inside the active
// rate-limit window, and an actual deletion leaves a
// data.login_attempts_pruned audit event behind.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// freshCoreForLoginPruneAudit opens a dedicated in-memory SQLite DB (with
// LoginAttempt + AuditEvent migrated, since this test asserts on both) and
// returns a ready KeyorixCore plus the raw *gorm.DB for direct audit-row
// verification.
func freshCoreForLoginPruneAudit(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.AuditEvent{}))
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestPruneLoginAttemptsProxy_ClampsFutureBeforeAndAudits(t *testing.T) {
	cs, db := freshCoreForLoginPruneAudit(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	// A login attempt recorded "now" — still well inside core.LoginWindow (15
	// minutes) — must survive ANY prune request, no matter what `before` the
	// caller supplies: it is live rate-limit state, not aged-out evidence.
	require.NoError(t, cs.Storage().RecordLoginAttempt(ctx, "203.0.113.9", time.Now()))
	// An attempt genuinely past the window (16 minutes ago) is legitimately
	// eligible for removal.
	require.NoError(t, cs.Storage().RecordLoginAttempt(ctx, "198.51.100.4", time.Now().Add(-16*time.Minute)))

	// The exploit payload: an unbounded, attacker-supplied far-future cutoff —
	// e.g. the finding's own "2099-01-01T00:00:00Z" example — that would wipe
	// the whole table under the pre-fix passthrough.
	attackerBefore := time.Now().Add(100 * 365 * 24 * time.Hour)
	body := proxyJSON(map[string]interface{}{"before": attackerBefore})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts/prune", body)
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	require.True(t, resp.Success)

	// The still-fresh row for 203.0.113.9 must have survived: the clamp to
	// now-LoginWindow, not the attacker's far-future `before`, governed the
	// deletion.
	n, err := cs.Storage().CountRecentLoginAttempts(ctx, "203.0.113.9", time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "a login attempt inside the active rate-limit window must survive an unbounded prune request")

	// The genuinely aged row was still pruned — the fix narrows the blast
	// radius, it doesn't disable maintenance pruning altogether.
	n, err = cs.Storage().CountRecentLoginAttempts(ctx, "198.51.100.4", time.Time{})
	require.NoError(t, err)
	assert.Zero(t, n, "a login attempt genuinely past the rate-limit window is still pruned")

	// Exactly one data.login_attempts_pruned audit event was written for the
	// actual deletion — the primitive that previously left NO trace at all of
	// an on-demand wipe of brute-force evidence.
	var events []models.AuditEvent
	require.NoError(t, db.Find(&events, "event_type = ?", "data.login_attempts_pruned").Error)
	require.Len(t, events, 1, "exactly one audit event for the prune")
	assert.Contains(t, events[0].Description, "1", "the audit description records the row count")
}

func TestPruneLoginAttemptsProxy_NoAuditWhenNothingToPrune(t *testing.T) {
	cs, db := freshCoreForLoginPruneAudit(t)
	h := NewAuthHandler(cs, false)

	// No rows recorded at all: the prune legitimately removes nothing.
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts/prune", body)
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var events []models.AuditEvent
	require.NoError(t, db.Find(&events, "event_type = ?", "data.login_attempts_pruned").Error)
	assert.Empty(t, events, "no audit event when nothing was actually removed")
}
