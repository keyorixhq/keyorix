// secrets_analytics_s13_test.go — coverage sweep targeting:
//   - secrets_risk.go         (GetSecretRisk): not-found (404), success path
//   - secrets_access_history.go (AccessHistory): not-found (404), days capping,
//     days query branching, success path
//   - secrets_access_stats.go (GetSecretAccessStats): not-found (404), days param,
//     success path
//   - secrets_access_list.go  (ListAccessors): not-found (404), success path
//   - secrets_usage.go        (parseIntQuery zero/negative, UsageMostAccessed bad
//     project_id, UsageUnused bad project_id, success paths)
//   - secrets_audit_trail.go  (AuditTrail): not-found (404), success path with data;
//     toSecretAuditEntry: Diff branch, Success=false branch
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSecretHandlerForS13 returns a SecretHandler only (no DB needed by some tests).
func newSecretHandlerForS13(t *testing.T) *SecretHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h
}

// newSecretHandlerWithDB returns a handler whose core shares the same DB as
// the seeded rows so permission checks resolve correctly.
func newHandlerAndSeedS13(t *testing.T, name string) (*SecretHandler, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "s13-proj-" + name}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s13-env-" + name, ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	sec := &models.SecretNode{
		Name:          "s13-sec-" + name,
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		OwnerID:       1,
		Type:          "static",
	}
	require.NoError(t, db.Create(sec).Error)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, sec.ID
}

// ── secrets_risk.go: GetSecretRisk ───────────────────────────────────────────

// TestGetSecretRisk_NotFound_S13 verifies the 404 branch when the secret does
// not exist — exercises the "not found" error path in GetSecretRisk.
func TestGetSecretRisk_NotFound_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99991",
	))
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecretRisk_Success_S13 seeds a secret and verifies the happy-path
// response (200 with a risk object).
func TestGetSecretRisk_Success_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "risk-ok")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_access_history.go: AccessHistory ─────────────────────────────────

// TestAccessHistory_NotFound_S13 verifies the 404 branch for a missing secret.
func TestAccessHistory_NotFound_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99992",
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestAccessHistory_DaysCapped_S13 verifies that ?days=1000 is silently capped
// to 365 (not an error) — exercises the cap branch.
func TestAccessHistory_DaysCapped_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	// With a non-existent secret we still hit the capping logic before the core call.
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?days=1000", nil),
		"id", "99993",
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	// days > 365 is capped internally; error comes from core (not found), not validation.
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// TestAccessHistory_DaysQueryBranch_S13 verifies that a non-positive or non-numeric
// ?days param falls back to the default (30) and does not cause a bad request.
func TestAccessHistory_DaysQueryBranch_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?days=bad", nil),
		"id", "99994",
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	// invalid days ignored → default used → still hits core (not found), not 400.
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// TestAccessHistory_Success_S13 seeds a real secret and exercises the success
// path, including the nil-logs → empty-slice assignment and the response shape.
func TestAccessHistory_Success_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "ahist-ok")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?days=7", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── secrets_access_stats.go: GetSecretAccessStats ────────────────────────────

// TestGetSecretAccessStats_NotFound_S13 verifies the 404 branch.
func TestGetSecretAccessStats_NotFound_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99995",
	))
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetSecretAccessStats_WithDays_S13 exercises the `days` query branch and
// success path by seeding a real secret and calling with ?days=14.
func TestGetSecretAccessStats_WithDays_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "stats-days")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?days=14", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetSecretAccessStats_ZeroDays_S13 verifies that days=0 path is handled
// (let core default to 30) — exercises the zero-days branch.
func TestGetSecretAccessStats_ZeroDays_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "stats-zero")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?days=0", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	// days=0 → falls through to core default; expect 200.
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── secrets_access_list.go: ListAccessors ────────────────────────────────────

// TestListAccessors_NotFound_S13 verifies the 404 branch for a missing secret.
func TestListAccessors_NotFound_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99996",
	))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestListAccessors_Success_S13 seeds a real secret and exercises the happy path
// including the degraded/degraded_reasons fields in the response.
func TestListAccessors_Success_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "access-list-ok")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── secrets_usage.go: parseIntQuery + UsageMostAccessed + UsageUnused ────────

// TestParseIntQuery_ZeroFallsBack_S13 exercises the n<=0 branch: ?days=0
// should fall back to the default.
func TestParseIntQuery_ZeroFallsBack_S13(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?days=0", nil)
	result := parseIntQuery(r, "days", 30)
	assert.Equal(t, 30, result, "n<=0 should fall back to default")
}

// TestParseIntQuery_NegativeFallsBack_S13 exercises the n<=0 branch with a
// negative value: ?days=-5 should fall back to the default.
func TestParseIntQuery_NegativeFallsBack_S13(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?days=-5", nil)
	result := parseIntQuery(r, "days", 30)
	assert.Equal(t, 30, result, "negative n should fall back to default")
}

// TestUsageMostAccessed_BadProjectID_S13 exercises the bad project_id (400)
// branch in UsageMostAccessed.
func TestUsageMostAccessed_BadProjectID_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?project_id=notanumber", nil),
	)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUsageMostAccessed_Success_S13 exercises the success path in
// UsageMostAccessed (no project filter, small limit).
func TestUsageMostAccessed_Success_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?days=7&limit=5", nil),
	)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUsageUnused_BadProjectID_S13 exercises the bad project_id (400) branch
// in UsageUnused.
func TestUsageUnused_BadProjectID_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil),
	)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUsageUnused_Success_S13 exercises the success path in UsageUnused
// with no project filter.
func TestUsageUnused_Success_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?days=14", nil),
	)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUsageMostAccessed_BadEnvironmentID_S13 exercises the 400 branch when
// environment_id is malformed.
func TestUsageMostAccessed_BadEnvironmentID_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?environment_id=notanumber", nil),
	)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUsageUnused_BadEnvironmentID_S13 exercises the 400 branch when
// environment_id is malformed.
func TestUsageUnused_BadEnvironmentID_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(
		httptest.NewRequest(http.MethodGet, "/?environment_id=notanumber", nil),
	)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// usageEnvFixture seeds one project with two environments, each holding a
// distinctly-named secret with distinctly-identifiable usage data: env1's
// secret is read repeatedly (making it "most accessed") and env2's secret is
// never read (making it "unused"), so a leak in either direction — env2 data
// bleeding into an env1-scoped most-accessed query, or vice versa for
// unused — is independently observable.
func usageEnvFixture(t *testing.T) (h *SecretHandler, projectID, env1ID, env2ID uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "usage-scope-proj"}
	require.NoError(t, db.Create(proj).Error)
	env1 := &models.Environment{Name: "env1", ProjectID: proj.ID}
	require.NoError(t, db.Create(env1).Error)
	env2 := &models.Environment{Name: "env2", ProjectID: proj.ID}
	require.NoError(t, db.Create(env2).Error)

	sec1 := &models.SecretNode{
		Name: "env1-hot-secret", ProjectID: proj.ID, EnvironmentID: env1.ID,
		OwnerID: 1, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(sec1).Error)
	sec2 := &models.SecretNode{
		Name: "env2-cold-secret", ProjectID: proj.ID, EnvironmentID: env2.ID,
		OwnerID: 1, Type: "static", IsSecret: true,
	}
	require.NoError(t, db.Create(sec2).Error)

	// env1's secret is read (most-accessed in env1, and NOT unused in env1).
	require.NoError(t, db.Create(&models.SecretAccessLog{
		SecretNodeID: sec1.ID, AccessedBy: "u", AccessTime: time.Now(), Action: "read",
	}).Error)
	// env2's secret is never read — it is unused in env2, and absent from
	// env2's most-accessed report.

	hh, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return hh, proj.ID, env1.ID, env2.ID
}

// TestUsageMostAccessed_ScopedToEnvironment is the regression test for the
// scope-widening leak (handlers-secrets-access-history.json#0): the route
// authorizes at {project, environment} via ScopeFromQuery, but the handler
// used to never read/forward environment_id, so a caller scoped to a single
// environment received the whole project's aggregate. Confirms an
// environment_id-scoped request returns only that environment's secret.
func TestUsageMostAccessed_ScopedToEnvironment(t *testing.T) {
	h, projectID, env1ID, _ := usageEnvFixture(t)

	url := fmt.Sprintf("/?project_id=%d&environment_id=%d", projectID, env1ID)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			Secrets []struct {
				SecretName string `json:"secret_name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))

	names := make([]string, 0, len(body.Data.Secrets))
	for _, s := range body.Data.Secrets {
		names = append(names, s.SecretName)
	}
	assert.Contains(t, names, "env1-hot-secret")
	assert.NotContains(t, names, "env2-cold-secret", "environment-scoped most-accessed query must not leak the other environment's usage data")
}

// TestUsageUnused_ScopedToEnvironment is the UnusedSecrets-side counterpart
// of TestUsageMostAccessed_ScopedToEnvironment: an environment_id-scoped
// request must return only that environment's unused secret.
func TestUsageUnused_ScopedToEnvironment(t *testing.T) {
	h, projectID, _, env2ID := usageEnvFixture(t)

	url := fmt.Sprintf("/?project_id=%d&environment_id=%d", projectID, env2ID)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			Secrets []struct {
				SecretName string `json:"secret_name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))

	names := make([]string, 0, len(body.Data.Secrets))
	for _, s := range body.Data.Secrets {
		names = append(names, s.SecretName)
	}
	assert.Contains(t, names, "env2-cold-secret")
	assert.NotContains(t, names, "env1-hot-secret", "environment-scoped unused query must not leak the other environment's usage data")
}

// TestUsageMostAccessed_NoEnvironment_ReturnsProjectWideAggregate confirms
// backward compatibility: omitting environment_id still returns the whole
// project's aggregate (both environments' secrets), matching pre-fix
// behavior for callers that intentionally query at project scope.
func TestUsageMostAccessed_NoEnvironment_ReturnsProjectWideAggregate(t *testing.T) {
	h, projectID, _, _ := usageEnvFixture(t)

	url := fmt.Sprintf("/?project_id=%d", projectID)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, url, nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			Secrets []struct {
				SecretName string `json:"secret_name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))

	names := make([]string, 0, len(body.Data.Secrets))
	for _, s := range body.Data.Secrets {
		names = append(names, s.SecretName)
	}
	assert.Contains(t, names, "env1-hot-secret", "project-wide query (no environment_id) keeps today's aggregate behavior")
}

// ── secrets_audit_trail.go: AuditTrail + toSecretAuditEntry ──────────────────

// TestAuditTrail_NotFound_S13 verifies the 404 branch for a non-existent secret.
func TestAuditTrail_NotFound_S13(t *testing.T) {
	h := newSecretHandlerForS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99997",
	))
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestAuditTrail_Success_S13 seeds a real secret and exercises the success path
// (empty audit trail) — covers the entries-loop and response shape.
func TestAuditTrail_Success_S13(t *testing.T) {
	h, secID := newHandlerAndSeedS13(t, "audit-ok")
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?limit=10", nil),
		"id", fmt.Sprintf("%d", secID),
	))
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestToSecretAuditEntry_WithDiff_S13 exercises the Diff != "" branch in
// toSecretAuditEntry: the output diff field should equal the raw JSON.
func TestToSecretAuditEntry_WithDiff_S13(t *testing.T) {
	uid := uint(1)
	success := true
	e := &models.AuditEvent{
		ID:            42,
		EventType:     "secret.updated",
		EventTime:     time.Now(),
		UserID:        &uid,
		ActorType:     "user",
		Description:   "value changed",
		Success:       &success,
		Diff:          `{"changed":true}`,
		Impersonation: false,
	}
	entry := toSecretAuditEntry(e)
	assert.Equal(t, uint(42), entry.ID)
	assert.Equal(t, "secret.updated", entry.EventType)
	require.NotNil(t, entry.Diff, "Diff should be populated")
	assert.Contains(t, string(entry.Diff), "changed")
}

// TestToSecretAuditEntry_SuccessFalse_S13 exercises the `Success == nil || *e.Success`
// false branch: when Success is explicitly false the entry should be false.
func TestToSecretAuditEntry_SuccessFalse_S13(t *testing.T) {
	successFalse := false
	e := &models.AuditEvent{
		ID:        7,
		EventType: "secret.read",
		EventTime: time.Now(),
		ActorType: "user",
		Success:   &successFalse,
	}
	entry := toSecretAuditEntry(e)
	assert.False(t, entry.Success)
}

// TestToSecretAuditEntry_SuccessNil_S13 exercises the `Success == nil` branch:
// when Success is nil the entry should default to true.
func TestToSecretAuditEntry_SuccessNil_S13(t *testing.T) {
	e := &models.AuditEvent{
		ID:        8,
		EventType: "secret.created",
		EventTime: time.Now(),
		ActorType: "user",
		Success:   nil,
	}
	entry := toSecretAuditEntry(e)
	assert.True(t, entry.Success)
}
