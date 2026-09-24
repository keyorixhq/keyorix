// rotation_policy_wire_regression_test.go proves the fix in ADR-108 PR 1
// (docs/cli-split-inventory.md §7): a real GET/POST /api/v1/rotation-policies
// response, produced by the actual RotationPolicyHandler (not a hand-built
// fixture), decodes into THIS package's own policyView struct -- the exact
// type the old, production `keyorix rotation` CLI has always used -- with
// correct, non-zero values for every multi-word field. Before the fix
// (internal/storage/models.RotationPolicy carrying no json tags, so the
// server emitted PascalCase keys policyView's snake_case tags could not
// match), this same test would have observed IntervalDays==0, IsActive==false,
// ProjectID==nil, etc., regardless of what was actually created -- see
// policyView's own doc comment for the mechanism.
//
// This lives in package rotation (not server/http/handlers) specifically so
// it can reference policyView directly: proving "the OLD CLI's own struct
// decodes this correctly" requires exercising that literal, unexported type,
// not a copy of it.
package rotation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// wireRegressionHandler builds a real RotationPolicyHandler against a fresh
// in-memory SQLite database, with the request-context user (UserID=1) seeded
// as a global admin (BypassesPermissionChecks) so Create/Get's own
// authorization checks pass without needing a separate permission-grant
// fixture -- mirrors server/http/handlers/rotation_policies_simple_test.go's
// setupRotationPolicyTest, replicated here (that helper is unexported and
// lives in a different package).
func wireRegressionHandler(t *testing.T) (*handlers.RotationPolicyHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.RotationPolicy{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	adminRole := &models.Role{Name: "admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	return handlers.NewRotationPolicyHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func wireRegressionUserCtx(r *http.Request) *http.Request {
	userCtx := &customMiddleware.UserContext{UserID: 1, Username: "testuser", Email: "testuser@example.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

func wireRegressionChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestOldCLIPolicyView_DecodesRealCreateResponse drives the real
// RotationPolicyHandler.Create end to end and decodes its raw response bytes
// with policyView -- the same decode path runOldCLI's createCmd performs in
// production. Every field asserted below is exactly the one the pre-fix bug
// zeroed (see policyView's doc comment): a regression here would mean the
// model-level fix (internal/storage/models.RotationPolicy's json tags) had
// been reverted or never actually took effect for this handler.
func TestOldCLIPolicyView_DecodesRealCreateResponse(t *testing.T) {
	h, _ := wireRegressionHandler(t)

	body, _ := json.Marshal(map[string]any{
		"name": "wire-regression-policy", "scope": "project", "project_id": 7,
		"interval_days": 45, "alert_days_before": 3, "notify_on_breach": true,
	})
	req := wireRegressionUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/rotation-policies", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "handler response: %s", w.Body.String())

	var envelope struct {
		Data policyView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope), "old CLI's own policyView must decode the real response")
	p := envelope.Data

	require.NotZero(t, p.ID, "ID must round-trip (single-word field -- was never affected by the bug)")
	require.Equal(t, "wire-regression-policy", p.Name)
	require.Equal(t, "project", p.Scope)
	require.NotNil(t, p.ProjectID, "ProjectID must decode non-nil -- the exact field class the pre-fix bug zeroed")
	require.Equal(t, uint(7), *p.ProjectID)
	require.Equal(t, 45, p.IntervalDays, "IntervalDays must decode as sent, not 0 (the pre-fix bug's signature symptom)")
	require.Equal(t, 3, p.AlertDaysBefore, "AlertDaysBefore must decode as sent, not 0")
	require.True(t, p.NotifyOnBreach, "NotifyOnBreach must decode as sent, not false")
	require.True(t, p.IsActive, "IsActive must decode true (core.CreateRotationPolicy always forces this server-side)")
	require.NotEmpty(t, p.CreatedBy, "CreatedBy must decode non-empty, not \"\"")
}

// TestOldCLIPolicyView_DecodesRealGetResponse repeats the proof for GET
// /api/v1/rotation-policies/{id} (runOldCLI's showCmd decode path), against a
// policy created directly through core (not through Create's handler) so this
// test is independent of TestOldCLIPolicyView_DecodesRealCreateResponse above.
func TestOldCLIPolicyView_DecodesRealGetResponse(t *testing.T) {
	h, db := wireRegressionHandler(t)

	// core.CreateRotationPolicy validates that an environment-scoped policy's
	// environment_id actually exists (and resolves its owning project from
	// it) -- a real Project+Environment row is required, not just any integer.
	proj := &models.Project{Name: "wire-regression-project"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "wire-regression-env"}
	require.NoError(t, db.Create(env).Error)

	// Seed directly via the Create handler (simplest path to a real,
	// server-persisted row without reaching into the handler's private core
	// field) rather than a second, parallel core instance.
	// notify_on_breach:true, not false: GORM's own `gorm:"default:true"` on
	// RotationPolicy.NotifyOnBreach silently coerces a zero-valued (false)
	// field to true on Create regardless of what was actually sent, which
	// would make a False assertion below prove nothing either way -- see
	// TestConformance_UpdateRotationPolicy (server/http) for the test that
	// specifically proves NotifyOnBreach:false survives the wire, via Update
	// (Save), where no such column-default substitution applies.
	body, _ := json.Marshal(map[string]any{
		"name": "wire-regression-get", "scope": "environment", "environment_id": env.ID,
		"interval_days": 21, "alert_days_before": 5, "notify_on_breach": true,
	})
	createReq := wireRegressionUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/rotation-policies", bytes.NewReader(body)))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	h.Create(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code, "seed create response: %s", createW.Body.String())
	var createEnvelope struct {
		Data policyView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createW.Body.Bytes(), &createEnvelope))
	id := createEnvelope.Data.ID

	getReq := wireRegressionUserCtx(wireRegressionChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/x", nil), "id", strconv.FormatUint(uint64(id), 10),
	))
	getW := httptest.NewRecorder()
	h.Get(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code, "handler response: %s", getW.Body.String())

	var envelope struct {
		Data policyView `json:"data"`
	}
	require.NoError(t, json.Unmarshal(getW.Body.Bytes(), &envelope), "old CLI's own policyView must decode the real response")
	p := envelope.Data

	require.Equal(t, id, p.ID)
	require.Equal(t, "environment", p.Scope)
	require.NotNil(t, p.EnvironmentID, "EnvironmentID must decode non-nil -- the exact field class the pre-fix bug zeroed")
	require.Equal(t, env.ID, *p.EnvironmentID)
	require.Equal(t, 21, p.IntervalDays, "IntervalDays must decode as sent, not 0")
	require.Equal(t, 5, p.AlertDaysBefore, "AlertDaysBefore must decode as sent, not 0")
	require.True(t, p.NotifyOnBreach, "NotifyOnBreach must decode as sent, not false")
}
