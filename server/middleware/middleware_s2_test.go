package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// --- PrometheusMiddleware ---

// TestPrometheusMiddleware_MatchedRoute verifies that PrometheusMiddleware calls the
// handler and returns a 200 when the route is matched.
func TestPrometheusMiddleware_MatchedRoute(t *testing.T) {
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/api/v1/secrets/{id}"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	PrometheusMiddleware(handler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestPrometheusMiddleware_UnmatchedRoute verifies that PrometheusMiddleware handles
// requests without a matched route (empty pattern).
func TestPrometheusMiddleware_UnmatchedRoute(t *testing.T) {
	rctx := chi.NewRouteContext()
	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	PrometheusMiddleware(handler).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// --- ScopeFromProjectParam ---

// TestScopeFromProjectParam_Valid verifies the resolver extracts a project ID from
// a chi URL parameter.
func TestScopeFromProjectParam_Valid(t *testing.T) {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectId", "42")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/42", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	scope, err := ScopeFromProjectParam("projectId")(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.ProjectID != 42 {
		t.Errorf("ProjectID = %d, want 42", scope.ProjectID)
	}
}

// TestScopeFromProjectParam_Invalid returns errInvalidTarget for a non-numeric param.
func TestScopeFromProjectParam_Invalid(t *testing.T) {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("projectId", "notanumber")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/notanumber", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	_, err := ScopeFromProjectParam("projectId")(req, nil)
	if err == nil {
		t.Error("expected error for non-numeric param, got nil")
	}
}

// --- ScopeFromRoleAssignmentBody ---

// TestScopeFromRoleAssignmentBody_ValidJSON parses project_id/environment_id from
// the request body and returns the right scope.
func TestScopeFromRoleAssignmentBody_ValidJSON(t *testing.T) {
	body := `{"project_id":3,"environment_id":7}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	scope, err := ScopeFromRoleAssignmentBody(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.ProjectID != 3 || scope.EnvironmentID != 7 {
		t.Errorf("scope = %+v, want {ProjectID:3 EnvironmentID:7}", scope)
	}
}

// TestScopeFromRoleAssignmentBody_EmptyBody returns a global scope (both IDs = 0).
func TestScopeFromRoleAssignmentBody_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", http.NoBody)
	scope, err := ScopeFromRoleAssignmentBody(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.ProjectID != 0 || scope.EnvironmentID != 0 {
		t.Errorf("empty body scope = %+v, want global (0,0)", scope)
	}
}

// TestScopeFromRoleAssignmentBody_InvalidJSON returns an error for malformed JSON.
func TestScopeFromRoleAssignmentBody_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", strings.NewReader("{not-json"))
	_, err := ScopeFromRoleAssignmentBody(req, nil)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// --- stripControl ---

// TestStripControl_RemovesControlChars verifies that CR/LF and other control
// bytes are stripped from log strings.
func TestStripControl_RemovesControlChars(t *testing.T) {
	input := "hello\rworld\nfoo\x00bar"
	got := stripControl(input)
	for _, bad := range []string{"\r", "\n", "\x00"} {
		for _, r := range got {
			if string(r) == bad {
				t.Errorf("stripControl did not remove control char %q from %q; got %q", bad, input, got)
			}
		}
	}
	// Safe characters must be preserved.
	for _, safe := range []string{"hello", "world", "foo", "bar"} {
		found := false
		for i := 0; i+len(safe) <= len(got); i++ {
			if got[i:i+len(safe)] == safe {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stripControl removed safe content %q from result %q", safe, got)
		}
	}
}

// TestStripControl_SafeString passes an already-safe string unchanged.
func TestStripControl_SafeString(t *testing.T) {
	input := "safe-log-entry-123"
	got := stripControl(input)
	if got != input {
		t.Errorf("stripControl(%q) = %q, want %q", input, got, input)
	}
}

// --- sweepLocked (rate limiter) ---

// TestSweepLocked_ViaHighRequestCount exercises the sweepLocked path by
// pre-seeding the request counter to just before the sweep boundary, then
// calling allow() to cross it, invoking sweepLocked.
func TestSweepLocked_ViaHighRequestCount(t *testing.T) {
	rl := &principalRateLimiter{
		rps:      1000,
		burst:    10000,
		limiters: make(map[string]*principalBucket),
	}
	rl.requests = principalLimiterSweepEvery - 1
	_ = rl.allow("test-key") // triggers sweepLocked on this call
}

// --- Authentication public wrapper ---

// TestAuthentication_PublicWrapper verifies that the Authentication function
// (which wraps authenticationWithValidator) rejects requests without a token,
// confirming the wrapper is wired correctly.
func TestAuthentication_PublicWrapper(t *testing.T) {
	// Build a real in-memory core for the wrapper (needed to avoid nil-deref
	// in the validator path; any unauthenticated call is rejected before it
	// reaches the core service).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	rec := httptest.NewRecorder()

	// Authentication(nil) should fail closed (no core service = reject everything).
	mw := Authentication(nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Authentication(nil): expected 401, got %d", rec.Code)
	}
}

// --- RequireScopedPermission ---

// TestRequireScopedPermission_NoUserContext returns 401 when there is no user context.
func TestRequireScopedPermission_NoUserContext(t *testing.T) {
	mw := RequireScopedPermission("secrets.read", ScopeGlobal)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no user context: expected 401, got %d", rec.Code)
	}
}

// TestRequireScopedPermission_NoCoreService returns 403 when the core service
// is absent from context.
func TestRequireScopedPermission_NoCoreService(t *testing.T) {
	mw := RequireScopedPermission("secrets.read", ScopeGlobal)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	uc := &UserContext{UserID: 1, Username: "admin"}
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, uc))
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no core service: expected 403, got %d", rec.Code)
	}
}

// TestRequirePermission_NoUserContext returns 401 when there is no user context.
func TestRequirePermission_NoUserContext(t *testing.T) {
	mw := RequirePermission("secrets.read")
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no user context: expected 401, got %d", rec.Code)
	}
}

// --- GetCoreServiceFromContext with a value ---

// TestGetCoreServiceFromContext_WithNilValue confirms nil is returned when the
// key exists with a non-*core.KeyorixCore value.
func TestGetCoreServiceFromContext_WithNilValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), coreServiceContextKey, "wrong type")
	got := GetCoreServiceFromContext(ctx)
	if got != nil {
		t.Errorf("expected nil for wrong type, got %v", got)
	}
}

// --- ScopeFromRefQuery ---

// TestScopeFromRefQuery_MissingRef returns errTargetNotFound for an empty ref.
func TestScopeFromRefQuery_MissingRef(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?ref=", nil)
	_, err := ScopeFromRefQuery(req, nil)
	if err == nil {
		t.Error("expected error for missing ref, got nil")
	}
}

// _ ensures the io package import is used.
var _ io.Reader = strings.NewReader("")
