// authorize_lookup_503_test.go — INV-MW-authorize-lookup-error-is-503 (AUTHZ-OUTAGE-503-1,
// #3458, PROD-OPS-1 finding 6).
//
// While PostgreSQL is down or the request deadline passes, the PERMISSION lookup
// behind a gate fails. That says nothing about the caller, so the answer is
// 503 + Retry-After (clients retry it) and never 403 (clients do not). The request
// is refused either way: the handler behind the gate is never invoked on a fault,
// a plain denial stays the same 403, and nothing is cached, so the same request
// succeeds once the fault clears.
//
// The fault is injected with internal/faultstorage on the exact permission-resolving
// read of each principal kind, over a real LocalStorage -> core path. The injected
// error is a structural connection error (a *net.OpError wrapping ECONNREFUSED), the
// shape a database driver returns, not an error whose text is matched.
package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// errDBDown is what a driver returns when PostgreSQL is unreachable.
var errDBDown = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

const (
	a503UserAdmin  uint = 1 // holds everything (admin bypass)
	a503UserNobody uint = 2 // holds nothing
)

type a503World struct {
	fs        *faultstorage.FaultyStorage
	cs        *core.KeyorixCore
	machineID uint
	secretID  uint
}

func newA503World(t *testing.T) *a503World {
	t.Helper()
	db := newScopedTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, db.Create(&models.User{ID: a503UserNobody, Username: "nobody", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	seedAdmin(t, db, a503UserAdmin)

	perm := models.Permission{Name: "secrets.write"}
	require.NoError(t, db.Create(&perm).Error)
	machine := &models.MachineIdentity{ProjectID: 1, Name: "bot", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)
	role := &models.Role{Name: "bot_writer"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: machine.ID, RoleID: role.ID}).Error)

	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "s"}
	require.NoError(t, db.Create(secret).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return &a503World{fs: fs, cs: core.NewKeyorixCore(fs), machineID: machine.ID, secretID: secret.ID}
}

// arm fails the next call of method with err.
func (w *a503World) arm(method string, err error) {
	w.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: err})
}

// principal is one principal kind and the storage method its permission lookup reads.
type a503Principal struct {
	name   string
	ctx    func(w *a503World) *UserContext
	lookup string
}

func a503Principals() []a503Principal {
	return []a503Principal{
		{"user", func(*a503World) *UserContext {
			return &UserContext{UserID: a503UserAdmin, ActorType: core.ActorTypeUser}
		}, "ResolveUserPermissionAt"},
		{"machine", func(w *a503World) *UserContext {
			id := w.machineID
			return &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: &id}
		}, "ResolveMachinePermissionAt"},
	}
}

// failIfReached is the handler behind every gate: reaching it on a fault is a bug.
func failIfReached(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the handler behind the gate was invoked")
		w.WriteHeader(http.StatusOK)
	})
}

func okNext(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func projectScope(*http.Request, *core.KeyorixCore) (core.Scope, error) {
	return core.Scope{ProjectID: 1}, nil
}

type a503Gate struct {
	name string
	mw   func(next http.Handler) http.Handler
}

func a503Gates() []a503Gate {
	return []a503Gate{
		{"RequirePermission(global)", RequirePermission("secrets.write")},
		{"RequireScopedPermission(project)", RequireScopedPermission("secrets.write", projectScope)},
		{"RequirePermissionInAnyScope", RequirePermissionInAnyScope("secrets.write")},
	}
}

func requireUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "a lookup outage is 503, not 403")
	assert.NotEmpty(t, rec.Header().Get("Retry-After"), "503 must tell the client when to retry")
	assert.Contains(t, rec.Body.String(), "authorization temporarily unavailable, please retry")
	assert.NotContains(t, rec.Body.String(), "refused", "no storage error text reaches the client")
}

// TestAuthorizeLookupFault_Is503ThenRecovers: for each principal kind and each gate,
// a fault on the permission lookup answers 503 + Retry-After and never runs the
// handler; the same request succeeds once the fault clears (nothing was cached).
func TestAuthorizeLookupFault_Is503ThenRecovers(t *testing.T) {
	for _, p := range a503Principals() {
		for _, g := range a503Gates() {
			t.Run(p.name+"/"+g.name, func(t *testing.T) {
				w := newA503World(t)
				uc := p.ctx(w)

				w.arm(p.lookup, errDBDown)
				rec := httptest.NewRecorder()
				g.mw(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", nil, uc, w.cs))
				require.True(t, w.fs.Fired(), "precondition: the permission lookup must hit the injected fault")
				requireUnavailable(t, rec)

				var called bool
				rec = httptest.NewRecorder()
				g.mw(okNext(&called)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", nil, uc, w.cs))
				assert.Equal(t, http.StatusOK, rec.Code, "after the fault clears the same request succeeds")
				assert.True(t, called)
			})
		}
	}
}

// TestAuthorizeLookupFault_DeadlineIs503: the request context hitting its deadline
// during the lookup is the other transient shape.
func TestAuthorizeLookupFault_DeadlineIs503(t *testing.T) {
	for _, p := range a503Principals() {
		t.Run(p.name, func(t *testing.T) {
			w := newA503World(t)
			w.arm(p.lookup, context.DeadlineExceeded)
			rec := httptest.NewRecorder()
			RequirePermission("secrets.write")(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", nil, p.ctx(w), w.cs))
			requireUnavailable(t, rec)
		})
	}
}

// TestAuthorizeLookupFault_SecretRouteIs503: the per-secret gate (RequireScopedSecretPermission)
// with a fault on the permission lookup, and with a fault on the secret fetch itself.
func TestAuthorizeLookupFault_SecretRouteIs503(t *testing.T) {
	for _, p := range a503Principals() {
		for _, lookup := range []string{p.lookup, "GetSecret"} {
			t.Run(p.name+"/"+lookup, func(t *testing.T) {
				w := newA503World(t)
				uc := p.ctx(w)
				params := map[string]string{"id": strconv.FormatUint(uint64(w.secretID), 10)}
				gate := RequireScopedSecretPermission("secrets.write", "id", core.SecretActionUpdate)

				w.arm(lookup, errDBDown)
				rec := httptest.NewRecorder()
				gate(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", params, uc, w.cs))
				require.True(t, w.fs.Fired(), "precondition: %s must hit the injected fault", lookup)
				requireUnavailable(t, rec)

				var called bool
				rec = httptest.NewRecorder()
				gate(okNext(&called)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", params, uc, w.cs))
				assert.Equal(t, http.StatusOK, rec.Code, "after the fault clears the same request succeeds")
				assert.True(t, called)
			})
		}
	}
}

// TestAuthorizeLookupFault_NotFoundProbeIs503: a missing target makes the gate probe
// the caller's global permission; if THAT lookup hits the outage the answer is 503,
// not the 403 that passes for "you hold nothing".
func TestAuthorizeLookupFault_NotFoundProbeIs503(t *testing.T) {
	w := newA503World(t)
	missing := func(*http.Request, *core.KeyorixCore) (core.Scope, error) { return core.Scope{}, errTargetNotFound }
	uc := &UserContext{UserID: a503UserAdmin, ActorType: core.ActorTypeUser}

	w.arm("ResolveUserPermissionAt", errDBDown)
	rec := httptest.NewRecorder()
	RequireScopedPermission("secrets.write", missing)(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodGet, "/x", nil, uc, w.cs))
	require.True(t, w.fs.Fired())
	requireUnavailable(t, rec)

	rec = httptest.NewRecorder()
	RequireScopedPermission("secrets.write", missing)(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodGet, "/x", nil, uc, w.cs))
	assert.Equal(t, http.StatusNotFound, rec.Code, "after the fault clears the global holder gets its 404 again")
}

// TestAuthorizeLookupFault_PlainDenialStaysForbidden: a caller who holds nothing is
// the same 403 with the same body as before, handler not invoked, no Retry-After.
func TestAuthorizeLookupFault_PlainDenialStaysForbidden(t *testing.T) {
	w := newA503World(t)
	uc := &UserContext{UserID: a503UserNobody, ActorType: core.ActorTypeUser}
	for _, g := range a503Gates() {
		t.Run(g.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			g.mw(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", nil, uc, w.cs))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Empty(t, rec.Header().Get("Retry-After"))
			assert.Contains(t, rec.Body.String(), defaultDenyMessage)
		})
	}
}

// TestAuthorizeLookupFault_NonTransientErrorStaysForbidden: a lookup error that is not
// an outage (a programming error, a verdict-shaped error) stays a fail-closed 403.
func TestAuthorizeLookupFault_NonTransientErrorStaysForbidden(t *testing.T) {
	for _, p := range a503Principals() {
		t.Run(p.name, func(t *testing.T) {
			w := newA503World(t)
			w.arm(p.lookup, errors.New("role resolution returned no result"))
			rec := httptest.NewRecorder()
			RequirePermission("secrets.write")(failIfReached(t)).ServeHTTP(rec, makeRequest(t, http.MethodPut, "/x", nil, p.ctx(w), w.cs))
			require.True(t, w.fs.Fired())
			assert.Equal(t, http.StatusForbidden, rec.Code, "an error that is not a storage outage must stay a denial")
			assert.Empty(t, rec.Header().Get("Retry-After"))
		})
	}
}

// TestAuthorizeLookupFault_RestrictedPATStays403WithoutStorage: a PAT whose
// restriction disallows the permission is a plain 403 decided before any storage
// access, so an armed fault never fires and the answer is not 503.
func TestAuthorizeLookupFault_RestrictedPATStays403WithoutStorage(t *testing.T) {
	w := newA503World(t)
	w.arm("ResolveUserPermissionAt", errDBDown)
	uc := &UserContext{UserID: a503UserAdmin, ActorType: core.ActorTypeUser}
	req := makeRequest(t, http.MethodPut, "/x", nil, uc, w.cs)
	req = req.WithContext(core.WithPATRestriction(req.Context(), &core.PATRestriction{Permissions: []string{"secrets.read"}}))

	rec := httptest.NewRecorder()
	RequirePermission("secrets.write")(failIfReached(t)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get("Retry-After"))
	assert.False(t, w.fs.Fired(), "the restriction denies before any storage access")
}

// TestAuthorizeLookupFault_NotCountedAsForbiddenDenial: a value read's denial note
// records the outage as a failed read (internal_error), never as a "forbidden"
// denial; the request is still refused.
func TestAuthorizeLookupFault_NotCountedAsForbiddenDenial(t *testing.T) {
	w := newA503World(t)
	uc := &UserContext{UserID: a503UserAdmin, ActorType: core.ActorTypeUser}

	req := makeRequest(t, http.MethodGet, "/x", nil, uc, w.cs)
	ctx, note := core.WithSecretReadDenialNote(req.Context(), core.SecretReadPathRESTGet)
	req = req.WithContext(ctx)
	w.arm("ResolveUserPermissionAt", errDBDown)
	rec := httptest.NewRecorder()
	RequirePermission("secrets.read")(failIfReached(t)).ServeHTTP(rec, req)
	requireUnavailable(t, rec)
	assert.Equal(t, core.SecretReadDeniedInternalError, note.Reason())

	// control: a plain denial is still "forbidden".
	req = makeRequest(t, http.MethodGet, "/x", nil, &UserContext{UserID: a503UserNobody, ActorType: core.ActorTypeUser}, w.cs)
	ctx, note = core.WithSecretReadDenialNote(req.Context(), core.SecretReadPathRESTGet)
	rec = httptest.NewRecorder()
	RequirePermission("secrets.read")(failIfReached(t)).ServeHTTP(rec, req.WithContext(ctx))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, core.SecretReadDeniedForbidden, note.Reason())
}
