// scope_resolver_read_fault_test.go — STORAGE-ERR-CLASS-3 item 1.
//
// Every scope resolver reads its target (environment, secret, deleted secret, share,
// rotation policy, dynamic-secret config) BEFORE the handler runs, and the per-secret
// gate reads the secret itself. Each folded ANY read error into errTargetNotFound, so a
// storage fault answered a global holder 404 "Resource not found" (the target may well
// exist and the operation was never applied) and everyone else 403. #3877 fixed the
// lease resolver; this covers the rest with the same errTargetReadFault branch:
//
//   - non-transient fault: a global holder gets 503 storage_unavailable + Retry-After,
//     a caller without global standing keeps the exact 403 an absent target gets;
//   - transient fault (connection refused): every caller gets the same 503
//     "authorization temporarily unavailable" (INV-MW-authorize-lookup-error-is-503);
//   - a real missing target is unchanged: 404 for a global holder, 403 otherwise.
//
// The fault is injected with internal/faultstorage on the resolver's own target read,
// over a real LocalStorage -> core path.
package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// errScanFault is a non-transient read failure whose text names a column: it must
// neither read as "not found" nor reach the client.
var errScanFault = errors.New(`sql: Scan error on column index 3, name "project_id": converting NULL to uint is unsupported`)

type srfWorld struct {
	fs                                        *faultstorage.FaultyStorage
	cs                                        *core.KeyorixCore
	envID, secretID, shareID, policyID, cfgID uint
}

func newSRFWorld(t *testing.T) *srfWorld {
	t.Helper()
	db := newScopedTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, db.Create(&models.User{ID: a503UserNobody, Username: "nobody", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	env := &models.Environment{ProjectID: 1, Name: "dev"}
	require.NoError(t, db.Create(env).Error)
	seedAdmin(t, db, a503UserAdmin)
	require.NoError(t, db.Create(&models.Permission{Name: "secrets.read"}).Error)

	secret := &models.SecretNode{ProjectID: 1, EnvironmentID: env.ID, Name: "s"}
	require.NoError(t, db.Create(secret).Error)
	share := &models.ShareRecord{SecretID: secret.ID, OwnerID: a503UserAdmin, RecipientID: a503UserNobody, Permission: "read"}
	require.NoError(t, db.Create(share).Error)
	pid, eid := uint(1), env.ID
	policy := &models.RotationPolicy{Name: "p", ProjectID: &pid, EnvironmentID: &eid, IntervalDays: 30, CreatedBy: "admin"}
	require.NoError(t, db.Create(policy).Error)
	cfg := &models.DynamicSecretConfig{Name: "c", ProjectID: 1, EnvironmentID: env.ID, BackendType: "postgres"}
	require.NoError(t, db.Create(cfg).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return &srfWorld{fs: fs, cs: core.NewKeyorixCore(fs), envID: env.ID, secretID: secret.ID, shareID: share.ID, policyID: policy.ID, cfgID: cfg.ID}
}

// srfGate is one gate whose scope comes from reading a target, and the storage method
// that read goes through.
type srfGate struct {
	name   string
	mw     func(next http.Handler) http.Handler
	method string
	target func(w *srfWorld) uint
}

func srfGates() []srfGate {
	const p = "secrets.read"
	return []srfGate{
		{"ScopeFromEnvParam", RequireScopedPermission(p, ScopeFromEnvParam("id")), "GetEnvironment", func(w *srfWorld) uint { return w.envID }},
		{"ScopeFromSecretParam", RequireScopedPermission(p, ScopeFromSecretParam("id")), "GetSecret", func(w *srfWorld) uint { return w.secretID }},
		{"ScopeFromDeletedSecretParam", RequireScopedPermission(p, ScopeFromDeletedSecretParam("id")), "GetSecretIncludingDeleted", func(w *srfWorld) uint { return w.secretID }},
		{"ScopeFromShareParam(share read)", RequireScopedPermission(p, ScopeFromShareParam("id")), "GetShareRecord", func(w *srfWorld) uint { return w.shareID }},
		{"ScopeFromShareParam(secret read)", RequireScopedPermission(p, ScopeFromShareParam("id")), "GetSecret", func(w *srfWorld) uint { return w.shareID }},
		{"ScopeFromRotationPolicyParam", RequireScopedPermission(p, ScopeFromRotationPolicyParam("id")), "GetRotationPolicy", func(w *srfWorld) uint { return w.policyID }},
		{"ScopeFromDynamicSecretConfigParam", RequireScopedPermission(p, ScopeFromDynamicSecretConfigParam("id")), "GetDynamicSecretConfig", func(w *srfWorld) uint { return w.cfgID }},
		{"RequireScopedSecretPermission", RequireScopedSecretPermission(p, "id"), "GetSecret", func(w *srfWorld) uint { return w.secretID }},
	}
}

func srfServe(t *testing.T, w *srfWorld, g srfGate, user uint, id uint) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	rec := httptest.NewRecorder()
	req := makeRequest(t, http.MethodGet, "/x", map[string]string{"id": strconv.FormatUint(uint64(id), 10)},
		&UserContext{UserID: user, ActorType: core.ActorTypeUser}, w.cs)
	g.mw(okNext(&called)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		assert.False(t, called, "the handler behind the gate ran on a %d", rec.Code)
	}
	return rec
}

func (w *srfWorld) armOnce(t *testing.T, method string, err error) {
	t.Helper()
	w.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: err})
}

func (w *srfWorld) disarm(t *testing.T) {
	t.Helper()
	require.True(t, w.fs.Fired(), "the resolver's target read must be reached")
	w.fs.Arm(nil)
}

const srfAbsentID = 999999

func TestScopeResolverReadFault_GlobalHolderGets503(t *testing.T) {
	for _, g := range srfGates() {
		t.Run(g.name, func(t *testing.T) {
			w := newSRFWorld(t)
			w.armOnce(t, g.method, errScanFault)
			rec := srfServe(t, w, g, a503UserAdmin, g.target(w))
			w.disarm(t)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "a read fault is not \"not found\": %s", rec.Body.String())
			assert.NotEmpty(t, rec.Header().Get("Retry-After"))
			assert.Contains(t, rec.Body.String(), `"storage_unavailable"`)
			assert.Contains(t, rec.Body.String(), core.StorageReadUnavailableMessage)
			assert.NotContains(t, rec.Body.String(), "project_id", "the driver cause must not reach the client")

			// Nothing cached: the same request reaches the handler once the fault clears.
			assert.Equal(t, http.StatusOK, srfServe(t, w, g, a503UserAdmin, g.target(w)).Code)
		})
	}
}

func TestScopeResolverReadFault_NonHolderKeepsAbsentTarget403(t *testing.T) {
	for _, g := range srfGates() {
		t.Run(g.name, func(t *testing.T) {
			w := newSRFWorld(t)
			w.armOnce(t, g.method, errScanFault)
			fault := srfServe(t, w, g, a503UserNobody, g.target(w))
			w.disarm(t)
			absent := srfServe(t, w, g, a503UserNobody, srfAbsentID)
			assert.Equal(t, http.StatusForbidden, absent.Code, absent.Body.String())
			assert.Equal(t, absent.Code, fault.Code, "a fault and an absent target are one answer for a non-holder")
			assert.Equal(t, absent.Body.String(), fault.Body.String(), "a fault and an absent target are one answer for a non-holder")
			assert.Empty(t, fault.Header().Get("Retry-After"))
		})
	}
}

func TestScopeResolverReadFault_TransientIsOne503ForEveryone(t *testing.T) {
	for _, g := range srfGates() {
		t.Run(g.name, func(t *testing.T) {
			w := newSRFWorld(t)
			w.armOnce(t, g.method, errDBDown)
			holder := srfServe(t, w, g, a503UserAdmin, g.target(w))
			w.disarm(t)
			w.armOnce(t, g.method, errDBDown)
			nonHolder := srfServe(t, w, g, a503UserNobody, g.target(w))
			w.disarm(t)
			requireUnavailable(t, holder)
			requireUnavailable(t, nonHolder)
			assert.Equal(t, holder.Body.String(), nonHolder.Body.String(), "a transient fault is one answer for holder and non-holder")
		})
	}
}

func TestScopeResolverReadFault_RealNotFoundUnchanged(t *testing.T) {
	for _, g := range srfGates() {
		if g.name == "ScopeFromShareParam(secret read)" {
			continue // same request as the share-read row
		}
		t.Run(g.name, func(t *testing.T) {
			w := newSRFWorld(t)
			holder := srfServe(t, w, g, a503UserAdmin, srfAbsentID)
			assert.Equal(t, http.StatusNotFound, holder.Code, holder.Body.String())
			assert.Contains(t, holder.Body.String(), "Resource not found")
			assert.Empty(t, holder.Header().Get("Retry-After"))
			nonHolder := srfServe(t, w, g, a503UserNobody, srfAbsentID)
			assert.Equal(t, http.StatusForbidden, nonHolder.Code, nonHolder.Body.String())
			assert.Contains(t, nonHolder.Body.String(), defaultDenyMessage)
		})
	}
}
