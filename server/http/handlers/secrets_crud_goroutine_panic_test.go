// secrets_crud_goroutine_panic_test.go — regression coverage for backlog
// #481: an adversarial regression audit of the #243 goSafe fix found that
// only auth.go/mfa.go/webauthn.go (goSafe's original 4 covered files) were
// wrapped, while every detached audit-logging goroutine in the secrets CRUD
// path — the highest-traffic subsystem — remained a bare `go
// h.coreService.LogSecret...(...)` with no panic recovery. A panic there
// (e.g. a future nil-deref inside the audit/SIEM-forwarding pipeline) runs on
// a goroutine the HTTP server's per-request recovery middleware never sees,
// and crashes the entire process for every connected tenant.
//
// These tests force a panic deep inside the audit write path (via a
// core.AuditForwarder whose Forward implementation panics — the same
// injectable seam SetAuditForwarder wires a real SIEM through) and prove
// each of CreateSecret/GetSecret/UpdateSecret/DeleteSecret still (a) returns
// its normal successful HTTP response and (b) does not crash the test
// process — the goSafe wrapper added at each call site recovers the panic
// instead.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// panicAuditForwarder panics inside Forward to simulate a bug surfacing on
// the audit-emit path that every LogSecret* call runs through (writeAudit*
// -> emitAudit -> auditForwarder.Forward). done is closed just before the
// panic so a test can synchronize with the detached goroutine having reached
// (and survived) it.
type panicAuditForwarder struct {
	done chan struct{}
}

func (p *panicAuditForwarder) Forward(_ *models.AuditEvent) {
	defer close(p.done)
	panic("simulated panic in audit forwarding")
}

func newPanicTestHandler(t *testing.T) (*SecretHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// A pooled sqlite ":memory:" connection hands out a fresh, empty database
	// per connection unless pinned to a single connection — pin it so every
	// query in this test sees the migrated schema.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{}, &models.Group{}, &models.GroupRole{},
		&models.UserGroup{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessLog{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.SecretAccessSchedule{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "admin"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)
	return handler, db
}

func userReq(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	userCtx := &middleware.UserContext{UserID: 1, Username: "alice", ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
}

func withIDParam(r *http.Request, id uint) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", strconv.FormatUint(uint64(id), 10))
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// TestCreateSecret_PanicInDetachedAuditGoroutineDoesNotCrash covers the #481
// call site at secrets_crud.go's CreateSecret (audit: secret.created).
func TestCreateSecret_PanicInDetachedAuditGoroutineDoesNotCrash(t *testing.T) {
	handler, _ := newPanicTestHandler(t)
	done := make(chan struct{})
	handler.coreService.SetAuditForwarder(&panicAuditForwarder{done: done})

	body, _ := json.Marshal(map[string]interface{}{
		"name": "S1", "value": "v", "project_id": uint(1),
		"environment_id": uint(10), "type": "static",
	})
	r := userReq(http.MethodPost, "/api/v1/secrets", body)
	rr := httptest.NewRecorder()
	handler.CreateSecret(rr, r)
	assert.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())

	select {
	case <-done:
		// The detached audit goroutine panicked and goSafe recovered it — the
		// process (and this test binary) is still alive to reach here.
	case <-time.After(2 * time.Second):
		t.Fatal("detached audit goroutine never ran")
	}
}

// TestGetSecret_PanicInDetachedAuditGoroutineDoesNotCrash covers the #481
// call site at secrets_crud.go's GetSecret (audit: secret.read) — the
// highest-traffic path of the CRUD subsystem.
func TestGetSecret_PanicInDetachedAuditGoroutineDoesNotCrash(t *testing.T) {
	handler, _ := newPanicTestHandler(t)
	created, err := handler.coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "target", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	done := make(chan struct{})
	handler.coreService.SetAuditForwarder(&panicAuditForwarder{done: done})

	// AUDIT-001 (commit 25fd0861): secret.read is now emitted only when the value
	// payload is returned (?include_value=true). Without it the audit goroutine is
	// never launched and the test would time out waiting for done.
	url := "/api/v1/secrets/" + strconv.FormatUint(uint64(created.ID), 10) + "?include_value=true"
	r := withIDParam(userReq(http.MethodGet, url, nil), created.ID)
	rr := httptest.NewRecorder()
	handler.GetSecret(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("detached audit goroutine never ran")
	}
}

// TestUpdateSecret_PanicInDetachedAuditGoroutineDoesNotCrash covers the #481
// call site at secrets_crud.go's UpdateSecret (audit: secret.updated).
func TestUpdateSecret_PanicInDetachedAuditGoroutineDoesNotCrash(t *testing.T) {
	handler, _ := newPanicTestHandler(t)
	created, err := handler.coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "target", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	done := make(chan struct{})
	handler.coreService.SetAuditForwarder(&panicAuditForwarder{done: done})

	body, _ := json.Marshal(map[string]interface{}{"max_reads": 3})
	r := withIDParam(userReq(http.MethodPut, "/api/v1/secrets/"+strconv.FormatUint(uint64(created.ID), 10), body), created.ID)
	rr := httptest.NewRecorder()
	handler.UpdateSecret(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("detached audit goroutine never ran")
	}
}

// TestDeleteSecret_PanicInDetachedAuditGoroutineDoesNotCrash covers the #481
// call site at secrets_crud.go's DeleteSecret (audit: secret.deleted).
func TestDeleteSecret_PanicInDetachedAuditGoroutineDoesNotCrash(t *testing.T) {
	handler, _ := newPanicTestHandler(t)
	created, err := handler.coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "target", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	done := make(chan struct{})
	handler.coreService.SetAuditForwarder(&panicAuditForwarder{done: done})

	r := withIDParam(userReq(http.MethodDelete, "/api/v1/secrets/"+strconv.FormatUint(uint64(created.ID), 10), nil), created.ID)
	rr := httptest.NewRecorder()
	handler.DeleteSecret(rr, r)
	assert.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("detached audit goroutine never ran")
	}
}
