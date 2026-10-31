package handlers

// authorize_outage_handlers_test.go — AUTHZ-OUTAGE-HANDLERS-1 item 2 (#3857): the
// routes that check the permission inside the handler answer a storage outage of
// that check 503 + Retry-After (as the middleware gates and gRPC do after #3853),
// not 403 "forbidden". A genuine denial keeps its 403 and body, and an error the
// classifier does not recognise stays a fail-closed 403.
//
// The outage is injected on the permission lookup itself through the faultstorage
// seam (ResolveUserPermissionAt for a user, ResolveMachinePermissionAt for a
// machine), so the test fails on the handler's own mapping and nowhere else.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const outageMachineID uint = 7

type outageSite struct {
	name string
	// fault is the permission-lookup storage method the route's check calls.
	fault string
	// machine runs the route as a machine principal instead of the admin user.
	machine bool
	// denyMessage is the 403 message the route answered before this change.
	denyMessage string
	call        func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, actor *middleware.UserContext) *httptest.ResponseRecorder
}

func outageCtx(r *http.Request, uc *middleware.UserContext) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

func outageSites() []outageSite {
	const insufficient = "Insufficient permissions"
	return []outageSite{
		{"CreateSecret", "ResolveUserPermissionAt", false, insufficient,
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(cs)
				require.NoError(t, err)
				body := fmt.Sprintf(`{"name":"outage-new","value":"v","project_id":%d,"environment_id":%d,"type":"static"}`, fx.projectID, fx.envID)
				req := outageCtx(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", strings.NewReader(body)), uc)
				w := httptest.NewRecorder()
				h.CreateSecret(w, req)
				return w
			}},
		{"ListSecrets", "ResolveMachinePermissionAt", true, insufficient,
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(cs)
				require.NoError(t, err)
				req := outageCtx(httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets?project_id=%d", fx.projectID), nil), uc)
				w := httptest.NewRecorder()
				h.ListSecrets(w, req)
				return w
			}},
		{"CopySecret", "ResolveUserPermissionAt", false, "Insufficient permissions for the target environment",
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(cs)
				require.NoError(t, err)
				body := fmt.Sprintf(`{"environment_id":%d,"name":"outage-copy"}`, fx.envID)
				req := outageCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", fx.id()), uc)
				w := httptest.NewRecorder()
				h.CopySecret(w, req)
				return w
			}},
		{"CreateFolder", "ResolveUserPermissionAt", false, insufficient,
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h := NewFolderHandler(cs)
				body := fmt.Sprintf(`{"name":"outage-folder","project_id":%d,"environment_id":%d}`, fx.projectID, fx.envID)
				req := outageCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", strings.NewReader(body)), uc)
				w := httptest.NewRecorder()
				h.CreateFolder(w, req)
				return w
			}},
		{"DynamicCreateConfig", "ResolveUserPermissionAt", false, insufficient,
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h := NewDynamicSecretHandler(cs)
				body := fmt.Sprintf(`{"name":"outage-dyn","project_id":%d,"environment_id":%d}`, fx.projectID, fx.envID)
				req := outageCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", strings.NewReader(body)), uc)
				w := httptest.NewRecorder()
				h.CreateConfig(w, req)
				return w
			}},
		{"DynamicListConfigs", "ResolveUserPermissionAt", false, insufficient,
			func(t *testing.T, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h := NewDynamicSecretHandler(cs)
				target := fmt.Sprintf("/api/v1/dynamic-secrets/configs?project_id=%d&environment_id=%d", fx.projectID, fx.envID)
				req := outageCtx(httptest.NewRequest(http.MethodGet, target, nil), uc)
				w := httptest.NewRecorder()
				h.ListConfigs(w, req)
				return w
			}},
	}
}

// outageActor is the principal a site runs as: the global admin user (so only the
// injected fault can refuse it), a machine with no roles, or the role-less user.
func outageActor(site outageSite, plainUser bool) *middleware.UserContext {
	if site.machine {
		id := outageMachineID
		return &middleware.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: &id, Username: "outage-machine"}
	}
	if plainUser {
		return &middleware.UserContext{UserID: secretsPlainID, Username: "plain_user", Email: "plain@example.com"}
	}
	return &middleware.UserContext{UserID: secretsAdminID, Username: "actor", Email: "actor@test.com"}
}

func outageFaultCore(db *gorm.DB, method string, ferr error) (*core.KeyorixCore, *faultstorage.FaultyStorage) {
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
		Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: ferr,
	})
	return core.NewKeyorixCore(faulty), faulty
}

// A storage outage of the in-handler permission check is 503 + Retry-After with the
// gates' fixed message, never the 403 a client reads as "you are not allowed".
func TestHandlerPermissionLookupOutageIs503(t *testing.T) {
	for _, site := range outageSites() {
		t.Run(site.name, func(t *testing.T) {
			_, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)
			fcs, faulty := outageFaultCore(db, site.fault, fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED))

			w := site.call(t, fcs, fx, outageActor(site, false))

			require.True(t, faulty.Fired(), "%s must reach storage method %s", site.name, site.fault)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, "2", w.Header().Get("Retry-After"))
			assert.Contains(t, w.Body.String(), "authorization temporarily unavailable, please retry")
			assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			assert.NotContains(t, w.Body.String(), "Forbidden")
		})
	}
}

// The value-read routes wrapped by AuditSecretValueReadDenials record a refused read
// only when a layer noted the reason or the status is 403/404. A 503 carries neither,
// so the handler must note internal_error itself (as the middleware gate does), or an
// outage on these checks would leave no audit row at all.
func TestHandlerPermissionLookupOutageNotesInternalErrorOnValueReads(t *testing.T) {
	sites := []struct {
		name    string
		fault   string
		machine bool
		call    func(t *testing.T, ctx context.Context, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder
	}{
		{"CopySecret", "ResolveUserPermissionAt", false,
			func(t *testing.T, ctx context.Context, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(cs)
				require.NoError(t, err)
				body := fmt.Sprintf(`{"environment_id":%d,"name":"outage-copy"}`, fx.envID)
				req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).WithContext(ctx), "id", fx.id())
				w := httptest.NewRecorder()
				h.CopySecret(w, outageCtx(req, uc))
				return w
			}},
		// No resolved secret on the context: the machine fallback re-authorizes the
		// principal against the path secret itself.
		{"GetSecretMachineFallback", "ResolveMachinePermissionAt", true,
			func(t *testing.T, ctx context.Context, cs *core.KeyorixCore, fx secretsFixture, uc *middleware.UserContext) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(cs)
				require.NoError(t, err)
				req := withChiParam(httptest.NewRequest(http.MethodGet, "/?include_value=true", nil).WithContext(ctx), "id", fx.id())
				w := httptest.NewRecorder()
				h.GetSecret(w, outageCtx(req, uc))
				return w
			}},
	}
	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			_, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)
			fcs, faulty := outageFaultCore(db, site.fault, fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED))
			ctx, note := core.WithSecretReadDenialNote(context.Background(), "outage/"+site.name)

			w := site.call(t, ctx, fcs, fx, outageActor(outageSite{machine: site.machine}, false))

			require.True(t, faulty.Fired(), "%s must reach storage method %s", site.name, site.fault)
			require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, core.SecretReadDeniedInternalError, note.Reason(),
				"a refused value read stays audited (outcome=failed) during an outage")
		})
	}
}

// A genuine denial still answers 403 with the same error type and message as before.
func TestHandlerPermissionDenialStays403(t *testing.T) {
	for _, site := range outageSites() {
		t.Run(site.name, func(t *testing.T) {
			cs, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)

			w := site.call(t, cs, fx, outageActor(site, true))

			require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
			var body struct {
				Error   string `json:"error"`
				Message string `json:"message"`
				Code    int    `json:"code"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "body: %s", w.Body.String())
			assert.Equal(t, "Forbidden", body.Error)
			assert.Equal(t, site.denyMessage, body.Message)
			assert.Equal(t, http.StatusForbidden, body.Code)
		})
	}
}

// A lookup error the classifier does not recognise is not an outage: the route
// stays fail-closed 403, so nothing is ever reported as retryable by mistake.
func TestHandlerPermissionLookupUnrecognisedErrorStays403(t *testing.T) {
	for _, site := range outageSites() {
		t.Run(site.name, func(t *testing.T) {
			_, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)
			fcs, faulty := outageFaultCore(db, site.fault, errors.New("injected: role resolution returned no result"))

			w := site.call(t, fcs, fx, outageActor(site, false))

			require.True(t, faulty.Fired(), "%s must reach storage method %s", site.name, site.fault)
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
			assert.NotContains(t, w.Body.String(), "injected")
		})
	}
}
