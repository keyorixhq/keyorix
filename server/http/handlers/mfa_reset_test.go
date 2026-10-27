package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// mfaResetRefusals is every typed refusal the MFA reset routes can receive from core.
var mfaResetRefusals = []error{
	core.ErrMFAResetAdminRequired, core.ErrMFAResetActorNeedsMFA, core.ErrMFAResetSelfApproval,
	core.ErrInsufficientAdminAuthority, core.ErrCannotActOnSelf, core.ErrMFAResetInput,
	core.ErrMFAResetTargetNotFound, core.ErrMFAResetRequestNotFound, core.ErrMFAResetMachineIdentity,
	core.ErrMFAResetGlobalAdmin, core.ErrMFAResetExternalIdentity, core.ErrMFAResetAccountBlocked,
	core.ErrMFAResetNoSecondAdmin, core.ErrMFAResetAlreadyPending, core.ErrMFAResetRequestDecided,
	core.ErrMFAResetRequestExpired, core.ErrMFAResetRequesterChanged, core.ErrMutationAuditUnavailable,
	core.ErrReauthRejected, core.ErrMFAVerificationStorageFailure,
}

// Every refusal answers with a fixed text, never the wrapped cause, and with a
// status the OpenAPI document declares for the MFA reset operations.
func TestSendMFAResetError_FixedTextsAndDocumentedStatuses(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &spec))
	documented := map[string]bool{}
	for _, p := range []string{"/api/v1/mfa-reset-requests", "/api/v1/mfa-reset-requests/{id}/approve"} {
		post, ok := spec.Paths[p]["post"].(map[string]any)
		require.True(t, ok, "%s has no post operation in openapi.yaml", p)
		for code := range post["responses"].(map[string]any) {
			documented[code] = true
		}
	}

	const secret = "db row 42 detail"
	for _, sentinel := range mfaResetRefusals {
		w := httptest.NewRecorder()
		sendMFAResetError(w, "approve", fmt.Errorf("%w: %s", sentinel, secret))
		assert.NotEqual(t, http.StatusInternalServerError, w.Code, "%v is unclassified", sentinel)
		assert.True(t, documented[strconv.Itoa(w.Code)], "%v answers %d, which openapi.yaml does not declare", sentinel, w.Code)
		assert.NotContains(t, w.Body.String(), secret, "%v leaks the wrapped cause", sentinel)
	}

	w := httptest.NewRecorder()
	sendMFAResetError(w, "approve", errors.New(secret))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), secret)
}

func TestMFAResetRoutes_NoActorIsUnauthorized(t *testing.T) {
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	defaultUserHandler = &UserHandler{}
	for name, h := range map[string]http.HandlerFunc{
		"request": RequestMFAReset, "approve": ApproveMFAReset, "cancel": CancelMFAReset, "list": ListMFAResetRequests,
	} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/api/v1/mfa-reset-requests", strings.NewReader("{}")))
		assert.Equal(t, http.StatusUnauthorized, w.Code, name)
	}
}

// mfaResetHandlerWorld is a real core over a fully migrated SQLite database with
// two TOTP-enrolled global admins (a, b) and an enrolled non-admin target.
type mfaResetHandlerWorld struct {
	cs      *core.KeyorixCore
	st      *store.LocalStorage
	a, b    *models.User
	target  *models.User
	secrets map[uint]string
}

func newMFAResetHandlerWorld(t *testing.T) *mfaResetHandlerWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_mfareset_")
	require.NoError(t, kxstorage.MigrateExisting(db))
	st := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(st)
	cs.SetBootstrapToken("bootstrap-token")
	ctx := context.Background()
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{Username: "admin", Email: "admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin", Token: "bootstrap-token"})
	require.NoError(t, err)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	cs.SetAuthEncryptor(enc)

	w := &mfaResetHandlerWorld{cs: cs, st: st, secrets: map[uint]string{}}
	w.a, err = st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	roleIDs, err := st.GetUserRoleIDsAt(ctx, w.a.ID, corestorage.Scope{})
	require.NoError(t, err)
	mk := func(name string) *models.User {
		u, err := cs.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", DisplayName: name, Password: "Tr1cky-Passphrase-For-Tests!"})
		require.NoError(t, err)
		return u
	}
	w.b = mk("admin-b")
	require.NoError(t, st.AssignRole(ctx, w.b.ID, roleIDs[0], corestorage.Scope{}))
	w.target = mk("target")
	for uid, pw := range map[uint]string{w.a.ID: "BootstrapPass123!", w.b.ID: "Tr1cky-Passphrase-For-Tests!", w.target.ID: "Tr1cky-Passphrase-For-Tests!"} {
		_, secret, err := cs.BeginMFAEnrollment(ctx, uid)
		require.NoError(t, err)
		w.secrets[uid] = secret
		code, err := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
		require.NoError(t, err)
		_, err = cs.ActivateMFA(ctx, uid, code, pw, "")
		require.NoError(t, err)
	}
	return w
}

// code is uid's code for the NEXT time step: activation used the previous one, so
// this one is fresh and still inside the ±1-step window.
func (w *mfaResetHandlerWorld) code(t *testing.T, uid uint) string {
	t.Helper()
	c, err := totp.GenerateCode(w.secrets[uid], time.Now().Add(30*time.Second))
	require.NoError(t, err)
	return c
}

func (w *mfaResetHandlerWorld) call(t *testing.T, actor *models.User, h http.HandlerFunc, method, path, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(),
		&customMiddleware.UserContext{UserID: actor.ID, Username: actor.Username, Email: actor.Email}))
	if id != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	contracttest.AssertOpenAPIResponse(t, req, rec)
	return rec
}

// The whole online flow through the four routes: admin A requests, A's own
// approval is refused, admin B approves and receives the one-time password, the
// target's factor, sessions and PATs are gone, and a replay is refused.
func TestContractMFAReset_RequestApproveListCancel(t *testing.T) {
	w := newMFAResetHandlerWorld(t)
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	uh, err := NewUserHandler(w.cs)
	require.NoError(t, err)
	defaultUserHandler = uh
	ctx := context.Background()
	_, err = w.st.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{UserID: w.target.ID, Name: "ci", TokenHash: "target-pat"})
	require.NoError(t, err)

	rec := w.call(t, w.a, RequestMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests", "",
		fmt.Sprintf(`{"user":"target","reason":"lost phone","verified_by":"video","code":%q}`, w.code(t, w.a.ID)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created struct {
		Data struct {
			Request struct {
				ID uint `json:"id"`
			} `json:"request"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	id := strconv.FormatUint(uint64(created.Data.Request.ID), 10)

	rec = w.call(t, w.a, ListMFAResetRequests, http.MethodGet, "/api/v1/mfa-reset-requests?status=pending", "", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"effective_status":"pending"`)

	rec = w.call(t, w.a, ApproveMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/"+id+"/approve", id, `{"code":"123456"}`)
	assert.Equal(t, http.StatusForbidden, rec.Code, "self-approval: %s", rec.Body.String())

	rec = w.call(t, w.b, ApproveMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/"+id+"/approve", id,
		fmt.Sprintf(`{"code":%q}`, w.code(t, w.b.ID)))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var approved struct {
		Data struct {
			OTP string `json:"one_time_password"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &approved))
	require.NotEmpty(t, approved.Data.OTP)

	u, err := w.st.GetUser(ctx, w.target.ID)
	require.NoError(t, err)
	assert.False(t, u.MFAEnabled)
	assert.True(t, u.MFAEnrolmentRequired)
	pats, err := w.st.ListPersonalAccessTokensByUser(ctx, w.target.ID)
	require.NoError(t, err)
	for _, p := range pats {
		assert.True(t, p.Revoked)
	}

	rec = w.call(t, w.b, ApproveMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/"+id+"/approve", id, `{"code":"123456"}`)
	assert.Equal(t, http.StatusConflict, rec.Code, "replay: %s", rec.Body.String())
	rec = w.call(t, w.a, CancelMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/"+id+"/cancel", id, "")
	assert.Equal(t, http.StatusConflict, rec.Code, "an approved request cannot be cancelled: %s", rec.Body.String())
}

func TestContractMFAReset_Cancel(t *testing.T) {
	w := newMFAResetHandlerWorld(t)
	old := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = old })
	uh, err := NewUserHandler(w.cs)
	require.NoError(t, err)
	defaultUserHandler = uh

	rec := w.call(t, w.a, RequestMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests", "",
		fmt.Sprintf(`{"user":"target","reason":"lost phone","verified_by":"ticket","evidence":"T-1","code":%q}`, w.code(t, w.a.ID)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	rec = w.call(t, w.b, CancelMFAReset, http.MethodPost, "/api/v1/mfa-reset-requests/1/cancel", "1", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	u, err := w.st.GetUser(context.Background(), w.target.ID)
	require.NoError(t, err)
	assert.True(t, u.MFAEnabled, "a cancelled request changes nothing")
}
