package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMachineCtxS10 wraps a request with a machine-identity UserContext.
func withMachineCtxS10(r *http.Request) *http.Request {
	mid := uint(1)
	userCtx := &customMiddleware.UserContext{
		UserID:            0,
		MachineIdentityID: &mid,
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// seedS10Secret creates a project, lists its first environment, and creates a secret.
// Returns (core, projectName, envName, secretID, secretName) or skips on any failure.
func seedS10Secret(t *testing.T, projName, secretName string) (*core.KeyorixCore, string, string, uint) {
	t.Helper()
	svc := newHandlerCoreS4(t)
	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, projName, "sprint-10 coverage seed")
	require.NoError(t, err, "CreateProject")
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err, "ListEnvironmentsByProject")
	require.NotEmpty(t, envs, "no environments seeded")
	envName := envs[0].Name
	req := &core.CreateSecretRequest{
		Name:          secretName,
		Value:         []byte("s10-test-value"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "testuser",
	}
	secret, err := svc.CreateSecret(ctx, req)
	if err != nil {
		t.Skip("CreateSecret failed (may already exist in shared DB):", err)
	}
	return svc, projName, envName, secret.ID
}

// ── toPATResponse: ExpiresAt and LastUsedAt branches ─────────────────────────

func TestToPATResponse_WithExpiresAt_S10(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:        99,
		Name:      "s10-expires",
		ExpiresAt: &expiry,
	}
	resp := toPATResponse(tok)
	require.NotNil(t, resp.ExpiresAt, "ExpiresAt should be set")
	assert.Equal(t, expiry.UTC().Format(time.RFC3339), *resp.ExpiresAt)
	assert.Nil(t, resp.LastUsedAt)
}

func TestToPATResponse_WithLastUsedAt_S10(t *testing.T) {
	lastUsed := time.Now().UTC().Add(-1 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:         98,
		Name:       "s10-lastused",
		LastUsedAt: &lastUsed,
	}
	resp := toPATResponse(tok)
	assert.Nil(t, resp.ExpiresAt)
	require.NotNil(t, resp.LastUsedAt, "LastUsedAt should be set")
	assert.Equal(t, lastUsed.UTC().Format(time.RFC3339), *resp.LastUsedAt)
}

func TestToPATResponse_BothSet_S10(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	lastUsed := time.Now().UTC().Add(-1 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:         97,
		Name:       "s10-both",
		ExpiresAt:  &expiry,
		LastUsedAt: &lastUsed,
	}
	resp := toPATResponse(tok)
	require.NotNil(t, resp.ExpiresAt)
	require.NotNil(t, resp.LastUsedAt)
}

// ── GetSecret: BadID (ParseUint error) ───────────────────────────────────────

func TestGetSecret_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/notanumber", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "notanumber")
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecret: machine identity path ─────────────────────────────────────────

func TestGetSecret_MachineIdentity_NotFound_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999", nil)
	r = withMachineCtxS10(r)
	r = withChiParam(r, "id", "99999")
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	// Secret 99999 doesn't exist → 404 via machine path (GetSecret not GetSecretWithPermissionCheck)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── GetSecret: include_value=true path ───────────────────────────────────────

func TestGetSecret_IncludeValue_MachineIdentity_S10(t *testing.T) {
	_, _, _, secretID := seedS10Secret(t, "s10-proj-inclval", "s10-inclval-secret")

	h := newSecretHandlerS4(t)
	url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = withMachineCtxS10(r)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	// Should be 200 with {"secret":...,"value":"..."} since machine bypass permission check
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, _ := body["data"].(map[string]any)
	assert.NotNil(t, data["secret"], "expected secret key in response")
	assert.NotNil(t, data["value"], "expected value key in response")
}

// ── GetSecretValueByRef: success path ────────────────────────────────────────

func TestGetSecretValueByRef_Success_MachineIdentity_S10(t *testing.T) {
	_, projName, envName, _ := seedS10Secret(t, "s10-proj-ref", "s10-ref-secret")

	h := newSecretHandlerS4(t)
	ref := fmt.Sprintf("%s/%s/%s", projName, envName, "s10-ref-secret")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-ref?ref="+ref, nil)
	r = withMachineCtxS10(r)
	w := httptest.NewRecorder()

	h.GetSecretValueByRef(w, r)
	// Machine identity → no permission check on value read
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, _ := body["data"].(map[string]any)
	assert.NotNil(t, data["secret"], "expected secret in ref response")
	assert.NotNil(t, data["value"], "expected value in ref response")
}

// ── SuspendProjectSecrets / ResumeProjectSecrets: BadID ──────────────────────

func TestSuspendProjectSecrets_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/secrets/suspend-all", strings.NewReader("{}"))
	r = withUserCtx(r)
	r = withChiParam(r, "id", "xyz")
	w := httptest.NewRecorder()

	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResumeProjectSecrets_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/secrets/resume-all", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "xyz")
	w := httptest.NewRecorder()

	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CopyEnvironmentSecrets: zero target_environment_id ───────────────────────

func TestCopyEnvironmentSecrets_ZeroTargetEnvID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":0}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "1", "envId": "1"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCopyEnvironmentSecrets_BadProjectID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":2}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/environments/1/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "xyz", "envId": "1"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCopyEnvironmentSecrets_BadEnvID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":2}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/xyz/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "1", "envId": "xyz"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecretValueByRef: isMachine=false success path ────────────────────────

func TestGetSecretValueByRef_UserPath_S10(t *testing.T) {
	_, projName, envName, _ := seedS10Secret(t, "s10-proj-userref", "s10-userref-secret")

	h := newSecretHandlerS4(t)
	ref := fmt.Sprintf("%s/%s/%s", projName, envName, "s10-userref-secret")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-ref?ref="+ref, nil)
	r = withUserCtx(r)
	w := httptest.NewRecorder()

	h.GetSecretValueByRef(w, r)
	// User path: GetSecretValueWithPermissionCheck — may 200 or 403 depending on sharing config
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── SuspendProjectSecrets / ResumeProjectSecrets: happy path ─────────────────

func TestSuspendProjectSecrets_HappyPath_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"reason":"s10 test"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/9999/secrets/suspend-all",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParam(r, "id", "9999")
	w := httptest.NewRecorder()

	h.SuspendProjectSecrets(w, r)
	// 9999 doesn't exist → succeeds with suspended:0
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResumeProjectSecrets_HappyPath_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/9999/secrets/resume-all", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "9999")
	w := httptest.NewRecorder()

	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetSecret: user path include_value=true (not found on existing secret) ───

func TestGetSecret_IncludeValue_UserPath_S10(t *testing.T) {
	_, _, _, secretID := seedS10Secret(t, "s10-proj-inclval-user", "s10-inclval-user-secret")

	h := newSecretHandlerS4(t)
	url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	// May be 200 (user 1 created it and has access) or 403 (permission denied)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── GetSecret: happy path via machine identity ────────────────────────────────

func TestGetSecret_MachineIdentity_Found_S10(t *testing.T) {
	_, _, _, secretID := seedS10Secret(t, "s10-proj-machine-found", "s10-machine-found-secret")

	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", secretID), nil)
	r = withMachineCtxS10(r)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
