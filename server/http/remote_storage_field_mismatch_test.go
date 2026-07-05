// remote_storage_field_mismatch_test.go — end-to-end regression coverage for #496:
// RemoteStorage.CreateUser/CreateSecret/UpdateSecret (internal/storage/store/
// remote_users.go, remote_secrets.go) used to POST/PUT the raw, untagged
// models.User/models.SecretNode Go struct directly as the request body, whose
// field names did not match the real HTTP handlers' snake_case request DTOs.
//
// All three cases here are driven against a REAL server (NewRouter), not a
// hand-rolled mock — a mock that manually sets fields "correctly" can never catch
// a real field-name mismatch (the same lesson #452/#794's own e2e test was built
// around).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wireCapture records the request body of the single request the test under
// it makes, and mirrors the real handler's response back to the caller
// unchanged — so a test can drive a real RemoteStorage call AND separately
// inspect exactly what bytes were sent, and what the real handler's own
// validator said about them.
type wireCapture struct {
	reqBody []byte
}

func (c *wireCapture) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.reqBody = body
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// rawPost replays a captured request body directly against the real server
// (bypassing store.RemoteStorage's HTTPClient entirely), so the test can read
// the real handler's raw JSON response — including "message"/"details" —
// which internal/storage/remote.HTTPClient.makeRequest deliberately discards
// for any 4xx status (it synthesizes a generic "HTTP 400: Bad Request" instead,
// so that detail is invisible through RemoteStorage's own return value).
func rawPost(t *testing.T, baseURL, path, token string, body []byte) (status int, parsed map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(respBody, &parsed))
	return resp.StatusCode, parsed
}

// TestRemoteStorage_FieldMismatchFix_CreateUser_WireShapeAndValidation proves the
// #496 fix for RemoteStorage.CreateUser's request wire shape against the REAL
// CreateUser handler (server/http/handlers/users_crud.go).
//
// Before the #496 fix, models.User (no json tags of its own besides
// PasswordHash's json:"-") was marshaled directly: "DisplayName" and "IsActive"
// do not case-insensitively match the handler's "display_name"/"active"...
// sorry, "is_active" tags (only single-word fields like "Username"/"Email"
// happened to still match). DisplayName landed as "" server-side, which fails
// the handler's OWN "required,min=1" structural validation — producing a
// generic "Invalid request data" error that (wrongly) implicated display_name,
// masking the separate, genuine gap #496 deliberately left open and #499 later
// closed: CreateUser's optional plaintextPassword variadic can now convey the
// password (see TestRemoteStorage_PlaintextChannel_CreateUser_RealServerRoundTrip
// for the genuine end-to-end success proof). THIS test calls rs.CreateUser with
// NO plaintextPassword argument — exactly what SSO/SCIM auto-provisioning (which
// has no real plaintext to offer) sends — so "password" is correctly absent from
// the wire and the handler's business-logic check still (correctly) rejects it.
// After the #496 fix, username/email/display_name/is_active all reach the
// handler correctly, so the ONLY remaining failure is the accurate one: the
// explicit "password is required" business-logic check, not a structural
// validation error blaming the wrong field.
func TestRemoteStorage_FieldMismatchFix_CreateUser_WireShapeAndValidation(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)

	capture := &wireCapture{}
	upstreamSrv := httptest.NewServer(capture.middleware(upstreamRouter))
	defer upstreamSrv.Close()

	ctx := context.Background()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	active := true
	// No plaintextPassword argument passed (#499): this call has nothing real to
	// offer, so it must still fail — matching an SSO/SCIM-style auto-provisioned
	// caller that genuinely has no plaintext credential to send.
	_, createErr := rs.CreateUser(ctx, &models.User{
		Username: "e2e-mismatch-newuser", Email: "e2e-mismatch-newuser@example.com",
		DisplayName: "E2E New User", IsActive: active,
		PasswordHash: "irrelevant-bcrypt-hash-never-sent", // json:"-": must never reach the wire
	})
	require.Error(t, createErr)

	// --- prove the exact bytes sent match the real handler's expected DTO shape ---
	var sentBody map[string]interface{}
	require.NoError(t, json.Unmarshal(capture.reqBody, &sentBody))
	assert.Equal(t, "e2e-mismatch-newuser", sentBody["username"])
	assert.Equal(t, "e2e-mismatch-newuser@example.com", sentBody["email"])
	assert.Equal(t, "E2E New User", sentBody["display_name"], "#496: display_name must be sent, not silently dropped as DisplayName")
	assert.Equal(t, true, sentBody["is_active"], "#496: is_active must be sent under the handler's actual key")
	_, hasPassword := sentBody["password"]
	assert.False(t, hasPassword, "PasswordHash (json:\"-\") must never leak onto the wire under any key")
	for _, badKey := range []string{"DisplayName", "IsActive", "Username", "Email"} {
		_, present := sentBody[badKey]
		assert.False(t, present, "must not send the old PascalCase Go field name %q", badKey)
	}

	// --- replay the exact same bytes directly against the real handler and read
	// its raw validation response (RemoteStorage's own wrapper discards this
	// detail for any 4xx) ---
	status, resp := rawPost(t, upstreamSrv.URL, "/api/v1/users", upstreamToken, capture.reqBody)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "Password is required unless deliver_setup_link or generate_one_time_password is set", resp["message"],
		"#496: with username/email/display_name/is_active correctly conveyed, the ONLY remaining "+
			"failure must be the accurate one (password can't be sent) — not a structural "+
			"validation error wrongly blaming display_name/is_active")
}

// TestRemoteStorage_FieldMismatchFix_CreateSecret_WireShapeAndValidation mirrors
// the CreateUser test above for RemoteStorage.CreateSecret against the real
// CreateSecret handler (server/http/handlers/secrets_crud.go).
//
// Before the #496 fix, models.SecretNode (no json tags at all) was marshaled
// directly: "ProjectID"/"EnvironmentID"/"MaxReads" do not case-insensitively
// match "project_id"/"environment_id"/"max_reads", so environment_id (required)
// landed as 0 server-side, producing a generic "Invalid request data" error
// blaming environment_id/project_id — masking the separate, genuine gap #496
// deliberately left open and #499 later closed: CreateSecret's optional
// plaintextValue variadic can now convey the value (see
// TestRemoteStorage_PlaintextChannel_CreateSecret_RealServerRoundTrip for the
// genuine end-to-end success proof). THIS test calls rs.CreateSecret with NO
// plaintextValue argument — exactly what a caller with nothing to offer sends —
// so "value" is present on the wire but empty, and the handler's structural
// "required" check still (correctly) rejects it. After the #496 fix,
// name/project_id/environment_id/type/max_reads/classification all reach the
// handler correctly, so the ONLY remaining validation failure is the accurate
// one: "value" missing.
func TestRemoteStorage_FieldMismatchFix_CreateSecret_WireShapeAndValidation(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)

	capture := &wireCapture{}
	upstreamSrv := httptest.NewServer(capture.middleware(upstreamRouter))
	defer upstreamSrv.Close()

	ctx := context.Background()

	project, err := upstreamCore.CreateProject(ctx, "e2e-mismatch-project", "seeded for #496's e2e test")
	require.NoError(t, err)
	envs, err := upstreamCore.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	maxReads := 5
	// No plaintextValue argument passed (#499): this call has nothing real to offer,
	// so it must still fail — the server's "value" required check correctly rejects
	// an empty value exactly as it would reject an absent one.
	_, createErr := rs.CreateSecret(ctx, &models.SecretNode{
		Name: "e2e-mismatch-secret", ProjectID: project.ID, EnvironmentID: envID,
		Type: "generic", MaxReads: &maxReads, Classification: "internal",
	})
	require.Error(t, createErr)

	// --- prove the exact bytes sent match the real handler's expected DTO shape ---
	var sentBody map[string]interface{}
	require.NoError(t, json.Unmarshal(capture.reqBody, &sentBody))
	assert.Equal(t, "e2e-mismatch-secret", sentBody["name"])
	assert.Equal(t, float64(project.ID), sentBody["project_id"], "#496: project_id must be sent, not silently dropped as ProjectID")
	assert.Equal(t, float64(envID), sentBody["environment_id"], "#496: environment_id must be sent, not silently dropped as EnvironmentID")
	assert.Equal(t, "generic", sentBody["type"])
	assert.Equal(t, float64(5), sentBody["max_reads"], "#496: max_reads must be sent, not silently dropped as MaxReads")
	assert.Equal(t, "internal", sentBody["classification"])
	value, hasValue := sentBody["value"]
	assert.True(t, hasValue, "#499: the wire request always includes a value key now that "+
		"CreateSecret can convey one via its optional plaintextValue argument")
	assert.Equal(t, "", value, "no plaintextValue was passed to this call, so it must be empty, not a real secret value")
	for _, badKey := range []string{"ProjectID", "EnvironmentID", "MaxReads", "Name", "Type"} {
		_, present := sentBody[badKey]
		assert.False(t, present, "must not send the old PascalCase Go field name %q", badKey)
	}

	// --- replay the exact same bytes directly against the real handler and read
	// its raw validation response ---
	status, resp := rawPost(t, upstreamSrv.URL, "/api/v1/secrets", upstreamToken, capture.reqBody)
	assert.Equal(t, http.StatusBadRequest, status)
	details, ok := resp["details"].(map[string]interface{})
	require.True(t, ok, "a structural validation failure must carry field-level details")
	errs, ok := details["errors"].([]interface{})
	require.True(t, ok)
	require.Len(t, errs, 1, "#496: with name/project_id/environment_id/type/max_reads/classification "+
		"correctly conveyed, exactly ONE structural validation error should remain")
	only, ok := errs[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value", only["field"],
		"#496: the one remaining failure must accurately blame the missing value — "+
			"not a coincidentally-also-broken project_id/environment_id/max_reads")
}

// TestRemoteStorage_FieldMismatchFix_UpdateUser_RealServerRoundTrip proves the
// #496 fix for RemoteStorage.UpdateUser's request AND response wire shape
// end-to-end against a real server — unlike CreateUser/CreateSecret above,
// UpdateUser carries no credential material, so this call CAN genuinely
// succeed, letting this test prove the fields actually landed, not just that
// the call didn't error.
func TestRemoteStorage_FieldMismatchFix_UpdateUser_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	// Seed a real user directly against the upstream's own core (bypassing the
	// wire for setup, mirroring the #452/#794 e2e test's own pattern).
	seeded, err := upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "e2e-mismatch-updateuser", Email: "e2e-mismatch-updateuser@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "Original Display Name",
	})
	require.NoError(t, err)
	require.Equal(t, "Original Display Name", seeded.DisplayName)
	require.True(t, seeded.IsActive)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	// --- the fixed request side: PUT a new display_name and active:false ---
	updated, err := rs.UpdateUser(ctx, &models.User{
		ID: seeded.ID, Username: seeded.Username, Email: seeded.Email,
		DisplayName: "Updated Via Remote", IsActive: false,
	})
	require.NoError(t, err, "UpdateUser must not be misreported as a failure for a genuinely successful upstream response")

	// --- the fixed response side: the decoded return value itself must carry
	// the real updated fields, not zero values ---
	assert.Equal(t, "Updated Via Remote", updated.DisplayName,
		"#496: display_name must round-trip in the response, not silently drop")
	assert.False(t, updated.IsActive, "#496: active must round-trip in the response, not silently drop")
	assert.Equal(t, core.AccountActive, updated.AccountState,
		"#496: account_state must decode from the response (previously always zeroed)")
	assert.False(t, updated.CreatedAt.IsZero(), "#496: created_at must decode from the response")

	// --- confirm it genuinely landed server-side, not just in the client's own
	// decode ---
	direct, err := upstreamCore.Storage().GetUser(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Via Remote", direct.DisplayName,
		"the downstream's forwarded PUT must be a real row-level write reaching the upstream's own users table")
	assert.False(t, direct.IsActive, "is_active must also have genuinely landed, not silently dropped")
}
