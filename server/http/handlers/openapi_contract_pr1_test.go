// openapi_contract_pr1_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 1 (dynamic-secret, rotation, breakglass) added
// response schemas for. Each test below drives the real handler through a happy
// path and calls contracttest.AssertOpenAPIResponse so the operation moves from
// "pending" to genuinely enforced -- see CLAUDE.md's "a mechanism must be
// validated against a failure that actually happened" and
// openapi_contract_pr2_test.go's identical precedent. Each test is self-contained
// (its own fixture) rather than grafted onto an existing test, so this batch is
// auditable as one unit and never risks changing an existing test's behavior.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

// ── break-glass fixtures ─────────────────────────────────────────────────────

// breakGlassFixturePR1 enables break-glass with a contained emergency role
// (no roles.assign, not an install-admin role name) and grants the withUserCtx
// test user (UserID=1) a project-scoped role so IsProjectMember passes --
// ActivateBreakGlass is deliberately not RBAC-gated (see break_glass.go's
// package doc), so this is the actual precondition, not a permission grant.
func breakGlassFixturePR1(t *testing.T) (*CatalogHandler, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "contract-pr1-bg-proj"}
	require.NoError(t, db.Create(proj).Error)
	// Two distinct roles: memberRole makes the test user IsProjectMember-true
	// (the actual precondition ActivateBreakGlass checks); emergencyRole is the
	// contained (no roles.assign, non-admin) role break-glass grants on
	// activation. They must differ, or the grant step fails with "already
	// assigned" since the user would already hold the emergency role.
	memberRole := &models.Role{Name: "contract_pr1_member", NameFolded: "contract_pr1_member"}
	require.NoError(t, db.Create(memberRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: memberRole.ID, ProjectID: proj.ID}).Error)
	emergencyRole := &models.Role{Name: "contract_pr1_emergency", NameFolded: "contract_pr1_emergency", Description: "contained role, no roles.assign"}
	require.NoError(t, db.Create(emergencyRole).Error)
	cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: emergencyRole.Name, DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})
	return NewCatalogHandler(cs), proj.ID
}

func TestContractPR1_ActivateBreakGlass(t *testing.T) {
	h, projID := breakGlassFixturePR1(t)
	body, _ := json.Marshal(map[string]any{"justification": "contract test activation, incident INC-1"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass", bytes.NewReader(body)),
		"id", machineUintToStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR1_ListBreakGlassActivations(t *testing.T) {
	h, projID := breakGlassFixturePR1(t)
	body, _ := json.Marshal(map[string]any{"justification": "contract test activation, incident INC-2"})
	activateReq := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/break-glass", bytes.NewReader(body)),
		"id", machineUintToStr(projID),
	))
	activateReq.Header.Set("Content-Type", "application/json")
	h.ActivateBreakGlass(httptest.NewRecorder(), activateReq)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/break-glass", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// ── dynamic-secrets fixtures ─────────────────────────────────────────────────

// dynamicSecretFixturePR1 wires a real AuthEncryptor (so the admin DSN
// round-trips through actual encrypt/decrypt, not a nil-encryptor shortcut)
// and a dynamic.FakeEngine (so IssueLease/RenewLease/RevokeLease exercise the
// real core logic without needing a live Postgres/MySQL/cloud-IAM target) --
// exactly the pattern internal/core/dynamic_secrets_test.go's newDynamicTestCore
// (unexported, core package only) already established.
func dynamicSecretFixturePR1(t *testing.T) (*DynamicSecretHandler, *core.KeyorixCore, uint, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("contract-pr1-test-passphrase"))
	cs.SetAuthEncryptor(enc)
	fake := &dynamic.FakeEngine{NativeExpiry: true}
	cs.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	proj := &models.Project{Name: "contract-pr1-ds-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "production"}
	require.NoError(t, db.Create(env).Error)
	return NewDynamicSecretHandler(cs), cs, proj.ID, env.ID
}

func mkDynamicSecretConfigPR1(t *testing.T, cs *core.KeyorixCore, projID, envID uint) *models.DynamicSecretConfig {
	t.Helper()
	cfg, err := cs.CreateDynamicSecretConfig(context.Background(), &core.CreateDynamicSecretConfigRequest{
		Name:              "contract-pr1-cfg",
		ProjectID:         projID,
		EnvironmentID:     envID,
		BackendType:       "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		CreatedBy:         "testuser_s12",
		ActorID:           1,
	})
	require.NoError(t, err)
	return cfg
}

func TestContractPR1_CreateDynamicSecretConfig(t *testing.T) {
	h, _, projID, envID := dynamicSecretFixturePR1(t)
	body, _ := json.Marshal(map[string]any{
		"name": "contract-pr1-create", "project_id": projID, "environment_id": envID,
		"backend_type": "postgres", "admin_dsn": "postgres://admin:s3cr3t@db.internal:5432/app",
		"creation_template": "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_ListDynamicSecretConfigs(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	mkDynamicSecretConfigPR1(t, cs, projID, envID)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?project_id="+machineUintToStr(projID), nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_GetDynamicSecretConfig(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/1", nil),
		"id", machineUintToStr(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_ClassifyDynamicSecretConfig(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)

	body, _ := json.Marshal(map[string]any{"classification": "internal"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/classification", bytes.NewReader(body)),
		"id", machineUintToStr(cfg.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_IssueDynamicSecretLease(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)

	body, _ := json.Marshal(map[string]any{"ttl_seconds": 1800})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/issue", bytes.NewReader(body)),
		"id", machineUintToStr(cfg.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_ListDynamicSecretLeases(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)
	_, err := cs.IssueLease(context.Background(), cfg.ID, 1800, 1)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/1/leases", nil),
		"id", machineUintToStr(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_RenewDynamicSecretLease(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)
	lease, err := cs.IssueLease(context.Background(), cfg.ID, 900, 1)
	require.NoError(t, err)

	// Renew to a LONGER ttl than the original issue (900s) so this genuinely
	// extends the lease -- RenewLease rejects a renewal that would not extend
	// it, and the config's default_ttl_seconds (3600, no max_ttl_seconds set)
	// is the effective ceiling, so 1800 is comfortably within bounds.
	body, _ := json.Marshal(map[string]any{"ttl_seconds": 1800})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/x/renew", bytes.NewReader(body)),
		"leaseID", lease.LeaseID,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RenewLease(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_RevokeDynamicSecretLease(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)
	lease, err := cs.IssueLease(context.Background(), cfg.ID, 1800, 1)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/x/revoke", nil),
		"leaseID", lease.LeaseID,
	))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_RevokeAllDynamicSecretLeases(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)
	_, err := cs.IssueLease(context.Background(), cfg.ID, 1800, 1)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", machineUintToStr(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// ── rotation-policies fixtures ───────────────────────────────────────────────

// rotationPolicyFixturePR1 uses freshCoreS12WithAdmin rather than the package's
// existing setupRotationPolicyTest: the latter's AutoMigrate list omits
// AuditEvent/SecretNode, which Evaluate's real code path queries (evaluating a
// policy scans covered secrets) -- freshCoreS12WithAdmin's broader migration set
// covers it without touching the shared helper other tests already depend on.
func rotationPolicyFixturePR1(t *testing.T) *core.KeyorixCore {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return cs
}

func mkRotationPolicyPR1(t *testing.T, cs *core.KeyorixCore) *models.RotationPolicy {
	t.Helper()
	pid := uint(1)
	policy, err := cs.CreateRotationPolicy(context.Background(), 1, &core.CreateRotationPolicyRequest{
		Name: "contract-pr1-policy", Scope: "project", ProjectID: &pid, IntervalDays: 30, CreatedBy: "testuser",
	})
	require.NoError(t, err)
	return policy
}

func TestContractPR1_ListRotationPolicies(t *testing.T) {
	cs := rotationPolicyFixturePR1(t)
	h := NewRotationPolicyHandler(cs)
	mkRotationPolicyPR1(t, cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies", nil))
	w := httptest.NewRecorder()
	h.List(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_CreateRotationPolicy(t *testing.T) {
	cs := rotationPolicyFixturePR1(t)
	h := NewRotationPolicyHandler(cs)
	body, _ := json.Marshal(map[string]any{
		"name": "contract-pr1-create-policy", "scope": "project", "project_id": 1, "interval_days": 45,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/rotation-policies", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR1_GetRotationPolicy(t *testing.T) {
	cs := rotationPolicyFixturePR1(t)
	h := NewRotationPolicyHandler(cs)
	policy := mkRotationPolicyPR1(t, cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/1", nil),
		"id", machineUintToStr(policy.ID),
	))
	w := httptest.NewRecorder()
	h.Get(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_EvaluateRotationPolicies(t *testing.T) {
	cs := rotationPolicyFixturePR1(t)
	h := NewRotationPolicyHandler(cs)
	mkRotationPolicyPR1(t, cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-policies/evaluate", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// ── rotation-order / rotation-plan fixtures (SecretHandler) ─────────────────

func rotationPlanFixturePR1(t *testing.T) (*SecretHandler, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj := &models.Project{Name: "contract-pr1-plan-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "production"}
	require.NoError(t, db.Create(env).Error)
	return h, proj.ID
}

func TestContractPR1_GetProjectRotationOrder(t *testing.T) {
	h, projID := rotationPlanFixturePR1(t)
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/rotation-order", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_GetProjectRotationPlan(t *testing.T) {
	h, projID := rotationPlanFixturePR1(t)
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/rotation-plan", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR1_GetDeploymentRotationPlan(t *testing.T) {
	h, _ := rotationPlanFixturePR1(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rotation-plan", nil))
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
