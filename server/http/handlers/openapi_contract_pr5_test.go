// openapi_contract_pr5_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 5 (secret bulk/rotation/export/import/scan/hygiene)
// added response schemas for. Each test below drives the real handler through a happy
// path and calls contracttest.AssertOpenAPIResponse so the operation moves from
// "pending" to genuinely enforced — see CLAUDE.md's "a mechanism must be validated
// against a failure that actually happened" and PR 2/PR 4's identical convention
// (openapi_contract_pr2_test.go / openapi_contract_pr4_test.go), reused here: withUserCtx,
// withChiParam, freshCoreS12WithAdmin. Each test is self-contained (its own fixture)
// rather than grafted onto an existing test, so this batch is auditable as one unit.
package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

// withChiParamsPR5 sets any number of chi URL params on the request.
func withChiParamsPR5(r *http.Request, kv ...string) *http.Request {
	rctx := chi.NewRouteContext()
	for i := 0; i+1 < len(kv); i += 2 {
		rctx.URLParams.Add(kv[i], kv[i+1])
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// pr5SecretFixture builds a SecretHandler against freshCoreS12WithAdmin's DB and seeds
// a project + environment. Returns the handler, core service, db, project ID, env ID.
func pr5SecretFixture(t *testing.T) (*SecretHandler, *core.KeyorixCore, *gorm.DB, uint, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "pr5-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{ProjectID: proj.ID, Name: "pr5-env"}
	require.NoError(t, db.Create(env).Error)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, cs, db, proj.ID, env.ID
}

func pr5CreateSecret(t *testing.T, cs *core.KeyorixCore, projID, envID uint, name string) *models.SecretNode {
	t.Helper()
	s, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: name, Value: []byte("pr5-value"), ProjectID: projID, EnvironmentID: envID,
		Type: "static", CreatedBy: "pr5-admin", OwnerID: 1,
	})
	require.NoError(t, err)
	return s
}

func pr5IDStr(id uint) string { return fmt.Sprintf("%d", id) }

func TestContractPR5_ListExpiringSecrets(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-expiring-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/expiring", nil),
		"id", pr5IDStr(projID),
	))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_ListOrphanedSecrets(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-orphaned-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/orphaned", nil),
		"id", pr5IDStr(projID),
	))
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_SecretNameConformance(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-conformance-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/name-conformance", nil),
		"id", pr5IDStr(projID),
	))
	w := httptest.NewRecorder()
	h.SecretNameConformance(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_DeploymentSecretNameConformance(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-deployment-conformance-target")

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/name-conformance", nil))
	w := httptest.NewRecorder()
	h.DeploymentSecretNameConformance(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_ReassignSecretOwner(t *testing.T) {
	h, cs, db, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-reassign-target")
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "pr5-new-owner", AccountState: "active"}).Error)

	body, _ := json.Marshal(map[string]any{"from_owner_id": 1, "to_owner_id": 2})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/reassign-owner", bytes.NewReader(body)),
		"id", pr5IDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_BulkRotateSecrets(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-bulk-rotate-target")

	body, _ := json.Marshal(map[string]any{"environment_id": envID})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate", bytes.NewReader(body)),
		"id", pr5IDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_BulkRenameSecrets(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-bulk-rename-target")

	body, _ := json.Marshal(map[string]any{
		"renames": []map[string]any{{"id": secret.ID, "new_name": "pr5-bulk-rename-target-2"}},
		"dry_run": true,
	})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", bytes.NewReader(body)),
		"id", pr5IDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.BulkRenameSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_BulkDeleteSecrets(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-bulk-delete-target")

	body, _ := json.Marshal(map[string]any{"secret_ids": []uint{secret.ID}})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-delete", bytes.NewReader(body)),
		"id", pr5IDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_RenderTemplate(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-render-target")

	body, _ := json.Marshal(map[string]any{"template": "static template, no references"})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body)),
		"id", pr5IDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_RotateSecret(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-rotate-target")

	body, _ := json.Marshal(map[string]any{"new_value": "pr5-new-value"})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotate", bytes.NewReader(body)),
		"id", pr5IDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_SimulateRotation(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-simulate-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotation/simulate", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.SimulateRotation(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_SetAutoRotate(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-autorotate-target")

	body, _ := json.Marshal(map[string]any{"enabled": true})
	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/auto-rotate", bytes.NewReader(body)),
		"id", pr5IDStr(secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetAutoRotate(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_AuditTrail(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-audit-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/audit", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_OwnershipHistory(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-ownership-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/ownership-history", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.OwnershipHistory(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// pr5SelfSignedPEM mints a self-signed EC certificate valid for a wide window
// (several years) so this test never becomes a clock-bomb as wall-clock drifts.
func pr5SelfSignedPEM(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(5 * 365 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestContractPR5_GetSecretCertificate(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	certPEM := pr5SelfSignedPEM(t, "pr5-cert.example.test")
	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "pr5-cert-target", Value: certPEM, ProjectID: projID, EnvironmentID: envID,
		Type: "certificate", CreatedBy: "pr5-admin", OwnerID: 1,
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/certificate", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_GetBlastRadius(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	pr5CreateSecret(t, cs, projID, envID, "pr5-blast-radius-target")
	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "pr5-blast-radius-source", Value: []byte("v"), ProjectID: projID, EnvironmentID: envID,
		Type: "static", CreatedBy: "pr5-admin", OwnerID: 1,
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/blast-radius", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetBlastRadius(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_GetSecretRisk(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	secret := pr5CreateSecret(t, cs, projID, envID, "pr5-risk-target")

	req := withUserCtx(withChiParamsPR5(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/risk", nil),
		"id", pr5IDStr(secret.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR5_GetQuotaReport(t *testing.T) {
	h, cs, _, projID, envID := pr5SecretFixture(t)
	maxReads := 10
	_, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "pr5-quota-target", Value: []byte("v"), ProjectID: projID, EnvironmentID: envID,
		Type: "static", CreatedBy: "pr5-admin", OwnerID: 1, MaxReads: &maxReads,
	})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/quota-report", nil))
	w := httptest.NewRecorder()
	h.GetQuotaReport(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
