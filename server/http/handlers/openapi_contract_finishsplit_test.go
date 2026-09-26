// openapi_contract_finishsplit_test.go — ADR-074 registry population for the operations
// FINISH-SPLIT's census-gaps batch (docs/cli-split-inventory-census.md) added response schemas
// for: getUsageReport, getBillingReport, migrateUserToMachine — the last 3 command-census gaps
// ported to the thin CLI. Each test drives the real handler through a happy path and calls
// contracttest.AssertOpenAPIResponse so the operation moves from "pending" to genuinely enforced
// (PR 2/PR 4/PR 5's identical convention). Reuses existing fixtures rather than redefining them:
// newUsageHandlerDB/getUsage (admin_usage_test.go), newBillingTestDB/licensedBillingCore/
// billingReportURL (admin_billing_test.go), newMigrateHandler (machine_identities_migrate_test.go).
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractFinishSplit_GetUsageReport(t *testing.T) {
	h := newUsageHandlerDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage?days=7", nil)
	w := httptest.NewRecorder()
	h.GetUsageReport(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractFinishSplit_GetBillingReport(t *testing.T) {
	db := newBillingTestDB(t)
	require.NoError(t, db.Create(&models.Project{Name: "acme-prod"}).Error)

	h := NewAdminBillingHandler(licensedBillingCore(t, db))
	req := httptest.NewRequest(http.MethodGet,
		billingReportURL("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", ""), nil)
	w := httptest.NewRecorder()
	h.GetBillingReport(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractFinishSplit_MigrateUserToMachine(t *testing.T) {
	h, _ := newMigrateHandler(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/machine-identities/migrate-from-user",
			strings.NewReader(`{"username":"ci-bot"}`)), "id", "3"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.MigrateUserToMachine(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}
