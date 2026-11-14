package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

// Contract tests for the DYNAMIC-ADMIN-DSN-1 operations. They reuse the
// fixture of openapi_contract_pr1_test.go and are named in contracttest's
// exercisingTests registry.

func TestContractDynamicAdminDSN_UpdateDynamicSecretConfigAdminDSN(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	cfg := mkDynamicSecretConfigPR1(t, cs, projID, envID)

	body, _ := json.Marshal(map[string]any{"admin_dsn": "postgres://admin:n3w-s3cr3t@db.internal:5432/app"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/1/admin-dsn", bytes.NewReader(body)),
		"id", machineUintToStr(cfg.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateConfigAdminDSN(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "n3w-s3cr3t", "the new DSN must never be echoed back")
}

func TestContractDynamicAdminDSN_ListDynamicSecretConfigsWithRefusedAdminDSN(t *testing.T) {
	h, cs, projID, envID := dynamicSecretFixturePR1(t)
	mkDynamicSecretConfigPR1(t, cs, projID, envID)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/refused-admin-dsn?project_id="+machineUintToStr(projID), nil))
	w := httptest.NewRecorder()
	h.ListConfigsWithRefusedAdminDSN(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
