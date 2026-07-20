package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineAuditReport_Unauthorized(t *testing.T) {
	h := NewMachineAuditHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetMachineAuditReport(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineAuditReport_EmptyDB(t *testing.T) {
	h := NewMachineAuditHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetMachineAuditReport(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.EqualValues(t, 0, d["total_count"])
}

func TestMachineAuditReportCSV_Unauthorized(t *testing.T) {
	h := NewMachineAuditHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetMachineAuditReportCSV(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineAuditReportCSV_EmptyDB(t *testing.T) {
	h := NewMachineAuditHandler(freshCoreS12(t))
	w := httptest.NewRecorder()
	h.GetMachineAuditReportCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Disposition"), "machine-audit.csv")
	assert.Contains(t, w.Body.String(), "machine_id")
}
