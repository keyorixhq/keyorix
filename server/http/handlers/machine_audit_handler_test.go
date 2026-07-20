package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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

func TestMachineAuditReportCSV_WithMachines(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewMachineAuditHandler(cs)

	now := time.Now().UTC()
	machine := &models.MachineIdentity{Name: "ci-bot", State: "active"}
	require.NoError(t, db.Create(machine).Error)
	cred := &models.MachineIdentityCredential{
		MachineIdentityID: machine.ID,
		Name:              "tok1",
		TokenHash:         "aaabbbccc",
		LastUsedAt:        &now,
	}
	require.NoError(t, db.Create(cred).Error)

	w := httptest.NewRecorder()
	h.GetMachineAuditReportCSV(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "ci-bot")
	lines := strings.Split(strings.TrimSpace(body), "\n")
	assert.Len(t, lines, 2) // header + one data row
}

func TestMachineAuditReport_WithMachines(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewMachineAuditHandler(cs)

	machine := &models.MachineIdentity{Name: "svc-account", State: "active"}
	require.NoError(t, db.Create(machine).Error)

	w := httptest.NewRecorder()
	h.GetMachineAuditReport(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)))
	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.EqualValues(t, 1, d["total_count"])
}
