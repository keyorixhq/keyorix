package handlers

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
)

func TestLicenseHandler_RequiresUserContext(t *testing.T) {
	db := openTestDB(t)
	h := NewLicenseHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/license/status", nil)
	w := httptest.NewRecorder()
	h.GetLicenseStatus(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLicenseHandler_NoLicense_ReportsBaseline(t *testing.T) {
	db := openTestDB(t)
	// No gate set → community baseline (the nil-gate is valid).
	h := NewLicenseHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/license/status", nil))
	w := httptest.NewRecorder()
	h.GetLicenseStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"state":"none"`)
	assert.Contains(t, body, `"grants":false`)
}

func TestLicenseHandler_ActiveLicense_ReportsFeatures(t *testing.T) {
	db := openTestDB(t)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))

	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := trust.NewRegistry()
	_ = reg.Add(trust.PurposeLicense, "license-2026", pub)
	token, err := license.Issue(license.License{
		Licensee: "ACME GmbH", Plan: "enterprise-airgap",
		Features: []string{"airgap_updates"},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyID: "license-2026",
	}, priv)
	assert.NoError(t, err)
	c.SetLicenseGate(license.NewGate(token, reg, "", 0))

	h := NewLicenseHandler(c)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/license/status", nil))
	w := httptest.NewRecorder()
	h.GetLicenseStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"state":"active"`)
	assert.Contains(t, body, `"grants":true`)
	assert.Contains(t, body, "airgap_updates")
	assert.Contains(t, body, "ACME GmbH")
	// The plaintext token must never appear in the status response.
	assert.False(t, strings.Contains(body, token), "license token must not be echoed in status")
}
