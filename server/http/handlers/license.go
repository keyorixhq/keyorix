// license.go — GetLicenseStatus: the locally-evaluated offline-license entitlement
// (ADR-065). Read-only; the server never phones home and the evaluation is fail-safe.
package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// LicenseHandler serves the offline-license status.
type LicenseHandler struct {
	coreService *core.KeyorixCore
}

// NewLicenseHandler constructs a LicenseHandler.
func NewLicenseHandler(coreService *core.KeyorixCore) *LicenseHandler {
	return &LicenseHandler{coreService: coreService}
}

// licenseStatusResponse is the read-only view of the evaluated entitlement.
type licenseStatusResponse struct {
	State     string   `json:"state"`
	Licensee  string   `json:"licensee,omitempty"`
	Plan      string   `json:"plan,omitempty"`
	Features  []string `json:"features"`
	Grants    bool     `json:"grants"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	MaxSeats  int      `json:"max_seats,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// GetLicenseStatus returns the freshly-evaluated license status. It never fails on license
// state — a degraded/absent license reports the community baseline, consistent with the
// fail-safe enforcement posture.
func (h *LicenseHandler) GetLicenseStatus(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	st := h.coreService.LicenseStatus()
	resp := licenseStatusResponse{
		State:    string(st.State),
		Licensee: st.Licensee,
		Plan:     st.Plan,
		Features: st.Features,
		Grants:   st.Grants(),
		MaxSeats: st.MaxSeats,
		Reason:   st.Reason,
	}
	if resp.Features == nil {
		resp.Features = []string{}
	}
	if !st.NotAfter.IsZero() {
		resp.ExpiresAt = st.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	sendSuccess(w, resp, "")
}
