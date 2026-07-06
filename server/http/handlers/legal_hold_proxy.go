// legal_hold_proxy.go — server-side endpoints backing RemoteStorage's
// CreateLegalHold/GetActiveLegalHold/UpdateLegalHold (finding #519).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its deployment-wide legal-hold storage calls to whichever upstream server it's
// configured against, through these three routes (registered in
// server/http/router.go under /api/v1/system/legal-hold, gated on the existing
// system.read/system.write RBAC permissions — the SAME credential a RemoteStorage
// client already needs for every other proxied call, e.g. full user CRUD, so this
// introduces no new privilege class). Mirrors dynamic_secrets_proxy.go and
// project_memberships_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/legal_hold.go already uses against a local backend — NO
// legal-hold POLICY decision (the admin-tier placement gate, the
// placer-or-admin-tier lift gate, the required-reason validation, the audit
// events) is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend. This
// file only persists/returns the raw legal_holds row.
//
// This also means the DashboardHandler's existing human-facing
// /api/v1/legal-hold routes (server/http/handlers/legal_hold.go: GetLegalHold/
// PlaceLegalHold/LiftLegalHold) are NOT reused for this proxy: PlaceLegalHold
// there enforces the admin-tier-actor check and required-reason validation, and
// LiftLegalHold enforces the placer-or-admin-tier check, against THIS server's
// own HTTP caller identity — the wrong semantics for a raw storage-primitive
// passthrough, whose caller (the downstream server's own core.KeyorixCore) has
// already run all of that against ITS OWN caller and only needs this server to
// persist/return the resulting row (exactly the same class of mistake the
// human-facing /groups routes were for #514).
//
// models.LegalHold already carries full, correct json tags for every field
// (unlike models.User/ProjectMembership/DynamicSecretConfig, which needed an
// explicit wire-DTO to avoid GORM-only fields silently dropping out of a direct
// marshal) — see internal/storage/store/remote_rotation_policies.go for the same
// direct-marshal precedent used here.
//
// Atomicity note: CreateLegalHold relies on a REAL DB-level partial unique index
// (uniq_legal_holds_active, `released` WHERE released = false — see
// factory.go's ensureLegalHoldActiveIndex and local_legal_hold.go) to reject a
// second concurrent placement — that guarantee is a property of the upstream's
// own database and survives this HTTP hop unchanged, since
// CreateLegalHoldProxy calls the identical storage.Storage primitive against the
// same table. Mirroring #511's ProjectMembership precedent, the unique-index
// rejection (surfaced locally as storage.ErrLegalHoldAlreadyActive) is translated
// into a LEGAL_HOLD_ALREADY_ACTIVE wire code so the client reconstructs the same
// sentinel core.PlaceLegalHold's errors.Is check depends on, rather than
// downgrading it to an opaque error. UpdateLegalHold, by contrast, is a plain
// unconditional Save (local_legal_hold.go) with no conditional-write guarantee to
// preserve — core.LiftLegalHold already re-fetches the hold and checks
// actor/placer eligibility before mutating it, exactly as it does against a
// local backend.
//
// Response envelope: like dynamic_secrets_proxy.go/project_memberships_proxy.go,
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses (its APIResponse/APIError
// types).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// legalHoldAlreadyActiveCode is the machine-readable error code returned when
// storage.CreateLegalHold fails with storage.ErrLegalHoldAlreadyActive (the
// upstream's own DB-level partial-unique-index rejection, local_legal_hold.go) —
// matches internal/storage/store/remote_legal_hold.go's
// legalHoldAlreadyActiveCode constant, the wire contract the RemoteStorage
// client checks for to reconstruct the sentinel client-side.
const legalHoldAlreadyActiveCode = "LEGAL_HOLD_ALREADY_ACTIVE"

// CreateLegalHoldProxy handles POST /api/v1/system/legal-hold. Persists the
// caller's already-fully-built hold row as-is (a raw storage-layer create) — the
// admin-tier placement gate and required-reason validation already ran in the
// CALLING server's own core.PlaceLegalHold before this is ever invoked.
func (h *DashboardHandler) CreateLegalHoldProxy(w http.ResponseWriter, r *http.Request) {
	var body models.LegalHold
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Reason == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "reason is required")
		return
	}
	created, err := h.coreService.Storage().CreateLegalHold(r.Context(), &body)
	if err != nil {
		if errors.Is(err, storage.ErrLegalHoldAlreadyActive) {
			writeRemoteAPIError(w, http.StatusConflict, legalHoldAlreadyActiveCode, storage.ErrLegalHoldAlreadyActive.Error())
			return
		}
		log.Printf("legal-hold proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, created)
}

// legalHoldActiveResponse mirrors GetLegalHold's own human-facing response shape
// ({"active":bool,"hold":...}) so a nil (no active hold) result is distinguished
// from an empty/zero-value row, rather than encoding a nil *models.LegalHold as
// JSON null and forcing the client to special-case that.
type legalHoldActiveResponse struct {
	Active bool              `json:"active"`
	Hold   *models.LegalHold `json:"hold,omitempty"`
}

// GetActiveLegalHoldProxy handles GET /api/v1/system/legal-hold/active.
func (h *DashboardHandler) GetActiveLegalHoldProxy(w http.ResponseWriter, r *http.Request) {
	hold, err := h.coreService.Storage().GetActiveLegalHold(r.Context())
	if err != nil {
		log.Printf("legal-hold proxy: get active failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if hold == nil {
		writeRemoteAPISuccess(w, legalHoldActiveResponse{Active: false})
		return
	}
	writeRemoteAPISuccess(w, legalHoldActiveResponse{Active: true, Hold: hold})
}

// UpdateLegalHoldProxy handles PUT /api/v1/system/legal-hold/{id}. A raw persist
// (storage.Storage.UpdateLegalHold is an unconditional full-row Save, matching
// LocalStorage's own semantics exactly — see the package doc for why there is no
// conditional-write guarantee to preserve here).
func (h *DashboardHandler) UpdateLegalHoldProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid legal hold id")
		return
	}
	var body models.LegalHold
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateLegalHold(r.Context(), &body); err != nil {
		log.Printf("legal-hold proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}
