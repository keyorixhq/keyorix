// remote_legal_hold.go — deployment-wide legal hold (ISO 27001 A.5.34 /
// eDiscovery) for RemoteStorage (finding #519).
//
// CreateLegalHold/GetActiveLegalHold/UpdateLegalHold are thin passthroughs onto
// three new server-side routes under /api/v1/system/legal-hold
// (server/http/handlers/legal_hold_proxy.go), following the SAME pattern
// #507/#510/#511 established: gated on the same broad system.read/system.write
// RBAC permissions a RemoteStorage credential already needs for every other
// proxied call, so this introduces no new privilege class. No legal-hold POLICY
// decision (the admin-tier placement gate, the placer-or-admin-tier lift gate,
// the required-reason validation, the audit events) is made in these routes —
// that stays entirely in the CALLING server's own internal/core.KeyorixCore
// (legal_hold.go), exactly as it does against a local backend.
//
// Before this fix, every one of these three methods returned
// ErrRemoteUnsupported, so core.PlaceLegalHold/core.LiftLegalHold/
// core.IsLegalHoldActive — and therefore every purge/prune scheduler's
// legalHoldGuard check — hard-failed under storage.type: remote: the purge jobs
// fail SAFE on that error (they skip the purge rather than risk deleting
// held data), so the practical effect was "purges never run at all" rather than
// silent data loss, but the legal-hold control itself was completely
// non-functional for a remote-storage deployment.
//
// Atomicity note (mirrors #511's ProjectMembership precedent):
// local_legal_hold.go's CreateLegalHold relies on a REAL DB-level partial unique
// index (uniq_legal_holds_active, `released` WHERE released = false) to reject a
// second concurrent placement — that guarantee is a property of the upstream's
// own database and survives this HTTP hop unchanged, since CreateLegalHoldProxy
// calls the identical storage.Storage primitive against the same table. The
// resulting storage.ErrLegalHoldAlreadyActive sentinel is translated into a
// LEGAL_HOLD_ALREADY_ACTIVE wire code (see legalHoldAlreadyActiveCode below) so
// core.PlaceLegalHold's own errors.Is check is preserved across this HTTP hop.
// UpdateLegalHold, by contrast, has no conditional-write guarantee even locally
// (local_legal_hold.go's implementation is a plain GORM Save; the
// actor/placer-eligibility check is enforced by the CALLING core.KeyorixCore
// before it ever calls storage.UpdateLegalHold), so a single passthrough PUT is
// exact behavioral parity with LocalStorage, not a new race introduced here.
//
// models.LegalHold already carries full, correct json tags for every field
// (unlike models.User/ProjectMembership/DynamicSecretConfig, which needed an
// explicit wire-DTO to avoid GORM-only fields silently dropping out of a direct
// marshal), so this marshals/unmarshals the model directly — the same
// direct-marshal precedent remote_rotation_policies.go already uses.
//
// For the local (GORM) equivalent of everything here see local_legal_hold.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// legalHoldAlreadyActiveCode is the machine-readable error code
// CreateLegalHoldProxy returns when the upstream's own DB-level unique-index
// rejection (isUniqueConstraintErr, local_legal_hold.go) fires — the wire-level
// signal RemoteStorage.CreateLegalHold uses to reconstruct the same
// storage.ErrLegalHoldAlreadyActive sentinel core.PlaceLegalHold's errors.Is
// check depends on, so that check-and-translate behavior is preserved across
// this HTTP hop and not silently downgraded to an opaque error.
const legalHoldAlreadyActiveCode = "LEGAL_HOLD_ALREADY_ACTIVE"

// CreateLegalHold persists an already-built hold row (Reason/PlacedBy/PlacedAt/
// Released are all computed by the CALLING core.KeyorixCore before this is
// invoked, exactly as it builds one for LocalStorage) via POST
// /api/v1/system/legal-hold.
func (rs *RemoteStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/legal-hold", h)
	if err != nil {
		// #501: makeRequest turns EVERY 4xx/5xx response (including
		// CreateLegalHoldProxy's 409 Conflict) into a non-nil error before resp
		// is ever populated, so the already-active signal must be recovered
		// from the *remote.HTTPError itself (its ErrorType), not from
		// resp.Error — reconstructing the SAME storage.ErrLegalHoldAlreadyActive
		// sentinel core.PlaceLegalHold's errors.Is check depends on.
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) && httpErr.ErrorType == legalHoldAlreadyActiveCode {
			return nil, fmt.Errorf("%w: %s", storage.ErrLegalHoldAlreadyActive, httpErr.Message)
		}
		return nil, fmt.Errorf("failed to create legal hold: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create legal hold failed: %s", resp.Error.Error())
	}
	var result models.LegalHold
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// legalHoldActiveResponse mirrors GetActiveLegalHoldProxy's wire shape
// ({"active":bool,"hold":...}) — see that handler's doc comment for why a nil
// (no active hold) result is signalled explicitly rather than as JSON null.
type legalHoldActiveResponse struct {
	Active bool              `json:"active"`
	Hold   *models.LegalHold `json:"hold,omitempty"`
}

// GetActiveLegalHold returns the current un-released hold, or (nil, nil) when
// none is active, via GET /api/v1/system/legal-hold/active.
func (rs *RemoteStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/legal-hold/active")
	if err != nil {
		return nil, fmt.Errorf("failed to get active legal hold: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get active legal hold failed: %s", resp.Error.Error())
	}
	var result legalHoldActiveResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if !result.Active {
		return nil, nil
	}
	return result.Hold, nil
}

// UpdateLegalHold persists a hold's current state (e.g. LiftLegalHold's
// Released/ReleasedBy/ReleasedAt/ReleaseReason) via PUT
// /api/v1/system/legal-hold/{id} — a single round trip mapping directly onto
// local_legal_hold.go's plain Save (see the package doc: there is no
// conditional-write guarantee to preserve here).
func (rs *RemoteStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	path := fmt.Sprintf("/api/v1/system/legal-hold/%d", h.ID)
	resp, err := rs.client.Put(ctx, path, h)
	if err != nil {
		return fmt.Errorf("failed to update legal hold: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update legal hold failed: %s", resp.Error.Error())
	}
	return nil
}
