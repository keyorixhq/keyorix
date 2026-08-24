// remote_break_glass.go — break-glass activations for RemoteStorage (#519).
//
// CreateBreakGlassActivation/GetBreakGlassActivation/ListBreakGlassActivations/
// UpdateBreakGlassActivation/RevokeBreakGlassActivation are thin passthroughs onto
// five new server-side routes under /api/v1/system/break-glass
// (server/http/handlers/break_glass_proxy.go), following the SAME pattern #507/
// #510/#511 established (remote_invitations.go, remote_memberships.go): gated on
// the same broad system.read/system.write RBAC permissions a RemoteStorage
// credential already needs for every other proxied call, so this introduces no
// new privilege class. No break-glass POLICY decision (enablement,
// project-affiliation, emergency-role containment, TTL clamping, the actual JIT
// role grant) is made in these routes — that stays entirely in the CALLING
// server's own internal/core.KeyorixCore (break_glass.go), exactly as it does
// against a local backend.
//
// Before this fix, every one of these methods returned ErrRemoteUnsupported, so
// ActivateBreakGlass/ListBreakGlassActivations/RevokeBreakGlass were completely
// non-functional under storage.type: remote.
//
// Atomicity note (mirrors #511's CreateProjectMembership/#507's
// UpdateProjectInvitation reasoning): local_break_glass.go's
// CreateBreakGlassActivation relies on a REAL DB-level partial unique index
// (uniq_break_glass_active_project_user, ensureBreakGlassActiveIndex, docs/
// security/BUGS.md #104 / PR #670) to reject a second concurrent active
// activation for the same (project_id, user_id) — that guarantee is a property of
// the upstream's own database and survives this HTTP hop unchanged, since
// CreateBreakGlassActivationProxy calls the identical storage.Storage primitive
// against the same table (not a client-side "GET then POST" sequence, which would
// reopen the exact race #104 closed). Likewise, RevokeBreakGlassActivation is a
// single conditional `UPDATE ... WHERE id = ? AND state = 'active'` (not a
// read-then-write) — RevokeBreakGlassActivationProxy calls that same primitive
// directly, so this file's RevokeBreakGlassActivation issues exactly one HTTP
// round trip per call, never a "GET, check state, then PUT" sequence that would
// reintroduce a double-revoke TOCTOU race. UpdateBreakGlassActivation, by
// contrast, has no such conditional-write guarantee even locally (a plain GORM
// Save), so a single passthrough PUT is exact behavioral parity with LocalStorage,
// not a new race introduced by this file.
//
// For the local (GORM) equivalent of everything here see local_break_glass.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// breakGlassActivationWire mirrors models.BreakGlassActivation's fields exactly
// (snake_case), used for both the create/update request body and every response
// (create/get/list) — there is no models.BreakGlassActivation json tag to fall
// back on in a way that survives a direct marshal reliably (a GORM model, like
// models.ProjectInvitation before #507), so — matching membershipWire's/
// invitationWire's reasoning — every field is named explicitly here.
type breakGlassActivationWire struct {
	ID            uint       `json:"id"`
	ProjectID     uint       `json:"project_id"`
	UserID        uint       `json:"user_id"`
	RoleID        uint       `json:"role_id"`
	RoleName      string     `json:"role_name"`
	Justification string     `json:"justification"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedBy     uint       `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func (w breakGlassActivationWire) toModel() *models.BreakGlassActivation {
	return &models.BreakGlassActivation{
		ID:            w.ID,
		ProjectID:     w.ProjectID,
		UserID:        w.UserID,
		RoleID:        w.RoleID,
		RoleName:      w.RoleName,
		Justification: w.Justification,
		State:         w.State,
		ExpiresAt:     w.ExpiresAt,
		CreatedAt:     w.CreatedAt,
		RevokedBy:     w.RevokedBy,
		RevokedAt:     w.RevokedAt,
	}
}

func decodeBreakGlassActivationResponse(data []byte) (*models.BreakGlassActivation, error) {
	var wire breakGlassActivationWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// breakGlassNotActiveCode must match
// server/http/handlers/break_glass_proxy.go's constant of the same name exactly
// — the wire contract RevokeBreakGlassActivation's error-translation logic
// depends on.
const breakGlassNotActiveCode = "BREAK_GLASS_NOT_ACTIVE"

// CreateBreakGlassActivation used to proxy onto POST /api/v1/system/break-glass
// (CreateBreakGlassActivationProxy), deleted in the G80 liveness sweep — no live
// caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) CreateBreakGlassActivation(_ context.Context, _ *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	return nil, errUnsupportedRemote
}

// GetBreakGlassActivation retrieves an activation by ID via GET
// /api/v1/system/break-glass/{id}.
func (rs *RemoteStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	path := fmt.Sprintf("/api/v1/system/break-glass/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get break-glass activation: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get break-glass activation failed: %s", resp.Error.Error())
	}
	return decodeBreakGlassActivationResponse(resp.Data)
}

// ListBreakGlassActivations lists a project's activations via GET
// /api/v1/system/break-glass?project_id=X.
func (rs *RemoteStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/break-glass?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list break-glass activations: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list break-glass activations failed: %s", resp.Error.Error())
	}
	var result struct {
		Activations []breakGlassActivationWire `json:"activations"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.BreakGlassActivation, 0, len(result.Activations))
	for _, w := range result.Activations {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// UpdateBreakGlassActivation used to proxy onto PUT /api/v1/system/break-glass/{id}
// (UpdateBreakGlassActivationProxy), deleted in the G80 liveness sweep — no live
// caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) UpdateBreakGlassActivation(_ context.Context, _ *models.BreakGlassActivation) error {
	return errUnsupportedRemote
}

// breakGlassRevokeRequest is RevokeBreakGlassActivation's request body, matching
// server/http/handlers/break_glass_proxy.go's breakGlassRevokeProxyRequest.
type breakGlassRevokeRequest struct {
	RevokedBy uint      `json:"revoked_by"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevokeBreakGlassActivation atomically transitions activation id from active to
// revoked via POST /api/v1/system/break-glass/{id}/revoke, preserving
// LocalStorage's exact conditional-update semantics end-to-end: the server
// performs the SAME conditional `UPDATE ... WHERE id = ? AND state = 'active'`
// write local_break_glass.go's RevokeBreakGlassActivation does — NOT a
// client-side "GET then check state then PUT" sequence, which would reintroduce
// the exact double-revoke TOCTOU race this method exists to close (two
// concurrent revoke requests both observing "active" before either writes). One
// HTTP round trip maps to one atomic server-side conditional UPDATE.
func (rs *RemoteStorage) RevokeBreakGlassActivation(ctx context.Context, id, revokedBy uint, revokedAt time.Time) error {
	path := fmt.Sprintf("/api/v1/system/break-glass/%d/revoke", id)
	resp, err := rs.client.Post(ctx, path, breakGlassRevokeRequest{RevokedBy: revokedBy, RevokedAt: revokedAt})
	if err != nil {
		// Same reasoning as CreateBreakGlassActivation above: makeRequest turns
		// RevokeBreakGlassActivationProxy's 409 Conflict into a non-nil error
		// before resp is populated, so the not-active signal must be recovered
		// from the *remote.HTTPError itself, reconstructing the SAME
		// storage.ErrBreakGlassNotActive sentinel a losing racer (or a caller
		// revoking an already-revoked/expired activation) depends on.
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) && httpErr.ErrorType == breakGlassNotActiveCode {
			return fmt.Errorf("%w: %s", storage.ErrBreakGlassNotActive, httpErr.Message)
		}
		return fmt.Errorf("failed to revoke break-glass activation: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("revoke break-glass activation failed: %s", resp.Error.Error())
	}
	return nil
}
