// remote_risk_exceptions.go — risk-exception storage primitives for
// RemoteStorage (finding #519): thin passthroughs onto four new server-side
// routes under /api/v1/system/risk-exceptions
// (server/http/handlers/risk_exceptions_proxy.go), mirroring the dynamic-secrets
// (round-116) and project-membership (#511) proxy patterns exactly: gated on the
// SAME broad system.read/system.write RBAC permissions a RemoteStorage
// credential already needs for every other proxied call, so this introduces no
// new privilege class.
//
// No risk-exception POLICY decision (title/category/justification validation,
// the expiry-in-the-future and max-365-day-sunset bounds, dual-control approval,
// or the effective-status computation from the revoked flag + expiry) is made in
// these routes — that stays entirely in the CALLING server's own
// internal/core.KeyorixCore (internal/core/risk_exceptions.go), exactly as it
// does against a local backend.
//
// Atomicity (investigated, not assumed): local_risk_exceptions.go's
// UpdateRiskException is an unconditional full-row `Save`, not a
// conditional/optimistic-concurrency write — there is no
// LockXForUpdate/SELECT ... FOR UPDATE anywhere in this subsystem, unlike, say,
// UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'` or #511's
// duplicate-active-membership unique-index translation. internal/core's
// RevokeRiskException/ApproveRiskException already re-fetch the exception and
// check its revoked/approved/expiry state before mutating it — a check-then-act
// sequence with exactly the same (small, pre-existing, accepted) race window
// against a local backend as against this proxy. This fix preserves that
// behavior exactly rather than introducing a stricter guarantee the local
// backend itself doesn't have — no new atomic storage-interface primitive is
// needed here.
//
// For the local (GORM) equivalent of every primitive here see
// local_risk_exceptions.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// riskExceptionWire mirrors riskExceptionProxyWire in
// server/http/handlers/risk_exceptions_proxy.go exactly.
type riskExceptionWire struct {
	ID            uint       `json:"id"`
	Title         string     `json:"title"`
	Category      string     `json:"category"`
	Reference     string     `json:"reference,omitempty"`
	Justification string     `json:"justification"`
	CreatedBy     uint       `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Revoked       bool       `json:"revoked"`
	RevokedBy     uint       `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	Approved      bool       `json:"approved"`
	ApprovedBy    uint       `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
}

func newRiskExceptionWire(e *models.RiskException) riskExceptionWire {
	return riskExceptionWire{
		ID:            e.ID,
		Title:         e.Title,
		Category:      e.Category,
		Reference:     e.Reference,
		Justification: e.Justification,
		CreatedBy:     e.CreatedBy,
		CreatedAt:     e.CreatedAt,
		ExpiresAt:     e.ExpiresAt,
		Revoked:       e.Revoked,
		RevokedBy:     e.RevokedBy,
		RevokedAt:     e.RevokedAt,
		Approved:      e.Approved,
		ApprovedBy:    e.ApprovedBy,
		ApprovedAt:    e.ApprovedAt,
	}
}

func (w riskExceptionWire) toModel() *models.RiskException {
	return &models.RiskException{
		ID:            w.ID,
		Title:         w.Title,
		Category:      w.Category,
		Reference:     w.Reference,
		Justification: w.Justification,
		CreatedBy:     w.CreatedBy,
		CreatedAt:     w.CreatedAt,
		ExpiresAt:     w.ExpiresAt,
		Revoked:       w.Revoked,
		RevokedBy:     w.RevokedBy,
		RevokedAt:     w.RevokedAt,
		Approved:      w.Approved,
		ApprovedBy:    w.ApprovedBy,
		ApprovedAt:    w.ApprovedAt,
	}
}

func decodeRiskExceptionResponse(data []byte) (*models.RiskException, error) {
	var wire riskExceptionWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// CreateRiskException persists an already-validated exception row (the
// title/category/justification/expiry checks already ran in the CALLING
// server's own core.CreateRiskException) via POST
// /api/v1/system/risk-exceptions.
func (rs *RemoteStorage) CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/risk-exceptions", newRiskExceptionWire(e))
	if err != nil {
		return nil, fmt.Errorf("failed to create risk exception: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create risk exception failed: %s", resp.Error.Error())
	}
	return decodeRiskExceptionResponse(resp.Data)
}

// ListRiskExceptions lists risk exceptions (newest-first) via GET
// /api/v1/system/risk-exceptions?active_only=true|false. When activeOnly is set,
// revoked rows are excluded (expiry is computed in the calling server's own
// core, not at the storage layer) — matching local_risk_exceptions.go's contract
// exactly.
func (rs *RemoteStorage) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	q := url.Values{}
	if activeOnly {
		q.Set("active_only", "true")
	}
	path := "/api/v1/system/risk-exceptions"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list risk exceptions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list risk exceptions failed: %s", resp.Error.Error())
	}
	var result struct {
		Exceptions []riskExceptionWire `json:"exceptions"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.RiskException, 0, len(result.Exceptions))
	for _, w := range result.Exceptions {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// GetRiskException retrieves an exception by ID via GET
// /api/v1/system/risk-exceptions/{id}.
func (rs *RemoteStorage) GetRiskException(ctx context.Context, id uint) (*models.RiskException, error) {
	path := fmt.Sprintf("/api/v1/system/risk-exceptions/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk exception: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get risk exception failed: %s", resp.Error.Error())
	}
	return decodeRiskExceptionResponse(resp.Data)
}

// UpdateRiskException persists the full exception row (revoke/approve
// bookkeeping) via PUT /api/v1/system/risk-exceptions/{id}. Matches
// LocalStorage's own unconditional full-row Save semantics exactly — see the
// package doc for why no conditional write is needed here.
func (rs *RemoteStorage) UpdateRiskException(ctx context.Context, e *models.RiskException) error {
	path := fmt.Sprintf("/api/v1/system/risk-exceptions/%d", e.ID)
	resp, err := rs.client.Put(ctx, path, newRiskExceptionWire(e))
	if err != nil {
		return fmt.Errorf("failed to update risk exception: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update risk exception failed: %s", resp.Error.Error())
	}
	return nil
}
