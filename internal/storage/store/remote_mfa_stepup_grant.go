// remote_mfa_stepup_grant.go — MFAStepUpGrant persistence for RemoteStorage.
// These proxy the three MFAStepUpGrant storage primitives to the server-side
// endpoints in server/http/handlers/mfa_stepup_proxy.go, following the same
// pattern as the other RemoteStorage proxy methods in remote_mfa.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mfaStepUpGrantWire mirrors models.MFAStepUpGrant on the wire.
type mfaStepUpGrantWire struct {
	ID        uint                    `json:"id"`
	UserID    uint                    `json:"user_id"`
	Purpose   models.MFAStepUpPurpose `json:"purpose"`
	ExpiresAt time.Time               `json:"expires_at"`
	CreatedAt time.Time               `json:"created_at"`
}

func (w mfaStepUpGrantWire) toModel() *models.MFAStepUpGrant {
	return &models.MFAStepUpGrant{
		ID:        w.ID,
		UserID:    w.UserID,
		Purpose:   w.Purpose,
		ExpiresAt: w.ExpiresAt,
		CreatedAt: w.CreatedAt,
	}
}

func decodeMFAStepUpGrantResponse(data []byte) (*models.MFAStepUpGrant, error) {
	var wire mfaStepUpGrantWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse MFA step-up grant response: %w", err)
	}
	return wire.toModel(), nil
}

// mfaStepUpGrantActiveWire is the request body for GetActiveMFAStepUpGrant.
// It no longer carries `now` on the wire (G-wave6, same fix as
// remote_mfa.go's mfaChallengeLookupWire): the upstream server always uses
// its own clock for the expiry comparison instead of trusting a
// caller-supplied value.
type mfaStepUpGrantActiveWire struct {
	UserID  uint                    `json:"user_id"`
	Purpose models.MFAStepUpPurpose `json:"purpose"`
}

// CreateMFAStepUpGrant used to proxy onto POST /api/v1/system/mfa/stepup-grants
// (CreateMFAStepUpGrantProxy), deleted in the G80 liveness sweep — no live
// caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) CreateMFAStepUpGrant(_ context.Context, _ *models.MFAStepUpGrant) error {
	return remoteUnsupported("CreateMFAStepUpGrant")
}

// GetActiveMFAStepUpGrant returns the most recent non-expired MFA step-up
// grant for userID AND purpose via POST
// /api/v1/system/mfa/stepup-grants/active. Returns (nil, nil) when the server
// returns null data (no active grant for that exact purpose). now is accepted
// only for interface parity with LocalStorage — the upstream server ignores
// any caller-supplied "current time" and always uses its own clock (see
// mfaStepUpGrantActiveWire's doc comment).
func (rs *RemoteStorage) GetActiveMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, _ time.Time) (*models.MFAStepUpGrant, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/stepup-grants/active", mfaStepUpGrantActiveWire{
		UserID:  userID,
		Purpose: purpose,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get active MFA step-up grant: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get active MFA step-up grant failed: %s", resp.Error.Error())
	}
	// data is null when no active grant exists.
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, nil
	}
	return decodeMFAStepUpGrantResponse(resp.Data)
}

// DeleteMFAStepUpGrantsFor is not supported in remote storage (#1480). No
// internal/core caller ever existed for it — server/main.go's own scheduled
// pruning comment names this directly: "DeleteMFAStepUpGrantsFor exists but
// is only reachable via the RemoteStorage proxy, never called from a local
// maintenance path" (grants are instead cleaned up by TTL via
// PruneMFAStepUpGrants). Its only real caller, repo-wide, was its own
// /system proxy handler, now also removed (DeleteMFAStepUpGrantsForProxy,
// server/http/handlers/mfa_stepup_proxy.go).
func (rs *RemoteStorage) DeleteMFAStepUpGrantsFor(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteMFAStepUpGrantsFor")
}

// mfaStepUpGrantPruneWire is the request body for PruneMFAStepUpGrants.
type mfaStepUpGrantPruneWire struct {
	Before time.Time `json:"before"`
}

// PruneMFAStepUpGrants removes expired MFA step-up grant rows via
// POST /api/v1/system/mfa/stepup-grants/prune (store-mfa-002 maintenance
// sweep). The upstream handler re-derives/clamps the effective cutoff itself
// (mirroring PruneLoginAttemptsProxy's CORE-RATE-003 defense) rather than
// trusting `before` verbatim, so this passthrough is safe even though `before`
// crosses the wire.
func (rs *RemoteStorage) PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/stepup-grants/prune", mfaStepUpGrantPruneWire{Before: before})
	if err != nil {
		return 0, fmt.Errorf("failed to prune MFA step-up grants: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("prune MFA step-up grants failed: %s", resp.Error.Error())
	}
	var result struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Deleted, nil
}
