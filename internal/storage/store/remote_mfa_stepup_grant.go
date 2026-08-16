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
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func newMFAStepUpGrantWire(g *models.MFAStepUpGrant) mfaStepUpGrantWire {
	return mfaStepUpGrantWire{
		ID:        g.ID,
		UserID:    g.UserID,
		ExpiresAt: g.ExpiresAt,
		CreatedAt: g.CreatedAt,
	}
}

func (w mfaStepUpGrantWire) toModel() *models.MFAStepUpGrant {
	return &models.MFAStepUpGrant{
		ID:        w.ID,
		UserID:    w.UserID,
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
	UserID uint `json:"user_id"`
}

// CreateMFAStepUpGrant persists a new MFA step-up grant via
// POST /api/v1/system/mfa/stepup-grants, copying the upstream-assigned
// fields (ID, CreatedAt) back into grant.
func (rs *RemoteStorage) CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/stepup-grants", newMFAStepUpGrantWire(grant))
	if err != nil {
		return fmt.Errorf("failed to create MFA step-up grant: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create MFA step-up grant failed: %s", resp.Error.Error())
	}
	saved, err := decodeMFAStepUpGrantResponse(resp.Data)
	if err != nil {
		return err
	}
	*grant = *saved
	return nil
}

// GetActiveMFAStepUpGrant returns the most recent non-expired MFA step-up
// grant for userID via POST /api/v1/system/mfa/stepup-grants/active.
// Returns (nil, nil) when the server returns null data (no active grant).
// now is accepted only for interface parity with LocalStorage — the
// upstream server ignores any caller-supplied "current time" and always
// uses its own clock (see mfaStepUpGrantActiveWire's doc comment).
func (rs *RemoteStorage) GetActiveMFAStepUpGrant(ctx context.Context, userID uint, _ time.Time) (*models.MFAStepUpGrant, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/mfa/stepup-grants/active", mfaStepUpGrantActiveWire{
		UserID: userID,
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

// DeleteMFAStepUpGrantsFor removes all step-up grants for userID via
// DELETE /api/v1/system/mfa/stepup-grants/{userID}.
func (rs *RemoteStorage) DeleteMFAStepUpGrantsFor(ctx context.Context, userID uint) error {
	path := fmt.Sprintf("/api/v1/system/mfa/stepup-grants/%d", userID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete MFA step-up grants: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete MFA step-up grants failed: %s", resp.Error.Error())
	}
	return nil
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
