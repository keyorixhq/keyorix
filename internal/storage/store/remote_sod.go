// remote_sod.go — separation-of-duties (SoD) policies for RemoteStorage
// (finding #519).
//
// CreateSoDPolicy/GetSoDPolicy/ListSoDPolicies/DeleteSoDPolicy are thin
// passthroughs onto four new server-side routes under
// /api/v1/system/sod-policies (server/http/handlers/sod_proxy.go), following
// the SAME pattern #507/#510/#511 established (remote_invitations.go,
// remote_auth.go, remote_memberships.go): gated on the same broad
// system.read/system.write RBAC permissions a RemoteStorage credential already
// needs for every other proxied call, so this introduces no new privilege
// class. No SoD-policy POLICY decision (name/permission-pair validation, the
// audit-log event, the violation-detection scan itself) is made in these
// routes — that stays entirely in the CALLING server's own
// internal/core.KeyorixCore (sod.go), exactly as it does against a local
// backend.
//
// Before this fix, every one of these methods returned ErrRemoteUnsupported,
// so a downstream server booted with storage.type: remote could neither manage
// SoD policies (internal/core/sod.go's CreateSoDPolicy/ListSoDPolicies/
// DeleteSoDPolicy) nor evaluate its own preventive grant-time gates
// (requireNoSoDViolation and its group/machine/grant-set siblings, #419 —
// every direct role-grant choke point calls ListSoDPolicies first) against a
// remote storage backend at all.
//
// Atomicity note: the storage.Storage interface exposes no Update method for
// SoDPolicy at all (a policy is immutable once created — retire it via
// DeleteSoDPolicy and create a replacement instead), and none of the four
// methods here rely on a LockXForUpdate + conditional-update pattern locally
// (local_sod.go's Create/Get/List are plain GORM Create/First/Find, and Delete
// is a plain GORM Delete keyed by primary key, whose RowsAffected == 0 check
// only ever races against another delete of the SAME row — both outcomes are
// "the row is gone," not a lost update). So a single passthrough per call,
// exactly mirroring local_sod.go's own semantics, introduces no NEW race and
// needs no additional atomic storage-interface primitive.
//
// models.SoDPolicy already carries full explicit json tags (unlike
// models.DynamicSecretConfig/models.ProjectMembership before their own proxy
// fixes), so no separate wire-DTO struct is needed here — the model is
// marshaled/unmarshaled directly, same as remote_rotation_policies.go's
// pre-existing (non-system-proxy) precedent.
//
// For the local (GORM) equivalent of everything here see local_sod.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSoDPolicy persists an already-validated policy row (name/permission-pair
// validation is done by the CALLING core.KeyorixCore before this is invoked,
// exactly as core.CreateSoDPolicy builds one for LocalStorage) via POST
// /api/v1/system/sod-policies.
func (rs *RemoteStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/sod-policies", p)
	if err != nil {
		return nil, fmt.Errorf("failed to create SoD policy: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create SoD policy failed: %s", resp.Error.Error())
	}
	var result models.SoDPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSoDPolicy retrieves a policy by ID via GET /api/v1/system/sod-policies/{id}.
func (rs *RemoteStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	path := fmt.Sprintf("/api/v1/system/sod-policies/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get SoD policy: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get SoD policy failed: %s", resp.Error.Error())
	}
	var result models.SoDPolicy
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListSoDPolicies lists every policy via GET /api/v1/system/sod-policies.
func (rs *RemoteStorage) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/sod-policies")
	if err != nil {
		return nil, fmt.Errorf("failed to list SoD policies: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list SoD policies failed: %s", resp.Error.Error())
	}
	var result struct {
		Policies []*models.SoDPolicy `json:"policies"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Policies, nil
}

// DeleteSoDPolicy retires a policy via DELETE /api/v1/system/sod-policies/{id}.
func (rs *RemoteStorage) DeleteSoDPolicy(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/sod-policies/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete SoD policy: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete SoD policy failed: %s", resp.Error.Error())
	}
	return nil
}
