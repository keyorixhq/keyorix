// remote_secrets.go — Secret node and version operations for RemoteStorage.
//
// Covers: CreateSecret, GetSecret, GetSecretByName, UpdateSecret, DeleteSecret,
//
//	ListSecrets, CreateSecretVersion, GetSecretVersion, GetSecretVersions,
//	GetLatestSecretVersion, ListSecretVersions, IncrementSecretReadCount.
//
// All operations proxy to the Keyorix REST API via the embedded HTTPClient.
// For the local (GORM) equivalent see local_secrets.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Wire DTOs (#496) ---
//
// models.SecretNode carries no json tags at all, so marshaling it directly (as
// CreateSecret/UpdateSecret used to) sends Go field names verbatim: "ProjectID",
// "EnvironmentID", "MaxReads", etc. server/http/handlers/secrets_crud.go's
// CreateSecret/UpdateSecret handlers decode into their own snake_case DTOs.
// encoding/json's case-insensitive decode fallback only saves single-word fields
// ("Name"/"name", "Type"/"type", "Classification"/"classification" — no
// underscore, so they happen to still match); every underscore-separated field —
// project_id, environment_id, max_reads, clear_expiration — does NOT
// case-insensitively equal its PascalCase Go counterpart and was silently
// dropped, landing at its zero value server-side (confirmed empirically by the
// existing TestRemoteStorage_SuccessFieldFix_RealServerRoundTrip end-to-end test
// in server/http, which already had to work around the MaxReads/max_reads gap by
// asserting on UpdatedAt instead of the field it actually changed).
//
// Note what is deliberately NOT sent, in both directions:
//   - CreateSecret: "value" (required by the handler) IS now sent (#499, closing
//     the residual gap #496 left open) via the optional plaintextValue variadic
//     on storage.Storage.CreateSecret — see the interface doc
//     (internal/core/storage/interface.go) for why it is a call argument rather
//     than a models.SecretNode field. Sent unconditionally required (no
//     omitempty): the handler always requires it, and core.CreateSecret always
//     has a value to offer (CreateSecretRequest.Value itself is
//     validate:"required").
//   - CreateSecret: "tags". core.CreateSecret applies create-time tags via a
//     separate SetSecretTags storage call (already documented as
//     remote-unsupported below), never through the SecretNode passed to
//     CreateSecret, so there is nothing to forward here either.
//   - UpdateSecret: "value" (optional). UpdateSecret has no equivalent
//     plaintextValue channel — value changes still go through
//     storeNextSecretVersion/CreateSecretVersion, not UpdateSecret's own
//     SecretNode argument. Left as a documented residual gap; UpdateSecret was
//     out of #499's scope (CreateUser/CreateSecret only).
type secretCreateWireRequest struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	ProjectID     uint   `json:"project_id"`
	EnvironmentID uint   `json:"environment_id"`
	Type          string `json:"type"`
	MaxReads      *int   `json:"max_reads,omitempty"`
	// ParentID (#G80) — omitting it silently created every secret at project
	// root regardless of the folder the caller placed it in.
	ParentID       *uint       `json:"parent_id,omitempty"`
	Metadata       models.JSON `json:"metadata,omitempty"`
	Classification string      `json:"classification,omitempty"`
}

func newSecretCreateWireRequest(secret *models.SecretNode, plaintextValue string) secretCreateWireRequest {
	return secretCreateWireRequest{
		Name:           secret.Name,
		Value:          plaintextValue,
		ProjectID:      secret.ProjectID,
		EnvironmentID:  secret.EnvironmentID,
		Type:           secret.Type,
		MaxReads:       secret.MaxReads,
		ParentID:       secret.ParentID,
		Metadata:       secret.Metadata,
		Classification: secret.Classification,
	}
}

// secretUpdateWireRequest carries the caller's full desired SecretNode state —
// a Go-to-Go round trip (SecretNode has no json tags besides ValueStored's
// "-"), matching the existing TransitionSecretStatus/GetSecretIncludingDeleted
// precedent — so the hub can diff it against its OWN authoritative row and
// decide what may actually change (G80 Phase 0).
//
// Deliberately NOT a narrow, named-field DTO: a hand-picked client-side field
// list is exactly how the original G80 bug happened (secretUpdateWireRequest
// used to carry only MaxReads/Expiration/ClearExpiration, silently dropping
// every other field seven other internal/core call sites mutate before
// calling storage.UpdateSecret — see docs/g80-remediation-notes.md). The hub
// is the only side that can enforce the security-gated fields' real
// authorization requirements (SoD on ownership transfer, the G09 read-approval
// gate on classification downgrade, requireAdminAuthorityAt on rotation-
// backend binding) — see updateSecretAllowlist in
// server/http/handlers/secret_update_diff.go for the full classification and
// why sending everything and letting the hub decide is the only safe shape
// here.
//
// By the time any internal/core call site calls storage.UpdateSecret, the
// SecretNode it passes already reflects the fully-resolved final desired
// state for every field it legitimately owns (each site first fetches the
// existing row via GetSecret, then mutates in place) — so a nil Expiration
// here unambiguously means "the final state has no expiration," with no
// separate clear-vs-unchanged flag needed the way the old narrow DTO required.
//
// DO NOT "optimize" this back to a named-field/sparse DTO. That is the exact
// shape of the original bug: a client-chosen subset silently drops whatever
// field the client didn't think to include, and the hub has no way to tell
// "the caller wants this field unchanged" from "the caller's DTO never had a
// slot for it." Sending the full node and diffing hub-side is what makes the
// allowlist in secret_update_diff.go default-deny instead of default-trust —
// narrowing the wire shape again would silently defeat that, not just
// regress performance. No secret VALUE or ciphertext is ever at risk here:
// ValueStored is gorm:"-"/json:"-" (never serialized — guarded by
// TestRemoteStorage_UpdateSecret_NeverSerializesValueStored,
// remote_secrets_test.go) and models.SecretNode itself has no field that
// carries the encrypted or plaintext value; that lives entirely in a
// separate SecretVersion row this struct never touches.
type secretUpdateWireRequest struct {
	Secret *models.SecretNode `json:"secret"`
}

func newSecretUpdateWireRequest(secret *models.SecretNode) secretUpdateWireRequest {
	return secretUpdateWireRequest{Secret: secret}
}

// CreateSecret creates a new secret via remote API. plaintextValue is optional
// (#499) — see the interface doc and secretCreateWireRequest's comment above
// for why it is a call argument rather than a models.SecretNode field. At most
// the first value is used; the rest is accepted only to satisfy the variadic
// interface signature (callers pass zero or one).
//
// When plaintextValue is supplied, the upstream server's CreateSecret handler
// creates version 1 atomically as part of this same request — so the returned
// node has ValueStored set, telling core.CreateSecret its own separate
// CreateSecretVersion call is unnecessary (and would otherwise try to mint a
// conflicting duplicate version 1).
func (rs *RemoteStorage) CreateSecret(ctx context.Context, secret *models.SecretNode, plaintextValue ...string) (*models.SecretNode, error) {
	var value string
	if len(plaintextValue) > 0 {
		value = plaintextValue[0]
	}
	resp, err := rs.client.Post(ctx, apiSecretsPath, newSecretCreateWireRequest(secret, value))
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create secret failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if value != "" {
		result.ValueStored = true
	}
	return &result, nil
}

// GetSecret retrieves a secret by ID via remote API.
func (rs *RemoteStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSecretsByIDs is the batch form of GetSecret. There is no bulk by-ID REST
// endpoint, so this issues one GetSecret call per ID (the same per-secret network
// cost remote mode already pays today) rather than adding a new one — it only lets
// callers batch at the Go-API level. An ID whose lookup fails is skipped rather
// than failing the whole batch: the caller (the rotation planner's risk-scoring
// batch, #409) already treats an ID missing from the result the same conservative
// way GetSecret's own error is treated for a single secret — never a silent
// zero-risk score, so skipping here loses no safety margin.
func (rs *RemoteStorage) GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error) {
	out := make([]*models.SecretNode, 0, len(ids))
	for _, id := range ids {
		secret, err := rs.GetSecret(ctx, id)
		if err != nil {
			continue
		}
		out = append(out, secret)
	}
	return out, nil
}

// GetSecretByName retrieves a secret by name and scope context via remote API.
//
// The server registers this lookup as GET /api/v1/secrets/by-name with the name as
// a query parameter (mirroring ListSecrets' project_id/environment_id query-scoped
// convention), not as a path segment (#497: an earlier version of this method
// requested /api/v1/secrets/by-name/{name}, a route server/http/router.go never
// registered, so every call 404'd against a real server regardless of whether the
// secret existed).
func (rs *RemoteStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/by-name?name=%s&project_id=%d&environment_id=%d",
		url.QueryEscape(name), projectID, environmentID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by name: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret by name failed: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ClearProjectSecretOwnership proxies onto POST
// /api/v1/system/rbac/clear-project-secret-ownership (RBAC-002).
func (rs *RemoteStorage) ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error {
	payload := map[string]uint{"user_id": userID, "project_id": projectID}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/clear-project-secret-ownership", payload)
	if err != nil {
		return fmt.Errorf("failed to clear project secret ownership: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("clear project secret ownership failed: %s", resp.Error.Error())
	}
	return nil
}

// UpdateSecret updates an existing secret via remote API. The hub independently
// decides what may change (G80 Phase 0) — a field this call mutated that the hub
// rejects surfaces here as a real error, never as a silent no-op: this method
// must never return (nil, nil) after the hub declined to apply part of the
// request. See secretUpdateWireRequest's doc comment for why the full desired
// state is sent rather than a client-chosen subset.
func (rs *RemoteStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	resp, err := rs.client.Put(ctx, path, newSecretUpdateWireRequest(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}
	if !resp.Success {
		// The hub's error names the rejected field(s) and states that the
		// operation needs its own dedicated endpoint against a hub — see
		// updateSecretAllowlist (server/http/handlers/secret_update_diff.go).
		// Not yet supported: ownership transfer, move, classification change,
		// bulk rename, rotation-backend binding, and recording a rotation
		// timestamp, when connected to a hub.
		return nil, fmt.Errorf("update secret rejected by hub: %s", resp.Error.Error())
	}
	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// transitionSecretStatusWireRequest is TransitionSecretStatus's request body:
// the full secret row the caller already mutated in memory (secret.Status/
// UpdatedAt already set to the target values), plus the fromStatus the caller
// observed via GetSecret immediately before mutating it, mirroring
// transitionMachineIdentityStateBody's shape exactly. The Secret field
// marshals *models.SecretNode directly — it carries no json tags of its own
// beyond ValueStored's `json:"-"`, so a Go-to-Go round trip between this
// client and the handler's identical type preserves every field exactly, the
// same choice GetSecretIncludingDeleted already makes for the identical type.
type transitionSecretStatusWireRequest struct {
	Secret     *models.SecretNode `json:"secret"`
	FromStatus string             `json:"from_status"`
}

// TransitionSecretStatus persists secret's full row via a single conditional
// PUT to /api/v1/system/secrets/{id}/transition-status (mirroring
// TransitionMachineIdentityState's #388 pattern), carrying fromStatus
// alongside so the upstream applies the exact SAME conditional
// "WHERE id = ? AND status = ?" write its own LocalStorage would — see the
// interface doc (internal/core/storage/interface.go) for why this exists as a
// single round-trip primitive rather than a generic GetSecret-then-
// UpdateSecret proxy pair (RemoteStorage.WithTransaction is a no-op
// passthrough, so that two-call sequence would reopen the exact race this
// closes).
func (rs *RemoteStorage) TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/secrets/%d/transition-status", secret.ID)
	body := transitionSecretStatusWireRequest{Secret: secret, FromStatus: fromStatus}
	return rs.putConditionalTransition(ctx, path, body, "transition secret status")
}

// DeleteSecret deletes a secret by ID via remote API.
func (rs *RemoteStorage) DeleteSecret(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete secret failed: %s", resp.Error.Error())
	}
	return nil
}

// GetSecretIncludingDeleted loads a secret even when soft-deleted, via GET
// /api/v1/system/secrets/{id}/including-deleted (finding #531). Before this fix,
// the unconditional stub broke ScopeFromDeletedSecretParam — the scope resolver
// ahead of POST /secrets/{id}/restore (server/middleware/auth.go) — so every
// restore request 404'd before ever reaching the already-correctly-proxied
// RestoreSecret. A thin passthrough onto storage.Storage's own Unscoped lookup
// (no policy decision made here); gated on the SAME system.read tier every
// other RemoteStorage read already needs. The response marshals models.SecretNode
// directly (it carries no json tags of its own beyond ValueStored's `json:"-"`,
// so a Go-to-Go round trip between this client and the handler's identical type
// preserves every field exactly, mirroring DeleteExpiredShareRecords' identical
// choice for models.ShareRecord), wrapped in a small envelope.
func (rs *RemoteStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/system/secrets/%d/including-deleted", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret including deleted: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret including deleted failed: %s", resp.Error.Error())
	}
	var result struct {
		Secret *models.SecretNode `json:"secret"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Secret, nil
}

func (rs *RemoteStorage) RestoreSecret(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/secrets/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore secret: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore secret failed: %s", resp.Error.Error())
	}
	return nil
}

// --- Retention/purge-sweep proxies (finding #520) ---
//
// These proxy onto NEW server-side routes under /api/v1/system/retention
// (server/http/handlers/retention_proxy.go), the SAME "RemoteStorage stub -> thin
// proxy route" pattern established for login-attempts (#452), project
// invitations (#507), and dynamic secrets (round 116): a raw passthrough onto
// storage.Storage's own retention primitives — no purge/retention POLICY decision
// (which window applies, the legal-hold guard, which rows are "in flight" and
// therefore excluded) is made server-side; that stays entirely in the CALLING
// server's own internal/core.KeyorixCore, exactly as it does against a local
// backend. Gated on the SAME system.read/system.write tier every other
// RemoteStorage call already needs — no new privilege class. See
// retention_proxy.go's package doc for the full atomicity and timezone analysis
// (short version: each of these already resolves in ONE storage.Storage call
// server-side, so one HTTP round trip preserves whatever transactional guarantee
// the local implementation has; RemoteStorage.WithTransaction's no-op status is
// irrelevant here since none of these needed to span multiple calls).
func (rs *RemoteStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	return postRetentionBeforeCountResp(ctx, rs, "/api/v1/system/retention/secrets/purge", before, "purge deleted secrets")
}

// DeleteAnomalyAlertsBefore used to proxy onto POST
// /api/v1/system/retention/anomaly-alerts/purge (DeleteAnomalyAlertsBeforeProxy),
// deleted in the G80 liveness sweep — no live caller in either topology; see
// docs/g80-remediation-notes.md. Returns errUnsupportedRemote like every other
// known-unsupported RemoteStorage operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteAnomalyAlertsBefore(_ context.Context, _, _ time.Time) (int64, error) {
	return 0, errUnsupportedRemote
}

// DeleteClosedAccessReviewsBefore used to proxy onto POST
// /api/v1/system/retention/access-reviews/purge-closed
// (DeleteClosedAccessReviewsBeforeProxy), deleted in the G80 liveness sweep — no
// live caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteClosedAccessReviewsBefore(_ context.Context, _ time.Time) (int64, int64, error) {
	return 0, 0, errUnsupportedRemote
}

// DeleteExpiredBreakGlassBefore used to proxy onto POST
// /api/v1/system/retention/break-glass/purge-expired
// (DeleteExpiredBreakGlassBeforeProxy), deleted in the G80 liveness sweep — no
// live caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteExpiredBreakGlassBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, errUnsupportedRemote
}

// DeleteResolvedAccessRequestsBefore used to proxy onto POST
// /api/v1/system/retention/access-requests/purge-resolved
// (DeleteResolvedAccessRequestsBeforeProxy), deleted in the G80 liveness sweep —
// no live caller in either topology; see docs/g80-remediation-notes.md. Returns
// errUnsupportedRemote like every other known-unsupported RemoteStorage
// operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) DeleteResolvedAccessRequestsBefore(_ context.Context, _ time.Time) (int64, int64, error) {
	return 0, 0, errUnsupportedRemote
}

// postRetentionBeforeCountResp is the shared shape for every retention-purge
// route whose body is a single {"before": ...} timestamp and whose response is a
// single {"purged": <count>} integer.
func postRetentionBeforeCountResp(ctx context.Context, rs *RemoteStorage, path string, before time.Time, verb string) (int64, error) {
	body := struct {
		Before time.Time `json:"before"`
	}{Before: before}
	resp, err := rs.client.Post(ctx, path, body)
	if err != nil {
		return 0, fmt.Errorf("failed to %s: %w", verb, err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("%s failed: %s", verb, resp.Error.Error())
	}
	var result struct {
		Purged int64 `json:"purged"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Purged, nil
}

// ListSecrets lists secrets with optional filtering via remote API.
// Query parameters are built from the non-nil fields of filter.
func (rs *RemoteStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	path := buildSecretFilterPath(filter)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list secrets: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("list secrets failed: %s", resp.Error.Error())
	}
	var result struct {
		Secrets []*models.SecretNode `json:"secrets"`
		Total   int64                `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Secrets, result.Total, nil
}

// ListProjectSecretsForDrift is not available in remote mode; drift detection aggregates server-side.
func (rs *RemoteStorage) ListProjectSecretsForDrift(_ context.Context, _ uint) ([]storage.DriftSecretRow, error) {
	return nil, fmt.Errorf("ListProjectSecretsForDrift not available in remote mode")
}

// ListOrphanedSecrets is not available in remote mode; the orphaned-owner JOIN runs server-side.
func (rs *RemoteStorage) ListOrphanedSecrets(_ context.Context, _ uint) ([]*models.SecretNode, error) {
	return nil, fmt.Errorf("ListOrphanedSecrets not available in remote mode")
}

// CountOrphanedSecretsByProject is not available in remote mode; the grouped
// hygiene-rollup query (#393) runs server-side.
func (rs *RemoteStorage) CountOrphanedSecretsByProject(_ context.Context, _ []uint) (map[uint]int, error) {
	return nil, fmt.Errorf("CountOrphanedSecretsByProject not available in remote mode")
}

// CountExpiringSecretsByProject is not available in remote mode; the grouped
// hygiene-rollup query (#393) runs server-side.
func (rs *RemoteStorage) CountExpiringSecretsByProject(_ context.Context, _ []uint, _ time.Time) (map[uint]int, error) {
	return nil, fmt.Errorf("CountExpiringSecretsByProject not available in remote mode")
}

// ListLiveSecretNamesByProject is not available in remote mode; the grouped
// deployment-wide name-conformance scan (#416) runs server-side.
func (rs *RemoteStorage) ListLiveSecretNamesByProject(_ context.Context, _ []uint, _ int) ([]storage.SecretNameRow, bool, error) {
	return nil, false, fmt.Errorf("ListLiveSecretNamesByProject not available in remote mode")
}

// GetSecretTags / SetSecretTags are not available in remote mode; tag storage is server-side.
func (rs *RemoteStorage) GetSecretTags(_ context.Context, _ uint) ([]string, error) {
	return nil, fmt.Errorf("GetSecretTags not available in remote mode")
}

func (rs *RemoteStorage) SetSecretTags(_ context.Context, _ uint, _ []string) error {
	return fmt.Errorf("SetSecretTags not available in remote mode")
}

// buildSecretFilterPath constructs the /api/v1/secrets query string from filter fields.
func buildSecretFilterPath(filter *storage.SecretFilter) string {
	if filter == nil {
		return apiSecretsPath
	}
	params := newQueryBuilder()
	params.addUint("project_id", filter.ProjectID)
	params.addUint("environment_id", filter.EnvironmentID)
	params.addString("type", filter.Type)
	params.addString("created_by", filter.CreatedBy)
	params.addUint("owner_id", filter.OwnerID)
	params.addTime("expires_before", filter.ExpiresBefore)
	params.addTime("created_after", filter.CreatedAfter)
	params.addTime("created_before", filter.CreatedBefore)
	params.addTags("tags", filter.Tags)
	params.addString("search", filter.Search)
	params.addPage(filter.Page, filter.PageSize)
	return apiSecretsPath + params.String()
}

// --- Version operations ---

// CreateSecretVersion creates a new version of a secret via remote API.
func (rs *RemoteStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions", version.SecretNodeID)
	resp, err := rs.client.Post(ctx, path, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSecretVersion retrieves a specific version of a secret via remote API.
func (rs *RemoteStorage) GetSecretVersion(ctx context.Context, secretID uint, version int) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions/%d", secretID, version)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListSecretVersions lists all versions of a secret via remote API.
func (rs *RemoteStorage) ListSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret versions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list secret versions failed: %s", resp.Error.Error())
	}
	var result []*models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetSecretVersions is an alias for ListSecretVersions, satisfying the interface.
func (rs *RemoteStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	return rs.ListSecretVersions(ctx, secretID)
}

// GetLatestSecretVersion retrieves the most recent version of a secret via remote API.
// SetSecretCertNotAfter is a server-side concern (the certificate scan runs on the
// server); the remote client never invokes it.
func (rs *RemoteStorage) SetSecretCertNotAfter(_ context.Context, _ uint, _ *time.Time) error {
	return remoteUnsupported("SetSecretCertNotAfter")
}

func (rs *RemoteStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/versions/latest", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest secret version: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get latest secret version failed: %s", resp.Error.Error())
	}
	var result models.SecretVersion
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// IncrementSecretReadCount increments the read counter for a secret version via remote API.
func (rs *RemoteStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	path := fmt.Sprintf("/api/v1/secret-versions/%d/increment-read-count", versionID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to increment read count: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("increment read count failed: %s", resp.Error.Error())
	}
	return nil
}

// TryIncrementSecretReadCount is the max-reads burn-after-N-reads gate
// (internal/core/storage/interface.go). LocalStorage implements it as a real
// conditional `UPDATE ... WHERE read_count < maxReads` (local_secrets.go) so
// concurrent readers can never collectively exceed the cap.
//
// The server exposes no REST endpoint for this conditional check-and-increment
// today — only a plain, non-conditional increment-read-count route is proxyable
// via IncrementSecretReadCount, and even that route isn't currently registered
// in router.go (confirmed: no /secret-versions/{id}/increment-read-count route
// exists server-side). Blindly delegating to the unconditional increment would
// silently defeat maxReads for any deployment/future code path that reaches this
// method through storage.type: remote — it would always report success without
// ever checking the cap. Fail closed instead: report unsupported so the caller
// (readVersionValue, internal/core/versions.go) takes its existing fail-closed
// branch and refuses the read, rather than silently granting an unbounded number
// of reads on a max-reads-limited secret (#188).
//
// This method is not on the live remote value-read path today — the CLI's
// value-read path goes through a separate, already max-reads-enforcing HTTP
// endpoint on the server, not through core.KeyorixCore/RemoteStorage — so this
// closes a latent landmine, not a currently-exploitable gap. A real fix that
// preserves remote-mode support for max-reads secrets would require a new
// atomic conditional-increment REST endpoint mirroring LocalStorage's semantics;
// that is a larger scope than this fix and remains a documented gap.
func (rs *RemoteStorage) TryIncrementSecretReadCount(_ context.Context, _ uint, _ int) (bool, error) {
	return false, remoteUnsupported("TryIncrementSecretReadCount")
}

// TryIncrementSecretNodeReadCount mirrors TryIncrementSecretReadCount: the
// authoritative enforcement runs server-side against local storage, so a remote
// client is never on the enforcement hot path. Not expected to be called from a
// CLI/remote context (KeyorixCore always runs against LocalStorage server-side);
// fails loud rather than silently reporting success if it ever is.
func (rs *RemoteStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	return false, fmt.Errorf("remote storage: max-reads enforcement is server-side only")
}
