// remote_sharing.go — ShareRecord operations for RemoteStorage.
//
// Covers: CreateShareRecord, GetShareRecord, UpdateShareRecord, DeleteShareRecord,
//
//	ListSharesBySecret, ListSharesByUser, ListSharesByOwner, ListSharesByGroup,
//	ListSharedSecrets, CheckSharePermission.
//
// For the local (GORM) equivalent see local_sharing.go (not yet implemented).
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateShareRecord: #1511/G80 deletion pass — POST /api/v1/shares has no
// matching route (confirmed real: the /shares group has no POST). Every
// caller (ShareSecret/ShareSecretWithGroup) is behind share/create.go's
// NewRemoteClient() guard. See docs/adr-087-remote-storage-deletion-pass.md.
func (rs *RemoteStorage) CreateShareRecord(_ context.Context, _ *models.ShareRecord) (*models.ShareRecord, error) {
	return nil, remoteUnsupported("CreateShareRecord")
}

// GetShareRecord: #1511/G80 deletion pass — GET /api/v1/shares/{id} has no
// matching route (confirmed real: the /shares group has no GET/{id}). Every
// caller (UpdateSharePermission, RevokeShare) is behind a NewRemoteClient()
// guard in share/update.go, share/revoke.go. See
// docs/adr-087-remote-storage-deletion-pass.md.
func (rs *RemoteStorage) GetShareRecord(_ context.Context, _ uint) (*models.ShareRecord, error) {
	return nil, remoteUnsupported("GetShareRecord")
}

// UpdateShareRecord updates an existing share record via remote API.
func (rs *RemoteStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/shares/%d", share.ID)
	resp, err := rs.client.Put(ctx, path, share)
	if err != nil {
		return nil, fmt.Errorf("failed to update share record: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update share record failed: %s", resp.Error.Error())
	}
	var result models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteShareRecord deletes a share record via remote API.
func (rs *RemoteStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	path := fmt.Sprintf("/api/v1/shares/%d", shareID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete share record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete share record failed: %s", resp.Error.Error())
	}
	return nil
}

// ListSharesBySecret lists all share records for a given secret via remote API.
func (rs *RemoteStorage) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d/shares", secretID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by secret: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by secret failed: %s", resp.Error.Error())
	}
	var result []*models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListSharesBySecretIDs is the batch form of ListSharesBySecret. There is no bulk
// by-secret-IDs REST endpoint, so this issues one ListSharesBySecret call per
// secret — but unlike GetSecretsByIDs, a failure here fails the WHOLE batch
// (returns immediately) rather than skipping the affected secret: silently
// treating a failed shares lookup as "no shares" would under-count that secret's
// exposure, exactly the #407 bug (a widely-shared secret incorrectly reading as
// low-exposure) this method must not reintroduce. Failing the batch degrades
// every secret's exposure factor to the worst case instead — never fewer
// principals than reality, only ever more caution than strictly necessary.
func (rs *RemoteStorage) ListSharesBySecretIDs(ctx context.Context, secretIDs []uint) ([]*models.ShareRecord, error) {
	var out []*models.ShareRecord
	for _, id := range secretIDs {
		shares, err := rs.ListSharesBySecret(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("list shares by secret %d: %w", id, err)
		}
		out = append(out, shares...)
	}
	return out, nil
}

// ListSharesByUser lists all share records where userID is the recipient, via
// GET /api/v1/system/shares/by-user/{userID}. This used to target
// /api/v1/users/{id}/shares — a route that was never registered server-side
// (there is no, and never was, a human-facing "list shares received by an
// arbitrary user ID" endpoint; the closest human-facing route, GET
// /api/v1/shares, resolves the CALLER's own ID from the request's auth
// context, not a path parameter). That meant core.ListSharesByUser (backing
// both GET /api/v1/shares and gRPC ShareService.ListShares) 404'd on this half
// unconditionally under storage.type: remote, even after #531 fixed the
// ListSharesByOwner half. Same thin-passthrough pattern as ListSharesByOwner
// immediately below: no policy decision made here, gated on the SAME
// system.read tier.
func (rs *RemoteStorage) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/system/shares/by-user/%d", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by user failed: %s", resp.Error.Error())
	}
	var result struct {
		Shares []*models.ShareRecord `json:"shares"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Shares, nil
}

// ListSharesByOwner lists currently-active share records created by ownerID, via
// GET /api/v1/system/shares/by-owner/{ownerID} (finding #531). Before this fix,
// the unconditional stub made core.ListSharesByUser hard-fail (no fallback —
// unlike the graceful-degrade access-activity gaps above, this one returns an
// ERROR to its own caller), breaking the gRPC "list my shares" call (and the
// owned-share half of ListSharesByUser generally) end to end under
// storage.type: remote. A thin passthrough onto storage.Storage's own
// active-share query (no policy decision made here); gated on the SAME
// system.read tier every other RemoteStorage read already needs.
func (rs *RemoteStorage) ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/system/shares/by-owner/%d", ownerID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by owner: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by owner failed: %s", resp.Error.Error())
	}
	var result struct {
		Shares []*models.ShareRecord `json:"shares"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Shares, nil
}

// ListSharesByGroup lists all share records where groupID is the recipient via remote API.
func (rs *RemoteStorage) ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	path := fmt.Sprintf("/api/v1/groups/%d/shares", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by group: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list shares by group failed: %s", resp.Error.Error())
	}
	var result []*models.ShareRecord
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListSharedSecrets: #1511/G80 deletion pass — GET
// /api/v1/users/*/shared-secrets has no matching route (confirmed real: only
// GET /shared-secrets, the caller's own, exists). Sole CLI caller
// (share/shared_secrets.go) is behind a NewRemoteClient() guard. See
// docs/adr-087-remote-storage-deletion-pass.md.
func (rs *RemoteStorage) ListSharedSecrets(_ context.Context, _ uint) ([]*models.SecretNode, error) {
	return nil, remoteUnsupported("ListSharedSecrets")
}

// CheckSharePermission: #1511/G80 deletion pass — GET
// /api/v1/secrets/*/permissions has no matching route, and core.CheckSharePermission
// itself has zero callers anywhere (no HTTP handler, no gRPC service, no CLI)
// — orphaned server-side, not just under storage.type: remote. See
// docs/adr-087-remote-storage-deletion-pass.md.
func (rs *RemoteStorage) CheckSharePermission(_ context.Context, _, _ uint) (string, error) {
	return "", remoteUnsupported("CheckSharePermission")
}

// DeleteExpiredShareRecords proxies onto POST
// /api/v1/system/retention/share-records/purge-expired
// (server/http/handlers/retention_proxy.go, finding #520) — the SAME
// "RemoteStorage stub -> thin proxy route" pattern established for login-attempts
// (#452). Returns the full removed *models.ShareRecord rows, not just a count:
// the calling server's own internal/core.RemoveExpiredShares writes one
// share.expired audit event per share using exactly this data, which a bare
// count could not reconstruct. models.ShareRecord carries no json tags of its
// own, so this marshals/unmarshals the model directly — matching every other
// ShareRecord round trip in this file (CreateShareRecord, GetShareRecord, ...).
func (rs *RemoteStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	body := struct {
		Before time.Time `json:"before"`
	}{Before: before}
	resp, err := rs.client.Post(ctx, "/api/v1/system/retention/share-records/purge-expired", body)
	if err != nil {
		return nil, fmt.Errorf("failed to purge expired share records: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("purge expired share records failed: %s", resp.Error.Error())
	}
	var result struct {
		Removed []*models.ShareRecord `json:"removed"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Removed, nil
}
