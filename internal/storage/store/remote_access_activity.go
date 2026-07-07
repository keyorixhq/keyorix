// remote_access_activity.go — dormant-access activity lookup for RemoteStorage
// (finding #531). Proxies LastUserSecretActivity/LastUserRoleManagementActivity/
// LastUserSecretDeletionActivity/LastUserSecretReadActivity/
// LastUserSecretWriteActivity onto NEW server-side routes under
// /api/v1/system/access-activity (server/http/handlers/access_activity_proxy.go),
// gated on the SAME system.read RBAC permission every other RemoteStorage read
// already needs (no new privilege class).
//
// Before this fix, every one of these five methods was an unconditional stub:
// GenerateProjectAccessReview (ISO 27001/SOC2 recertification) and
// compliance_posture.go's countDormantRoleGrants both degrade gracefully on
// error (a dormant-access grant is simply never flagged, not a hard failure),
// so the practical effect was a silently missing detective control rather than
// an outage — but the dormant-access/dormant-role-grant compliance signal was
// never available at all under storage.type: remote. Each is a thin passthrough
// onto storage.Storage's own audit_events query (no POLICY decision — which
// event types count as "activity" for which bucket, internal/storage/store/
// local_access_activity.go's accessActivityEventTypes and friends — is made
// here; that lives entirely server-side in LocalStorage, exactly as it does for
// a local backend).
//
// For the local (GORM) equivalent see local_access_activity.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// accessActivityWireResponse wraps the per-user last-activity map. JSON object
// keys must be strings, so the uint user IDs are carried as decimal strings on
// the wire and parsed back into a map[uint]time.Time on decode.
type accessActivityWireResponse struct {
	Activity map[string]time.Time `json:"activity"`
}

func decodeAccessActivityResponse(data []byte) (map[uint]time.Time, error) {
	var wire accessActivityWireResponse
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	out := make(map[uint]time.Time, len(wire.Activity))
	for k, v := range wire.Activity {
		id, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			continue
		}
		out[uint(id)] = v
	}
	return out, nil
}

// getAccessActivity is the shared GET behind all five methods below — they
// differ only in which server-side route (and therefore which event-type
// bucket) they hit.
func (rs *RemoteStorage) getAccessActivity(ctx context.Context, route string, projectID uint) (map[uint]time.Time, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/access-activity/" + route + "?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s activity: %w", route, err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get %s activity failed: %s", route, resp.Error.Error())
	}
	return decodeAccessActivityResponse(resp.Data)
}

// LastUserSecretActivity returns the most recent secret-access time per user in
// the project via GET /api/v1/system/access-activity/secret.
func (rs *RemoteStorage) LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	return rs.getAccessActivity(ctx, "secret", projectID)
}

// LastUserRoleManagementActivity returns the most recent role-management
// activity time per user in the project via GET
// /api/v1/system/access-activity/role-management.
func (rs *RemoteStorage) LastUserRoleManagementActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	return rs.getAccessActivity(ctx, "role-management", projectID)
}

// LastUserSecretDeletionActivity returns the most recent secret-deletion time
// per user in the project via GET
// /api/v1/system/access-activity/secret-deletion.
func (rs *RemoteStorage) LastUserSecretDeletionActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	return rs.getAccessActivity(ctx, "secret-deletion", projectID)
}

// LastUserSecretReadActivity returns the most recent secret.read time per user
// in the project via GET /api/v1/system/access-activity/secret-read.
func (rs *RemoteStorage) LastUserSecretReadActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	return rs.getAccessActivity(ctx, "secret-read", projectID)
}

// LastUserSecretWriteActivity returns the most recent
// secret.created/updated/rotated time per user in the project via GET
// /api/v1/system/access-activity/secret-write.
func (rs *RemoteStorage) LastUserSecretWriteActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	return rs.getAccessActivity(ctx, "secret-write", projectID)
}
