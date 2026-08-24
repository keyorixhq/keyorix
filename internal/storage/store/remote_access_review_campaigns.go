// remote_access_review_campaigns.go — access-review campaign storage primitives
// for RemoteStorage (ISO 27001 A.5.18, finding #519): thin passthroughs onto
// eleven new server-side routes under /api/v1/system/access-review-campaigns
// (server/http/handlers/access_review_campaigns_proxy.go), mirroring the
// project-memberships proxy (#511) and dynamic-secrets proxy patterns exactly:
// gated on the SAME broad system.read/system.write RBAC permissions a
// RemoteStorage credential already needs for every other proxied call, so this
// introduces no new privilege class.
//
// No campaign-lifecycle POLICY decision (snapshotting the project's live
// access-review report into items, the reviewer-independence check, the
// pending-vs-force-close gate, revoking the underlying grant on a "revoke"
// decision) is made in these routes — that stays entirely in the CALLING
// server's own internal/core.KeyorixCore (internal/core/access_review_campaign.go),
// exactly as it does against a local backend.
//
// UpdateAccessReviewCampaign/UpdateAccessReviewItem atomicity (investigated,
// not assumed): both are already a single, self-contained conditional UPDATE on
// the LocalStorage side (local_access_review_campaigns.go) — not a
// LockXForUpdate-then-write pair — and the storage.Storage interface already
// threads the result back as a bool (RowsAffected==1). A single proxied HTTP
// round trip (the upstream server runs that same one conditional UPDATE and
// reports the bool back on the wire) therefore preserves the guarantee exactly:
// no new atomic storage-interface primitive and no cross-call transaction
// spanning the wire is needed. See access_review_campaigns_proxy.go's package
// doc for the full reasoning.
//
// For the local (GORM) equivalent of every primitive here see
// local_access_review_campaigns.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// accessReviewCampaignWire mirrors accessReviewCampaignProxyWire in
// server/http/handlers/access_review_campaigns_proxy.go exactly.
type accessReviewCampaignWire struct {
	ID               uint       `json:"id"`
	ProjectID        uint       `json:"project_id"`
	Name             string     `json:"name"`
	State            string     `json:"state"`
	CreatedBy        uint       `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	ClosedBy         uint       `json:"closed_by,omitempty"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
	Degraded         bool       `json:"degraded"`
	DegradedReasons  []string   `json:"degraded_reasons,omitempty"`
	ForcedIncomplete bool       `json:"forced_incomplete"`
}

func newAccessReviewCampaignWire(c *models.AccessReviewCampaign) accessReviewCampaignWire {
	return accessReviewCampaignWire{
		ID:               c.ID,
		ProjectID:        c.ProjectID,
		Name:             c.Name,
		State:            c.State,
		CreatedBy:        c.CreatedBy,
		CreatedAt:        c.CreatedAt,
		ClosedBy:         c.ClosedBy,
		ClosedAt:         c.ClosedAt,
		Degraded:         c.Degraded,
		DegradedReasons:  c.DegradedReasons,
		ForcedIncomplete: c.ForcedIncomplete,
	}
}

func (w accessReviewCampaignWire) toModel() *models.AccessReviewCampaign {
	return &models.AccessReviewCampaign{
		ID:               w.ID,
		ProjectID:        w.ProjectID,
		Name:             w.Name,
		State:            w.State,
		CreatedBy:        w.CreatedBy,
		CreatedAt:        w.CreatedAt,
		ClosedBy:         w.ClosedBy,
		ClosedAt:         w.ClosedAt,
		Degraded:         w.Degraded,
		DegradedReasons:  w.DegradedReasons,
		ForcedIncomplete: w.ForcedIncomplete,
	}
}

func decodeAccessReviewCampaignResponse(data []byte) (*models.AccessReviewCampaign, error) {
	var wire accessReviewCampaignWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// accessReviewItemWire mirrors accessReviewItemProxyWire exactly.
type accessReviewItemWire struct {
	ID            uint       `json:"id"`
	CampaignID    uint       `json:"campaign_id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalID   uint       `json:"principal_id"`
	PrincipalName string     `json:"principal_name"`
	Email         string     `json:"email,omitempty"`
	Source        string     `json:"source"`
	RoleID        uint       `json:"role_id,omitempty"`
	RoleName      string     `json:"role_name,omitempty"`
	AccessLevel   string     `json:"access_level"`
	EnvironmentID uint       `json:"environment_id"`
	SecretID      uint       `json:"secret_id,omitempty"`
	SecretName    string     `json:"secret_name,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	Decision      string     `json:"decision"`
	Reason        string     `json:"reason,omitempty"`
	DecidedBy     uint       `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
}

func newAccessReviewItemWire(it *models.AccessReviewItem) accessReviewItemWire {
	return accessReviewItemWire{
		ID:            it.ID,
		CampaignID:    it.CampaignID,
		PrincipalType: it.PrincipalType,
		PrincipalID:   it.PrincipalID,
		PrincipalName: it.PrincipalName,
		Email:         it.Email,
		Source:        it.Source,
		RoleID:        it.RoleID,
		RoleName:      it.RoleName,
		AccessLevel:   it.AccessLevel,
		EnvironmentID: it.EnvironmentID,
		SecretID:      it.SecretID,
		SecretName:    it.SecretName,
		LastUsedAt:    it.LastUsedAt,
		Decision:      it.Decision,
		Reason:        it.Reason,
		DecidedBy:     it.DecidedBy,
		DecidedAt:     it.DecidedAt,
	}
}

func (w accessReviewItemWire) toModel() *models.AccessReviewItem {
	return &models.AccessReviewItem{
		ID:            w.ID,
		CampaignID:    w.CampaignID,
		PrincipalType: w.PrincipalType,
		PrincipalID:   w.PrincipalID,
		PrincipalName: w.PrincipalName,
		Email:         w.Email,
		Source:        w.Source,
		RoleID:        w.RoleID,
		RoleName:      w.RoleName,
		AccessLevel:   w.AccessLevel,
		EnvironmentID: w.EnvironmentID,
		SecretID:      w.SecretID,
		SecretName:    w.SecretName,
		LastUsedAt:    w.LastUsedAt,
		Decision:      w.Decision,
		Reason:        w.Reason,
		DecidedBy:     w.DecidedBy,
		DecidedAt:     w.DecidedAt,
	}
}

func decodeAccessReviewItemResponse(data []byte) (*models.AccessReviewItem, error) {
	var wire accessReviewItemWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// CreateAccessReviewCampaign persists an already-built campaign (the caller's
// own core.OpenAccessReviewCampaign already snapshotted the project's live
// access-review report before this call) via POST
// /api/v1/system/access-review-campaigns.
func (rs *RemoteStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/access-review-campaigns", newAccessReviewCampaignWire(c))
	if err != nil {
		return nil, fmt.Errorf("failed to create access-review campaign: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create access-review campaign failed: %s", resp.Error.Error())
	}
	return decodeAccessReviewCampaignResponse(resp.Data)
}

// GetAccessReviewCampaign retrieves a campaign by ID via GET
// /api/v1/system/access-review-campaigns/{id}.
func (rs *RemoteStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get access-review campaign: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get access-review campaign failed: %s", resp.Error.Error())
	}
	return decodeAccessReviewCampaignResponse(resp.Data)
}

// ListAccessReviewCampaigns lists a project's campaigns via GET
// /api/v1/system/access-review-campaigns?project_id=X.
func (rs *RemoteStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/access-review-campaigns?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list access-review campaigns: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list access-review campaigns failed: %s", resp.Error.Error())
	}
	var result struct {
		Campaigns []accessReviewCampaignWire `json:"campaigns"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.AccessReviewCampaign, 0, len(result.Campaigns))
	for _, w := range result.Campaigns {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// GetOpenAccessReviewCampaign returns the project's open campaign (nil, nil if
// none is open — matching LocalStorage's own contract) via GET
// /api/v1/system/access-review-campaigns/open?project_id=X.
func (rs *RemoteStorage) GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/access-review-campaigns/open?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get open access-review campaign: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get open access-review campaign failed: %s", resp.Error.Error())
	}
	var result struct {
		Campaign *accessReviewCampaignWire `json:"campaign"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Campaign == nil {
		return nil, nil
	}
	return result.Campaign.toModel(), nil
}

// GetLatestClosedAccessReviewCampaign returns the project's most recently
// closed campaign (nil, nil if it has never had one) via GET
// /api/v1/system/access-review-campaigns/latest-closed?project_id=X.
func (rs *RemoteStorage) GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	path := "/api/v1/system/access-review-campaigns/latest-closed?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest-closed access-review campaign: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get latest-closed access-review campaign failed: %s", resp.Error.Error())
	}
	var result struct {
		Campaign *accessReviewCampaignWire `json:"campaign"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if result.Campaign == nil {
		return nil, nil
	}
	return result.Campaign.toModel(), nil
}

// UpdateAccessReviewCampaign used to proxy onto PUT
// /api/v1/system/access-review-campaigns/{id} (UpdateAccessReviewCampaignProxy),
// deleted in the G80 liveness sweep — no live caller in either topology; see
// docs/g80-remediation-notes.md. Returns errUnsupportedRemote like every other
// known-unsupported RemoteStorage operation (see remote_auth.go's package doc).
func (rs *RemoteStorage) UpdateAccessReviewCampaign(_ context.Context, _ *models.AccessReviewCampaign) (bool, error) {
	return false, errUnsupportedRemote
}

// CreateAccessReviewItems bulk-persists a campaign's freshly-opened (all
// "pending") item snapshot via POST
// /api/v1/system/access-review-campaigns/{id}/items.
func (rs *RemoteStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if len(items) == 0 {
		return nil
	}
	campaignID := items[0].CampaignID
	wire := make([]accessReviewItemWire, 0, len(items))
	for _, it := range items {
		wire = append(wire, newAccessReviewItemWire(it))
	}
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", campaignID)
	resp, err := rs.client.Post(ctx, path, map[string]interface{}{"items": wire})
	if err != nil {
		return fmt.Errorf("failed to create access-review items: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("create access-review items failed: %s", resp.Error.Error())
	}
	return nil
}

// ListAccessReviewItems lists a campaign's items via GET
// /api/v1/system/access-review-campaigns/{id}/items.
func (rs *RemoteStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", campaignID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list access-review items: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list access-review items failed: %s", resp.Error.Error())
	}
	var result struct {
		Items []accessReviewItemWire `json:"items"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.AccessReviewItem, 0, len(result.Items))
	for _, w := range result.Items {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// CountPendingAccessReviewItems returns how many of a campaign's items still
// await a decision via GET
// /api/v1/system/access-review-campaigns/{id}/items/pending-count.
func (rs *RemoteStorage) CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error) {
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items/pending-count", campaignID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending access-review items: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count pending access-review items failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

// GetAccessReviewItem retrieves a single item by its own ID via GET
// /api/v1/system/access-review-campaigns/items/{itemID}.
func (rs *RemoteStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get access-review item: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get access-review item failed: %s", resp.Error.Error())
	}
	return decodeAccessReviewItemResponse(resp.Data)
}

// UpdateAccessReviewItem persists a recertification decision via PUT
// /api/v1/system/access-review-campaigns/items/{itemID}. See the package doc
// for why the bool this returns IS the single conditional `WHERE decision =
// 'pending' AND campaign state = 'open'` UPDATE's own RowsAffected==1 result,
// relayed faithfully across the wire — not synthesized by this method.
func (rs *RemoteStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", item.ID)
	resp, err := rs.client.Put(ctx, path, newAccessReviewItemWire(item))
	if err != nil {
		return false, fmt.Errorf("failed to update access-review item: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("update access-review item failed: %s", resp.Error.Error())
	}
	var result struct {
		Updated bool `json:"updated"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Updated, nil
}
