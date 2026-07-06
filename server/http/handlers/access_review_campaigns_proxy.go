// access_review_campaigns_proxy.go — server-side endpoints backing
// RemoteStorage's access-review campaign storage primitives (ISO 27001 A.5.18,
// finding #519): CreateAccessReviewCampaign/GetAccessReviewCampaign/
// ListAccessReviewCampaigns/GetOpenAccessReviewCampaign/
// GetLatestClosedAccessReviewCampaign/UpdateAccessReviewCampaign/
// CreateAccessReviewItems/ListAccessReviewItems/CountPendingAccessReviewItems/
// GetAccessReviewItem/UpdateAccessReviewItem.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its access-review-campaign storage calls to whichever upstream server it's
// configured against, through these routes (registered in
// server/http/router.go under /api/v1/system/access-review-campaigns, gated on
// the existing system.read/system.write RBAC permissions — the SAME credential
// a RemoteStorage client already needs for every other proxied call, e.g. full
// user CRUD, project-membership CRUD (#511), so this introduces no new
// privilege class). Mirrors project_memberships_proxy.go and
// dynamic_secrets_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/access_review_campaign.go already uses against a local
// backend — NO campaign-lifecycle POLICY decision (opening a campaign from a
// live access-review snapshot, the independence/self-review check, the
// pending-vs-force-close gate, revoking the underlying grant on a "revoke"
// decision) is made here; all of that stays entirely in the CALLING server's
// own internal/core.KeyorixCore, exactly as it does against a local backend.
// The existing human-facing /api/v1/projects/{id}/access-review/campaigns
// routes (access_review_campaigns.go's CatalogHandler methods) are
// deliberately NOT reused as the proxy target — like the human-facing
// /groups routes were the wrong target for #514 (see groups_proxy.go's
// package doc), those run the full campaign open/decide/close business logic
// against the HTTP caller's own identity, the wrong semantics for a raw
// storage-primitive passthrough whose caller already ran all of that on the
// downstream side.
//
// Atomicity (investigated, not assumed): UpdateAccessReviewCampaign and
// UpdateAccessReviewItem are each ALREADY a single, self-contained atomic
// operation — a single conditional `UPDATE ... WHERE <precondition>` statement
// (local_access_review_campaigns.go), not a separate LockXForUpdate-then-write
// pair — and the storage.Storage interface already threads the result back as
// a bool (RowsAffected==1), not a plain error. That means the ENTIRE
// atomicity guarantee lives inside one storage call, so a single proxied HTTP
// round trip (this server runs that same one conditional UPDATE, then reports
// the bool back on the wire) preserves it exactly: no new atomic
// storage-interface primitive, and no cross-call transaction spanning the
// wire, is needed here (unlike, say, #511's unique-index-violation
// translation, which needed the DUPLICATE_ACTIVE_MEMBERSHIP wire code because
// CreateProjectMembership's atomicity depended on a DB-level constraint
// surfacing through an untyped error). UpdateAccessReviewCampaignProxy/
// UpdateAccessReviewItemProxy below MUST relay that bool faithfully — never
// synthesize "updated: true" independent of the storage call's own result.
//
// Response envelope: like project_memberships_proxy.go/dynamic_secrets_proxy.go,
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses (its APIResponse/APIError
// types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// accessReviewCampaignProxyWire mirrors models.AccessReviewCampaign's fields
// exactly (snake_case). Unlike dynamicSecretConfigProxyWire/groupProxyWire,
// models.AccessReviewCampaign already carries a complete, correct set of json
// tags (no `json:"-"` fields to route around) — but a named wire type is kept
// anyway, matching every other proxy in this package, so the wire contract
// stays stable and explicit even if the model's tags ever change independently.
type accessReviewCampaignProxyWire struct {
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

func newAccessReviewCampaignProxyWire(c *models.AccessReviewCampaign) accessReviewCampaignProxyWire {
	return accessReviewCampaignProxyWire{
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

func (w accessReviewCampaignProxyWire) toModel() *models.AccessReviewCampaign {
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

// accessReviewItemProxyWire mirrors models.AccessReviewItem's fields exactly.
type accessReviewItemProxyWire struct {
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

func newAccessReviewItemProxyWire(it *models.AccessReviewItem) accessReviewItemProxyWire {
	return accessReviewItemProxyWire{
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

func (w accessReviewItemProxyWire) toModel() *models.AccessReviewItem {
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

// parseRequiredProjectIDQuery parses the required project_id query parameter shared by
// ListAccessReviewCampaignsProxy/GetOpenAccessReviewCampaignProxy/
// GetLatestClosedAccessReviewCampaignProxy.
func parseRequiredProjectIDQuery(w http.ResponseWriter, r *http.Request) (projectID uint, ok bool) {
	v := r.URL.Query().Get("project_id")
	if v == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id query parameter is required")
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return 0, false
	}
	return uint(id), true
}

// CreateAccessReviewCampaignProxy handles POST /api/v1/system/access-review-campaigns.
// Persists the caller's already-fully-built campaign row as-is (a raw
// storage-layer create) — matching CreateMembershipProxy's precedent, this is
// NOT the human-facing POST .../access-review/campaigns
// (CatalogHandler.OpenAccessReviewCampaign), which additionally snapshots the
// project's live access-review report and generates the campaign's items; the
// calling server's own core.OpenAccessReviewCampaign already did that and
// calls CreateAccessReviewItemsProxy separately to persist them.
func (h *CatalogHandler) CreateAccessReviewCampaignProxy(w http.ResponseWriter, r *http.Request) {
	var body accessReviewCampaignProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.ProjectID == 0 || body.Name == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id and name are required")
		return
	}
	created, err := h.coreService.Storage().CreateAccessReviewCampaign(r.Context(), body.toModel())
	if err != nil {
		log.Printf("access-review-campaigns proxy: create campaign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessReviewCampaignProxyWire(created))
}

// GetAccessReviewCampaignProxy handles GET /api/v1/system/access-review-campaigns/{id}.
func (h *CatalogHandler) GetAccessReviewCampaignProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid campaign id")
		return
	}
	c, err := h.coreService.Storage().GetAccessReviewCampaign(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access-review campaign not found")
			return
		}
		log.Printf("access-review-campaigns proxy: get campaign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessReviewCampaignProxyWire(c))
}

// ListAccessReviewCampaignsProxy handles GET
// /api/v1/system/access-review-campaigns?project_id=X.
func (h *CatalogHandler) ListAccessReviewCampaignsProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseRequiredProjectIDQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListAccessReviewCampaigns(r.Context(), projectID)
	if err != nil {
		log.Printf("access-review-campaigns proxy: list campaigns failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]accessReviewCampaignProxyWire, 0, len(rows))
	for _, c := range rows {
		wire = append(wire, newAccessReviewCampaignProxyWire(c))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"campaigns": wire})
}

// GetOpenAccessReviewCampaignProxy handles GET
// /api/v1/system/access-review-campaigns/open?project_id=X (a static path,
// registered before /access-review-campaigns/{id} in router.go). Returns
// {"campaign": null} (success, no error) when the project has no open
// campaign — mirroring LocalStorage.GetOpenAccessReviewCampaign's own
// (nil, nil) "none open" contract, not a 404.
func (h *CatalogHandler) GetOpenAccessReviewCampaignProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseRequiredProjectIDQuery(w, r)
	if !ok {
		return
	}
	c, err := h.coreService.Storage().GetOpenAccessReviewCampaign(r.Context(), projectID)
	if err != nil {
		log.Printf("access-review-campaigns proxy: get open campaign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if c == nil {
		writeRemoteAPISuccess(w, map[string]interface{}{"campaign": nil})
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"campaign": newAccessReviewCampaignProxyWire(c)})
}

// GetLatestClosedAccessReviewCampaignProxy handles GET
// /api/v1/system/access-review-campaigns/latest-closed?project_id=X (a static
// path, registered before /access-review-campaigns/{id} in router.go). Same
// nil-is-success contract as GetOpenAccessReviewCampaignProxy above.
func (h *CatalogHandler) GetLatestClosedAccessReviewCampaignProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseRequiredProjectIDQuery(w, r)
	if !ok {
		return
	}
	c, err := h.coreService.Storage().GetLatestClosedAccessReviewCampaign(r.Context(), projectID)
	if err != nil {
		log.Printf("access-review-campaigns proxy: get latest-closed campaign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if c == nil {
		writeRemoteAPISuccess(w, map[string]interface{}{"campaign": nil})
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"campaign": newAccessReviewCampaignProxyWire(c)})
}

// UpdateAccessReviewCampaignProxy handles PUT
// /api/v1/system/access-review-campaigns/{id}. Runs the SAME single
// conditional UPDATE (`WHERE id = ? AND state = 'open'`) LocalStorage's own
// UpdateAccessReviewCampaign does — see the package doc for why relaying that
// call's bool result (not synthesizing one) is the entire atomicity
// contract here.
func (h *CatalogHandler) UpdateAccessReviewCampaignProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid campaign id")
		return
	}
	var body accessReviewCampaignProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	updated, err := h.coreService.Storage().UpdateAccessReviewCampaign(r.Context(), body.toModel())
	if err != nil {
		log.Printf("access-review-campaigns proxy: update campaign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": updated})
}

// CreateAccessReviewItemsProxy handles POST
// /api/v1/system/access-review-campaigns/{id}/items. Bulk-persists the
// caller's already-built item snapshot (each "pending") — the calling
// server's own core.OpenAccessReviewCampaign already generated these from its
// own live GenerateProjectAccessReview report.
func (h *CatalogHandler) CreateAccessReviewItemsProxy(w http.ResponseWriter, r *http.Request) {
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid campaign id")
		return
	}
	var body struct {
		Items []accessReviewItemProxyWire `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	items := make([]*models.AccessReviewItem, 0, len(body.Items))
	for _, w := range body.Items {
		w.CampaignID = uint(campaignID)
		items = append(items, w.toModel())
	}
	if err := h.coreService.Storage().CreateAccessReviewItems(r.Context(), items); err != nil {
		log.Printf("access-review-campaigns proxy: create items failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"created": true})
}

// ListAccessReviewItemsProxy handles GET
// /api/v1/system/access-review-campaigns/{id}/items.
func (h *CatalogHandler) ListAccessReviewItemsProxy(w http.ResponseWriter, r *http.Request) {
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid campaign id")
		return
	}
	rows, err := h.coreService.Storage().ListAccessReviewItems(r.Context(), uint(campaignID))
	if err != nil {
		log.Printf("access-review-campaigns proxy: list items failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]accessReviewItemProxyWire, 0, len(rows))
	for _, it := range rows {
		wire = append(wire, newAccessReviewItemProxyWire(it))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"items": wire})
}

// CountPendingAccessReviewItemsProxy handles GET
// /api/v1/system/access-review-campaigns/{id}/items/pending-count (a static
// path — chi always matches the literal "pending-count" segment over any
// wildcard sibling at the same depth, so it coexists safely with the item
// routes below regardless of registration order).
func (h *CatalogHandler) CountPendingAccessReviewItemsProxy(w http.ResponseWriter, r *http.Request) {
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid campaign id")
		return
	}
	n, err := h.coreService.Storage().CountPendingAccessReviewItems(r.Context(), uint(campaignID))
	if err != nil {
		log.Printf("access-review-campaigns proxy: count pending items failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int{"count": n})
}

// GetAccessReviewItemProxy handles GET
// /api/v1/system/access-review-campaigns/items/{itemID} — a top-level item
// lookup by its own ID (not nested under a campaign), matching the storage
// interface's own GetAccessReviewItem(ctx, id) signature. The literal "items"
// path segment here takes priority over the /access-review-campaigns/{id}
// wildcard at the same depth — the same static-vs-wildcard precedence
// project_memberships_proxy.go's "active"/"stale"/"counts"/"by-user" already
// rely on.
func (h *CatalogHandler) GetAccessReviewItemProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "itemID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid item id")
		return
	}
	it, err := h.coreService.Storage().GetAccessReviewItem(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access-review item not found")
			return
		}
		log.Printf("access-review-campaigns proxy: get item failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessReviewItemProxyWire(it))
}

// UpdateAccessReviewItemProxy handles PUT
// /api/v1/system/access-review-campaigns/items/{itemID}. Runs the SAME single
// conditional UPDATE (`WHERE id = ? AND decision = 'pending' AND campaign_id
// IN (SELECT ... WHERE state = 'open')`) LocalStorage's own
// UpdateAccessReviewItem does — see the package doc for why relaying that
// call's bool result (not synthesizing one) is the entire atomicity contract
// here; this single round trip verifies both the item-pending and
// campaign-open preconditions atomically, exactly as it does against a local
// backend.
func (h *CatalogHandler) UpdateAccessReviewItemProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "itemID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid item id")
		return
	}
	var body accessReviewItemProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	updated, err := h.coreService.Storage().UpdateAccessReviewItem(r.Context(), body.toModel())
	if err != nil {
		log.Printf("access-review-campaigns proxy: update item failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": updated})
}
