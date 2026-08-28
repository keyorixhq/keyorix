// notification_proxy.go — server-side endpoint backing RemoteStorage's
// CreateNotification (#1589, docs/adr-087-remote-storage-deletion-pass.md).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies its in-app notification writes to whichever upstream server it's
// configured against, through this route (registered in server/http/router.go
// under /api/v1/system/notifications, gated on the same system.write RBAC
// permission every other proxy in this group already needs — no new
// privilege class). Before this fix, CreateNotification was an unconditional
// remoteUnsupported stub: notify()/notifyWithSeverity() (internal/core/
// notifications.go) is a best-effort, error-swallowing wrapper by design (the
// same contract as audit emission — a delivery failure never blocks the
// triggering action), so every notification-worthy action under
// storage.type: remote succeeded while silently, permanently losing its
// notification. That best-effort contract is correct for an occasional local
// DB error; composed with a stub that fails 100% of the time, it became a
// standing feature outage. See #1589 for the full liveness trace.
//
// This is a raw passthrough onto storage.CreateNotification — no
// notification POLICY decision (which event types fire, who the recipient
// is, what the title/message read) is made here; that stays entirely in the
// CALLING server's own internal/core.KeyorixCore, exactly as it does against
// a local backend. Same pattern as access_request_proxy.go's package doc.
//
// Actor/origin note: models.Notification carries no actor, sender, or origin
// field — UserID is the RECIPIENT (who the notification is FOR), not an
// actor whose identity this proxy could misattribute. Any "who did this"
// text a caller renders (e.g. "approved by admin X") lives entirely inside
// the free-text Title/Message strings, already computed by the CALLING
// server's own authorized core function before this call is ever made —
// there is no structured field here for the wire-actor class of finding
// (CreateAccessRequestApprovalProxy's approver_id, UpdateAccessRequestProxy's
// resolved_by) to apply to. Nothing to derive from the authenticated caller;
// nothing more needed.
//
// Response envelope: like every other proxy in this package, this does NOT
// use the package's generic sendSuccess/sendError helpers — it constructs
// the exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// notificationProxyWire mirrors models.Notification's PERSISTED fields
// exactly (snake_case) — models.Notification carries no json tags of its own
// (see remote_notifications.go's notificationWireResponse comment for the
// case-sensitivity reasoning this mirrors). Deliberately distinct from that
// struct: notificationWireResponse is the self-scoped GET /notifications
// DISPLAY shape (bell icon), which omits SecretNodeID/Severity — this proxy
// needs the full persisted shape so a create round-trips every field
// notifyWithSeverity sets.
type notificationProxyWire struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	SecretNodeID *uint     `json:"secret_node_id,omitempty"`
	ProjectID    *uint     `json:"project_id,omitempty"`
	Type         string    `json:"type"`
	Title        string    `json:"title"`
	Message      string    `json:"message"`
	Link         string    `json:"link"`
	Severity     int       `json:"severity"`
	IsRead       bool      `json:"is_read"`
	CreatedAt    time.Time `json:"created_at"`
}

func newNotificationProxyWire(n *models.Notification) notificationProxyWire {
	return notificationProxyWire{
		ID:           n.ID,
		UserID:       n.UserID,
		SecretNodeID: n.SecretNodeID,
		ProjectID:    n.ProjectID,
		Type:         n.Type,
		Title:        n.Title,
		Message:      n.Message,
		Link:         n.Link,
		Severity:     int(n.Severity),
		IsRead:       n.IsRead,
		CreatedAt:    n.CreatedAt,
	}
}

func (w notificationProxyWire) toModel() *models.Notification {
	return &models.Notification{
		UserID:       w.UserID,
		SecretNodeID: w.SecretNodeID,
		ProjectID:    w.ProjectID,
		Type:         w.Type,
		Title:        w.Title,
		Message:      w.Message,
		Link:         w.Link,
		Severity:     models.NotificationSeverity(w.Severity),
		CreatedAt:    w.CreatedAt,
	}
}

// notificationDuplicateReminderCode is the machine-readable error code this
// route returns when storage.CreateNotification rejects a duplicate unread
// reminder (#250/#482's dedup unique index) — the wire-level signal
// RemoteStorage.CreateNotification uses to reconstruct
// storage.ErrDuplicateReminderNotification across the HTTP hop, mirroring
// duplicateSecretDependencyCode's identical pattern in
// remote_secret_dependencies.go.
const notificationDuplicateReminderCode = "DUPLICATE_REMINDER_NOTIFICATION"

// CreateNotificationProxy handles POST /api/v1/system/notifications. Always
// creates with IsRead=false, matching every real caller of notify()/
// notifyWithSeverity() (a notification is never created pre-read) — ID is
// left to the database to assign, not trusted from the wire, matching the
// same "never trust a client-supplied primary key on create" convention
// access_request_proxy.go's CreateAccessRequestProxy follows for ResolvedBy.
func (h *CatalogHandler) CreateNotificationProxy(w http.ResponseWriter, r *http.Request) {
	var body notificationProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id is required")
		return
	}
	created, err := h.coreService.Storage().CreateNotification(r.Context(), body.toModel())
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateReminderNotification) {
			writeRemoteAPIError(w, http.StatusConflict, notificationDuplicateReminderCode, err.Error())
			return
		}
		log.Printf("notifications proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newNotificationProxyWire(created))
}
