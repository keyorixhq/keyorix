// audit_ingest_proxy.go — server-side endpoint backing RemoteStorage's
// LogAuditEvent (#r122-A).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// emits audit events via internal/core.KeyorixCore.emitAudit, which calls
// storage.LogAuditEvent. On a RemoteStorage backend, LogAuditEvent used to
// POST to /api/v1/audit/events — a path that has never existed on the hub
// server (the read route is /api/v1/audit/logs, with no write counterpart).
// Every emitAudit call on a follower therefore returned a 404, the error was
// logged and discarded, and the hub's audit trail had a silent, complete gap
// for all follower-originated events: secret reads, logins, MFA enrolments,
// RBAC changes, etc.
//
// This proxy adds the missing write endpoint at
// POST /api/v1/system/audit/event (registered in server/http/router.go under
// the /system group, gated on system.write — the same credential tier every
// other RemoteStorage proxy already requires). It is a raw passthrough onto
// storage.Storage.LogAuditEvent, exactly like the access-request,
// invitation, MFA, and scheduler-lock proxies: no audit POLICY decision is
// made here; the emitting server's own core.KeyorixCore already made that
// decision before ever calling storage.LogAuditEvent.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// IngestAuditEventProxy accepts a single models.AuditEvent from a remote-
// storage follower and persists it in this server's own storage backend.
// Registered at POST /api/v1/system/audit/event (system.write).
func (h *AuditHandler) IngestAuditEventProxy(w http.ResponseWriter, r *http.Request) {
	var event models.AuditEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		sendError(w, "BadRequest", "invalid audit event body", http.StatusBadRequest, nil)
		return
	}
	// Zero the ID so the hub's DB assigns it. A caller-supplied ID could forge a
	// specific chain position, skip auto-increment sequences, or collide with an
	// existing entry — all of which corrupt VerifyAuditChain.
	event.ID = 0
	if err := h.coreService.Storage().LogAuditEvent(r.Context(), &event); err != nil {
		sendError(w, "InternalServerError", "failed to persist audit event", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "")
}
