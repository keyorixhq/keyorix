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
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditIngestProxyValidActorTypes mirrors internal/core/audit_context.go's
// ActorTypeUser/ActorTypeMachine/ActorTypeSystem constants — duplicated here
// (a small, stable enum) because this proxy cannot import internal/core's
// unexported values directly.
var auditIngestProxyValidActorTypes = map[string]bool{
	"":                 true, // LogAuditEvent normalizes empty to "user" before hashing
	"user":             true,
	"machine_identity": true,
	"system":           true,
}

// auditIngestProxyMaxClockSkew bounds how far a submitted event_time may
// diverge from this server's own clock, in either direction.
//
// #G79: this does NOT close the finding's core issue — LogAuditEvent computes
// EntryHash over whatever fields are set on the event it's given, so any
// system.write holder able to reach this endpoint directly (bypassing the
// emitting server's own core.KeyorixCore) can still submit a fully fabricated,
// self-consistent event (wrong actor, wrong description, wrong outcome) that
// passes VerifyAuditChain — a hash chain only detects tampering with entries
// already written, it cannot attest that a NEW entry's content is genuine.
// Closing that fully needs a way to attest the submitter really is a
// legitimate downstream node (the G79 structural part: a node-identity
// credential distinct from the RBAC permission tier, deferred to Wave 4).
// What IS closable here without that: reject the cruder abuse of an
// attacker-chosen event_time used to plant a forged entry at an arbitrary
// point in the forensic timeline (far in the past or future), and reject
// empty/unrecognized required fields no legitimate emitAudit call would ever
// leave that way.
const auditIngestProxyMaxClockSkew = 24 * time.Hour

// IngestAuditEventProxy accepts a single models.AuditEvent from a remote-
// storage follower and persists it in this server's own storage backend.
// Registered at POST /api/v1/system/audit/event (system.write). See
// auditIngestProxyMaxClockSkew's doc for what this validation does and does
// not close.
func (h *AuditHandler) IngestAuditEventProxy(w http.ResponseWriter, r *http.Request) {
	var event models.AuditEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		sendError(w, "BadRequest", "invalid audit event body", http.StatusBadRequest, nil)
		return
	}
	if event.EventType == "" {
		sendError(w, "BadRequest", "event_type is required", http.StatusBadRequest, nil)
		return
	}
	if !auditIngestProxyValidActorTypes[event.ActorType] {
		sendError(w, "BadRequest", "unrecognized actor_type", http.StatusBadRequest, nil)
		return
	}
	if event.EventTime.IsZero() {
		sendError(w, "BadRequest", "event_time is required", http.StatusBadRequest, nil)
		return
	}
	now := time.Now()
	if event.EventTime.Before(now.Add(-auditIngestProxyMaxClockSkew)) || event.EventTime.After(now.Add(auditIngestProxyMaxClockSkew)) {
		sendError(w, "BadRequest", "event_time is too far from the current time", http.StatusBadRequest, nil)
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
