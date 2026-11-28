package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
)

// sendExportAuditUnavailable answers an export refused because its audit row could
// not be recorded (core.ErrMutationAuditUnavailable from a core.Log*Exported call
// or core.ExportSecretAccessLog, #4721) with 503, Retry-After and the stable code
// audit_unavailable, and reports whether it did. Nothing of the export was sent.
func sendExportAuditUnavailable(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, core.ErrMutationAuditUnavailable) {
		return false
	}
	log.Printf("SECURITY: export refused, audit log unavailable (HTTP 503): %v", err)
	w.Header().Set("Retry-After", strconv.Itoa(auditUnavailableRetryAfterSeconds))
	sendError(w, auditUnavailableCode, core.ExportAuditUnavailableMessage, http.StatusServiceUnavailable, nil)
	return true
}
