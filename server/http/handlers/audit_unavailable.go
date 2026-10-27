package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
)

// auditUnavailableCode is the stable machine-readable error code (the envelope's
// "error" field) of a mutation refused because its audit row could not be
// recorded. Clients branch on it, never on the message.
const auditUnavailableCode = "audit_unavailable"

// auditUnavailableRetryAfterSeconds is the Retry-After a client is given. The
// outage is the audit store's, not the request's: nothing was changed, and a
// retry after a short pause is the right answer.
const auditUnavailableRetryAfterSeconds = 5

// sendAuditUnavailable answers a core.ErrMutationAuditUnavailable (a
// security-relevant mutation whose audit row could not be recorded, so its
// transaction rolled back) with 503, a Retry-After header and the stable code
// audit_unavailable, and reports whether it did. The message is the sentinel's
// own fixed text, never err.Error(): the wrapped cause names the audit event and
// the storage failure. Check it in a mutation handler's error branch before any
// other mapping, which would otherwise fall through to a bare 500.
//
// A core.PartialMutationError also unwraps to the sentinel but carries a body that
// says which half was applied; it is left to sendPartialMutation (check that
// first), so this reports false for it.
func sendAuditUnavailable(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, core.ErrMutationAuditUnavailable) {
		return false
	}
	if _, partial := core.AsPartialMutationError(err); partial {
		return false
	}
	log.Printf("mutation refused, audit log unavailable (HTTP 503): %v", err)
	w.Header().Set("Retry-After", strconv.Itoa(auditUnavailableRetryAfterSeconds))
	sendError(w, auditUnavailableCode, core.MutationAuditUnavailableMessage, http.StatusServiceUnavailable, nil)
	return true
}
