// rotation_calendar_handler.go — HTTP handler for GET /api/v1/rotation-calendar.
//
// Returns all policy-covered secrets with a computed NextRotationAt that falls
// within a caller-supplied [from, to] window. Both params are required and
// accepted as RFC 3339 timestamps or plain YYYY-MM-DD dates (interpreted as
// midnight UTC). Optional project_id/environment_id query params narrow the
// result to that scope; the route itself gates the required permission scope
// accordingly (see router.go's use of RequireScopedPermission + ScopeFromQuery).
package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// RotationCalendarHandler serves GET /api/v1/rotation-calendar.
type RotationCalendarHandler struct {
	coreService *core.KeyorixCore
}

// NewRotationCalendarHandler creates a new RotationCalendarHandler.
func NewRotationCalendarHandler(svc *core.KeyorixCore) *RotationCalendarHandler {
	return &RotationCalendarHandler{coreService: svc}
}

// Get handles GET /api/v1/rotation-calendar?from=&to=&project_id=&environment_id=
func (h *RotationCalendarHandler) Get(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		sendError(w, "MissingParameter", "both 'from' and 'to' query parameters are required", http.StatusBadRequest, nil)
		return
	}
	from, err := parseCalendarDate(fromStr)
	if err != nil {
		sendError(w, "InvalidParameter", "'from' must be RFC 3339 or YYYY-MM-DD", http.StatusBadRequest, nil)
		return
	}
	to, err := parseCalendarDate(toStr)
	if err != nil {
		sendError(w, "InvalidParameter", "'to' must be RFC 3339 or YYYY-MM-DD", http.StatusBadRequest, nil)
		return
	}
	if from.After(to) {
		sendError(w, "InvalidParameter", "'from' must not be after 'to'", http.StatusBadRequest, nil)
		return
	}

	// Optional scoping filter (see router.go: the route requires global secrets.read
	// when neither is supplied, and project/environment-scoped secrets.read otherwise).
	projectID, perr := parseOptionalUintQuery(r, "project_id")
	if perr != nil {
		sendError(w, "InvalidParameter", errInvalidProjectIDField, http.StatusBadRequest, nil)
		return
	}
	environmentID, perr := parseOptionalUintQuery(r, "environment_id")
	if perr != nil {
		sendError(w, "InvalidParameter", errInvalidEnvIDField, http.StatusBadRequest, nil)
		return
	}

	entries, err := h.coreService.GetRotationCalendar(r.Context(), from, to, projectID, environmentID)
	if err != nil {
		log.Printf("Error fetching rotation calendar [%s, %s]: %v", from.Format(time.DateOnly), to.Format(time.DateOnly), err)
		sendError(w, "InternalError", "Failed to fetch rotation calendar", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, entries, "")
}

func parseCalendarDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse(time.DateOnly, s)
}
