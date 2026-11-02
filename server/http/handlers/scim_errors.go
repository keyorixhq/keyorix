// scim_errors.go — the status an IdP sees when a SCIM user operation fails (#3494).
//
// The status is the IdP's only signal for what to do next, so it must say what
// happened, not a convenient default. A 404 means "this user does not exist": an IdP
// that gets one for a deactivation or a DELETE marks the user gone and never retries,
// so a 404 for a write that a storage failure rolled back left the account ACTIVE
// after the IdP believed it was deprovisioned. Classification is by errors.Is on the
// core/storage sentinels, never by message text (the texts are i18n and change with
// the locale).
package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// RFC 7644 §3.12 scimType values used here.
const (
	scimTypeUniqueness   = "uniqueness"
	scimTypeInvalidValue = "invalidValue"
)

const scimBusyDetail = "the service is temporarily busy; retry the request"

// scimErrorClass is one row of the SCIM error mapping.
type scimErrorClass struct {
	status   int
	scimType string // "" = none
	detail   string // "" = clientSafe's generic text
}

// classifySCIMError maps a core error from a SCIM user or group operation to its SCIM answer:
//
//   - the user/group positively does not exist, or the user is not SCIM-managed -> 404
//   - email/externalId (user) or displayName (group) taken by another  -> 409 uniqueness
//   - the last-admin guard refused (permanent, not retried)           -> 409
//   - invalid attribute value, or a group member SCIM does not manage -> 400 invalidValue
//   - adding members to a group that grants an admin role (permanent) -> 403
//   - SQLite write-gate contention, or a concurrent state change lost
//     the conditional write (nothing written, safe to retry)          -> 503 + Retry-After
//   - anything else: transient, deadlock, rolled back, canceled       -> 500, generic detail
//
// A PartialMutationError is not classified here (scimPartialMutation answers it first).
func classifySCIMError(err error) scimErrorClass {
	switch {
	case errors.Is(err, corestorage.ErrUserNotFound), errors.Is(err, core.ErrNotSCIMManaged):
		return scimErrorClass{status: http.StatusNotFound, detail: "user not found"}
	case errors.Is(err, corestorage.ErrGroupNotFound):
		return scimErrorClass{status: http.StatusNotFound, detail: "group not found"}
	case errors.Is(err, corestorage.ErrDuplicateGroupName):
		return scimErrorClass{status: http.StatusConflict, scimType: scimTypeUniqueness, detail: corestorage.ErrDuplicateGroupName.Error()}
	case errors.Is(err, core.ErrSCIMMemberNotManaged):
		return scimErrorClass{status: http.StatusBadRequest, scimType: scimTypeInvalidValue, detail: "a member is not a SCIM-managed user"}
	case errors.Is(err, core.ErrSCIMGroupConfersAdmin):
		return scimErrorClass{status: http.StatusForbidden, detail: core.ErrSCIMGroupConfersAdmin.Error()}
	case errors.Is(err, core.ErrLastAdminGroupGuard), errors.Is(err, corestorage.ErrWouldStrandLastAdmin):
		return scimErrorClass{status: http.StatusConflict, detail: core.ErrLastAdminGroupGuard.Error()}
	case errors.Is(err, core.ErrSCIMUserExists):
		return scimErrorClass{status: http.StatusConflict, scimType: scimTypeUniqueness, detail: core.ErrSCIMUserExists.Error()}
	case errors.Is(err, core.ErrEmailInUse), errors.Is(err, corestorage.ErrDuplicateEmail):
		return scimErrorClass{status: http.StatusConflict, scimType: scimTypeUniqueness, detail: core.ErrEmailInUse.Error()}
	case errors.Is(err, corestorage.ErrDuplicateUsername):
		return scimErrorClass{status: http.StatusConflict, scimType: scimTypeUniqueness, detail: core.ErrSCIMUserExists.Error()}
	case errors.Is(err, core.ErrLastAdminDeactivation):
		return scimErrorClass{status: http.StatusConflict, detail: core.ErrLastAdminDeactivation.Error()}
	case errors.Is(err, core.ErrInvalidInput):
		return scimErrorClass{status: http.StatusBadRequest, scimType: scimTypeInvalidValue, detail: "invalid attribute value"}
	case corestorage.IsWriteContention(err),
		errors.Is(err, core.ErrUserActiveStateConflict),
		errors.Is(err, core.ErrUserAccountStateConflict):
		return scimErrorClass{status: http.StatusServiceUnavailable, detail: scimBusyDetail}
	default:
		return scimErrorClass{status: http.StatusInternalServerError}
	}
}

// writeSCIMWriteError answers err from a SCIM user or group operation (what names it
// for the log). The full error goes to the server log with the request id; the client
// gets only the class's fixed detail. Every SCIM user and group handler's error path
// goes through here (TestSCIM_UserWriteStorageError_Is500NotNotFound,
// TestSCIM_GroupStorageError_Is500NotNotFound).
func writeSCIMWriteError(w http.ResponseWriter, r *http.Request, what string, err error) {
	if scimPartialMutation(w, err) {
		log.Printf("SCIM %s partially applied (HTTP 503, request %s): %v", what, chimw.GetReqID(r.Context()), err)
		return
	}
	c := classifySCIMError(err)
	log.Printf("SCIM %s failed (HTTP %d, request %s): %v", what, c.status, chimw.GetReqID(r.Context()), err)
	detail := c.detail
	if detail == "" {
		detail = clientSafe(err)
	}
	if c.status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", strconv.Itoa(middleware.WriteContentionRetryAfterSeconds))
	}
	scimErrorTyped(w, c.status, c.scimType, detail)
}
