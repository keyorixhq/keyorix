// mfa_reset.go — the online two-admin MFA reset routes (RECOVERY-MFA-RESET-1).
// The rules live in core (internal/core/mfa_reset.go); these handlers decode,
// call core, and map its typed refusals to fixed client texts.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// sendMFAResetError maps a core refusal to its status and fixed text; anything
// unclassified is a 500 with a generic message (the cause is logged). An audit-log
// outage gets the shared answer of every audited mutation (sendAuditUnavailable).
func sendMFAResetError(w http.ResponseWriter, op string, err error) {
	if sendAuditUnavailable(w, err) {
		return
	}
	type mapping struct {
		target error
		status int
		code   string
		msg    string
	}
	for _, m := range []mapping{
		{core.ErrMFAResetAdminRequired, http.StatusForbidden, "PermissionDenied", core.MFAResetAdminRequiredMessage},
		{core.ErrMFAResetActorNeedsMFA, http.StatusForbidden, "MFAEnrollmentRequired", core.MFAResetActorNeedsMFAMessage},
		{core.ErrMFAResetSelfApproval, http.StatusForbidden, "PermissionDenied", core.MFAResetSelfApprovalMessage},
		{core.ErrInsufficientAdminAuthority, http.StatusForbidden, "PermissionDenied", "insufficient admin authority over this user"},
		{core.ErrCannotActOnSelf, http.StatusBadRequest, "BadRequest", "an MFA reset cannot target your own account; use a recovery code or `keyorix-server admin recover-admin`"},
		{core.ErrMFAResetInput, http.StatusBadRequest, "ValidationError", core.MFAResetInputMessage},
		{core.ErrMFAResetUserRequired, http.StatusBadRequest, "ValidationError", core.MFAResetUserRequiredMessage},
		{core.ErrMFAResetTargetNotFound, http.StatusNotFound, "NotFound", core.MFAResetTargetNotFoundMessage},
		{core.ErrMFAResetRequestNotFound, http.StatusNotFound, "NotFound", core.MFAResetRequestNotFoundMessage},
		{core.ErrMFAResetMachineIdentity, http.StatusUnprocessableEntity, "UnprocessableEntity", core.MFAResetMachineIdentityMessage},
		{core.ErrMFAResetGlobalAdmin, http.StatusUnprocessableEntity, "UnprocessableEntity", core.MFAResetGlobalAdminMessage},
		{core.ErrMFAResetExternalIdentity, http.StatusConflict, "Conflict", core.MFAResetExternalIdentityMessage},
		{core.ErrMFAResetAccountBlocked, http.StatusConflict, "Conflict", core.MFAResetAccountBlockedMessage},
		{core.ErrMFAResetNoSecondAdmin, http.StatusConflict, "Conflict", core.MFAResetNoSecondAdminMessage},
		{core.ErrMFAResetAlreadyPending, http.StatusConflict, "Conflict", core.MFAResetAlreadyPendingMessage},
		{core.ErrMFAResetRequestDecided, http.StatusConflict, "Conflict", core.MFAResetRequestDecidedMessage},
		{core.ErrMFAResetRequestExpired, http.StatusConflict, "Conflict", core.MFAResetRequestExpiredMessage},
		{core.ErrMFAResetRequesterChanged, http.StatusConflict, "Conflict", core.MFAResetRequesterChangedMessage},
	} {
		if errors.Is(err, m.target) {
			sendError(w, m.code, m.msg, m.status, nil)
			return
		}
	}
	if errors.Is(err, core.ErrReauthRejected) || errors.Is(err, core.ErrMFAVerificationStorageFailure) {
		// The same answer as every other re-auth endpoint: never which step failed.
		sendError(w, "Error", reauthFaultMessage(err), http.StatusBadRequest, nil)
		return
	}
	log.Printf("MFA reset %s error: %v", op, err)
	sendError(w, "InternalError", "Failed to "+op+" the MFA reset", http.StatusInternalServerError, nil)
}

func mfaResetRequestID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil || id == 0 {
		sendError(w, "InvalidParameter", "Invalid MFA reset request ID", http.StatusBadRequest, nil)
		return 0, false
	}
	return uint(id), true
}

// RequestMFAReset handles POST /api/v1/mfa-reset-requests.
func RequestMFAReset(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		User       string `json:"user"`
		Reason     string `json:"reason"`
		VerifiedBy string `json:"verified_by"`
		Evidence   string `json:"evidence"`
		Code       string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	req, err := defaultUserHandler.coreService.RequestMFAReset(r.Context(), actor.UserID, isMachineActor(r), core.MFAResetRequestInput{
		User: body.User, Reason: body.Reason, VerifiedBy: body.VerifiedBy, Evidence: body.Evidence, Code: body.Code,
	})
	if err != nil {
		sendMFAResetError(w, "request", err)
		return
	}
	sendCreated(w, map[string]any{"request": &core.MFAResetRequestView{MFAResetRequest: req, EffectiveStatus: req.Status}},
		"MFA reset requested; a different administrator must approve it")
}

// ApproveMFAReset handles POST /api/v1/mfa-reset-requests/{id}/approve. The
// response carries the target's one-time password, once.
func ApproveMFAReset(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := mfaResetRequestID(w, r)
	if !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	res, err := defaultUserHandler.coreService.ApproveMFAReset(r.Context(), actor.UserID, isMachineActor(r), id, body.Code)
	if err != nil {
		sendMFAResetError(w, "approve", err)
		return
	}
	// The body carries a credential: never cache it.
	w.Header().Set("Cache-Control", "no-store")
	sendSuccess(w, res, "MFA reset approved: give the one-time password to the user out of band")
}

// CancelMFAReset handles POST /api/v1/mfa-reset-requests/{id}/cancel.
func CancelMFAReset(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, ok := mfaResetRequestID(w, r)
	if !ok {
		return
	}
	if err := defaultUserHandler.coreService.CancelMFAReset(r.Context(), actor.UserID, isMachineActor(r), id); err != nil {
		sendMFAResetError(w, "cancel", err)
		return
	}
	sendSuccess(w, nil, "MFA reset request cancelled")
}

// ListMFAResetRequests handles GET /api/v1/mfa-reset-requests[?status=pending].
func ListMFAResetRequests(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", errUserHandlerNotInit, http.StatusServiceUnavailable, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "pending" {
		sendError(w, "InvalidParameter", "status must be pending or omitted", http.StatusBadRequest, nil)
		return
	}
	rows, err := defaultUserHandler.coreService.ListMFAResetRequests(r.Context(), actor.UserID, isMachineActor(r), status == "pending")
	if err != nil {
		sendMFAResetError(w, "list", err)
		return
	}
	sendSuccess(w, map[string]any{"requests": rows}, "")
}
