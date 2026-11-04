package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// authorizeLookupUnavailableMessage is the fixed 503 text: no storage error detail
// reaches the client. It is the text the REST permission gates and the gRPC
// services answer (server/middleware authorizeLookupUnavailableMessage, unexported
// there); the tests on both sides assert the literal, so a change to one fails the
// other.
const authorizeLookupUnavailableMessage = "authorization temporarily unavailable, please retry"

// authorizeLookupUnavailableRetryAfter is the Retry-After (seconds) the gates send:
// a brief storage blip, not a sustained outage.
const authorizeLookupUnavailableRetryAfter = "2"

// refuseUnlessAuthorized is the in-handler twin of the middleware permission gate's
// verdict: it writes the refusal for the result of a permission check and reports
// whether it did. The caller returns when it is true.
//
//   - err is a storage outage (core.IsAuthorizeTransient): 503 + Retry-After and the
//     fixed message. The caller was not judged, so a client may retry; the request is
//     refused, never served. On a value-read route the denial note records
//     internal_error, as the middleware gate does.
//   - any other err, or err == nil with allowed == false: forbidden() writes the
//     handler's own 403, so a genuine denial keeps its status and body. An error the
//     classifier does not recognise stays a fail-closed denial.
//   - err == nil and allowed: false, the handler goes on.
//
// Nothing here grants access: every path that is not "allowed" refuses
// (INV-MW-authorize-lookup-error-is-503).
func refuseUnlessAuthorized(w http.ResponseWriter, r *http.Request, allowed bool, err error, forbidden func()) bool {
	if err != nil {
		if core.IsAuthorizeTransient(r.Context(), err) {
			// A refused value read stays audited (outcome=failed): the 503 carries
			// neither a 403/404 status nor a note otherwise, so AuditSecretValueReadDenials
			// would write no row. A no-op on routes without a note.
			core.NoteSecretReadDenial(r.Context(), core.SecretReadDeniedInternalError)
			w.Header().Set("Retry-After", authorizeLookupUnavailableRetryAfter)
			sendError(w, "ServiceUnavailable", authorizeLookupUnavailableMessage, http.StatusServiceUnavailable, nil)
			return true
		}
		log.Printf("WARNING: authorization lookup failed, denying: handler permission check error=%q", err.Error())
	}
	if err != nil || !allowed {
		forbidden()
		return true
	}
	return false
}

// authorizeLookupRefusalError is a refusal returned as an error by a helper that
// ran a permission lookup, carrying the lookup's error so the caller can tell a
// storage outage (503) from a denial (403). Error() is the fixed refusal text, so
// the storage error never reaches a client.
type authorizeLookupRefusalError struct {
	msg   string
	cause error
}

func (e *authorizeLookupRefusalError) Error() string { return e.msg }
func (e *authorizeLookupRefusalError) Unwrap() error { return e.cause }

// authorizeLookupRefusal builds the error for a helper's `err != nil || !allowed`
// refusal: a plain error when the lookup succeeded and denied (cause == nil),
// otherwise one that carries the lookup error for refuseWithAuthorizeError.
func authorizeLookupRefusal(cause error, msg string) error {
	if cause == nil {
		return errors.New(msg)
	}
	return &authorizeLookupRefusalError{msg: msg, cause: cause}
}

// refuseWithAuthorizeError writes the answer for an error built by
// authorizeLookupRefusal: 503 + Retry-After when its lookup failed with a storage
// outage, otherwise a 403 "Forbidden" carrying err's text (a denial, or a lookup
// error the classifier does not recognise: fail closed).
func refuseWithAuthorizeError(w http.ResponseWriter, r *http.Request, err error) {
	forbidden := func() { sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil) }
	var lookup *authorizeLookupRefusalError
	if errors.As(err, &lookup) {
		refuseUnlessAuthorized(w, r, false, lookup.cause, forbidden)
		return
	}
	forbidden()
}
