package httpx

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	HdrContentType         = "Content-Type"
	HdrXContentTypeOptions = "X-Content-Type-Options"
	MimeApplicationJSON    = "application/json"
)

// SendSuccess sends a successful JSON response
//
// The envelope always carries "success": true (in addition to the implicit 2xx
// status code). Every internal/storage/store/remote_*.go method backing
// storage.type: remote decodes the upstream body into
// internal/storage/remote.APIResponse and branches on its Success field, NOT
// the HTTP status — before this field was added, that field silently defaulted
// to Go's zero value (false) for every genuinely successful response from a
// real (non-test-mock) production server, so the entire storage.type: remote
// deployment mode misreported every successful proxied read/write as a
// failure. This is a purely additive JSON key: existing consumers of the
// "data"/"message" keys are unaffected.
func SendSuccess(w http.ResponseWriter, data any, message string) {
	w.Header().Set(HdrContentType, MimeApplicationJSON)
	w.Header().Set(HdrXContentTypeOptions, "nosniff")

	response := map[string]any{
		"success": true,
		"data":    UTCTimes(data),
	}
	if message != "" {
		response["message"] = message
	}

	if err := EncodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// SendCreated writes a 201 Created JSON success response with correctly ordered
// headers. Unlike calling w.WriteHeader(201) before SendSuccess (which causes
// SendSuccess's Header().Set() calls to be silently ignored), this function sets
// Content-Type and X-Content-Type-Options before WriteHeader.
func SendCreated(w http.ResponseWriter, data any, message string) {
	SendSuccessStatus(w, http.StatusCreated, data, message)
}

// SendAccepted is SendCreated for 202 Accepted (work started in the background).
func SendAccepted(w http.ResponseWriter, data any, message string) {
	SendSuccessStatus(w, http.StatusAccepted, data, message)
}

func SendSuccessStatus(w http.ResponseWriter, status int, data any, message string) {
	w.Header().Set(HdrContentType, MimeApplicationJSON)
	w.Header().Set(HdrXContentTypeOptions, "nosniff")
	w.WriteHeader(status)
	response := map[string]any{
		"success": true,
		"data":    UTCTimes(data),
	}
	if message != "" {
		response["message"] = message
	}
	if err := EncodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// ClientSafe returns a generic, client-safe message in place of err's raw
// Error() text. Use it at the fallback/default branch of an error path once
// the caller has already carved out the small set of deliberately-crafted,
// known-safe outcomes (validation messages, "not found", "already exists",
// etc.) — everything left over is assumed to originate from a lower layer
// (database/ORM/driver, an upstream secret-store connector, a parser) whose
// raw text can leak schema, driver, or hostname details that help an
// attacker fingerprint the backend (backlog #116). The caller MUST still log
// the original err server-side (e.g. via log.Printf) before calling this —
// ClientSafe only sanitizes the copy that reaches the client.
func ClientSafe(err error) string {
	if err == nil {
		return ""
	}
	return "an internal error occurred; please try again or contact support if the problem persists"
}

// ErrorMessageFor is the message for an error response whose status is decided at
// run time: err's own text for a 4xx (the core validation message the caller needs
// to correct the request), ClientSafe's generic text for a 5xx, with err logged.
// A raw err.Error() on a 500 branch would hand the client a storage or driver error
// (TestNoRawErrorTextOnServerErrors).
func ErrorMessageFor(status int, err error) string {
	if status >= http.StatusInternalServerError {
		log.Printf("internal error (HTTP %d), not sent to client: %v", status, err)
		return ClientSafe(err)
	}
	return err.Error()
}

// GoSafe runs fn in a detached goroutine with panic recovery. Auth handlers
// spawn "fire and forget" goroutines for side effects (audit logging,
// last-login stamps) so the HTTP response isn't blocked on that I/O — but
// those goroutines run on the hottest, lowest-privilege request path (every
// login attempt), and are NOT covered by the HTTP server's per-request
// recovery middleware, which only guards the goroutine actually serving the
// request. A panic in a bare `go func(){...}()` here (nil pointer, index
// out of range, etc., even in "just logging" code) would crash the entire
// process for every in-flight user — a low-privilege DoS lever (backlog
// #243). GoSafe closes that gap: any panic in fn is recovered and logged
// instead of taking the server down. Use it in place of a bare `go` for any
// detached side-effect goroutine spawned from a request handler. The actual
// recover/log/metric logic lives in besteffort.RunRecover (package
// besteffort), shared with internal/core's and server/grpc/services'
// identical GoSafe.
// goSafeWG tracks every in-flight GoSafe goroutine so tests can deterministically
// wait for detached audit/side-effect writes to land instead of guessing with a
// sleep (see DrainBackgroundGoroutines). Negligible overhead in production — one
// Add/Done pair per dispatch, no contention outside test use of the Wait below.
var goSafeWG sync.WaitGroup

// DrainBackgroundGoroutines blocks until every GoSafe goroutine dispatched so far
// by this package has returned. Test-only observability hook: production code has
// no reason to call it (GoSafe is fire-and-forget by design), but a test asserting
// on an async side effect (e.g. an audit row) needs a deterministic point to scan
// at, not a fixed sleep that can race a slow write and silently miss a real leak.
func DrainBackgroundGoroutines() {
	goSafeWG.Wait()
}

func GoSafe(fn func()) {
	goSafeWG.Go(func() {
		defer besteffort.RunRecover("http.goSafe")()
		fn()
	})
}

// MustParseUintParam parses a named URL parameter as a uint, sending a 400 error on failure.
// On failure it writes a 400 response and returns (0, false); the caller should return immediately.
// Eliminates repeated ParseUint+SendError blocks across handler files.
func MustParseUintParam(w http.ResponseWriter, r *http.Request, param, errKey, errMsg string) (uint, bool) {
	v, err := strconv.ParseUint(chi.URLParam(r, param), 10, 32)
	if err != nil {
		SendError(w, errKey, errMsg, http.StatusBadRequest, nil)
		return 0, false
	}
	return uint(v), true
}

// MustParseProjectID extracts and validates the "id" URL parameter as a uint project ID.
// On failure it writes a 400 response and returns (0, false); the caller should return immediately.
func MustParseProjectID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	return MustParseUintParam(w, r, "id", "InvalidParameter", ErrInvalidProjectID)
}

// MustGetUser retrieves the authenticated user from the request context.
// On failure it writes a 401 response and returns (nil, false); the caller should return immediately.
// Eliminates the repeated 4-line GetUserFromContext+SendError block across handler files.
func MustGetUser(w http.ResponseWriter, r *http.Request) (*middleware.UserContext, bool) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		SendError(w, "Unauthorized", ErrUserContext, http.StatusUnauthorized, nil)
		return nil, false
	}
	return user, true
}

// MustGetHumanUser is MustGetUser for routes that act on the caller's own user
// record (sessions, personal access tokens, impersonation, self-share). A machine
// identity authenticates with UserID 0 (ADR-030), which the core layer rejects as a
// validation error; without this guard the handler mapped that to a 500. A machine
// principal on a user-only route is the caller's mistake: 403 with the standard
// error body, the same status the router's own principal gates use.
func MustGetHumanUser(w http.ResponseWriter, r *http.Request) (*middleware.UserContext, bool) {
	user, ok := MustGetUser(w, r)
	if !ok {
		return nil, false
	}
	if user.ActorKind() == core.ActorTypeMachine {
		SendError(w, "Forbidden", ErrUserOnlyEndpoint, http.StatusForbidden, nil)
		return nil, false
	}
	return user, true
}

// MustDecodeBody decodes the JSON request body into v.
// On failure it writes a 400 response and returns false; the caller should return immediately.
// Eliminates the repeated 4-line json.NewDecoder+SendError block across handler files.
func MustDecodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		SendError(w, "InvalidJSON", ErrInvalidRequestBody, http.StatusBadRequest, nil)
		return false
	}
	return true
}

// SendError sends an error JSON response
//
// Explicitly carries "success": false. This is not strictly load-bearing for
// internal/storage/remote.HTTPClient today: this body's "error" key is a bare
// string, which doesn't unmarshal into APIResponse.Error's *APIError struct
// type, so json.Unmarshal already fails and makeRequest's parse-failure branch
// synthesizes its own Success:false/Error response instead of ever reading
// this body's fields. That's an accidental, fragile safety net (it would stop
// working the moment this "error" key were ever reshaped into an object to
// match APIError) — writing the field explicitly here means the error path no
// longer depends on that coincidence.
func SendError(w http.ResponseWriter, errorType, message string, statusCode int, details any) {
	w.Header().Set(HdrContentType, MimeApplicationJSON)
	w.Header().Set(HdrXContentTypeOptions, "nosniff")
	w.WriteHeader(statusCode)

	response := map[string]any{
		"success": false,
		"error":   errorType,
		"message": message,
		"code":    statusCode,
	}
	if details != nil {
		response["details"] = details
	}

	if err := EncodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}
