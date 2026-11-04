package authzdiff

import (
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// Outcome is the single vocabulary every layer is mapped into (OUTCOMES.md).
type Outcome string

const (
	Allowed Outcome = "allowed"
	Denied  Outcome = "denied"
	Other   Outcome = "other"
)

// result is one leg's mapped outcome plus a NON-SENSITIVE detail for the
// report: an HTTP status, a gRPC code, or a core error's sentinel class —
// never a body, a message carrying values, or a request.
type result struct {
	Outcome Outcome
	Detail  string
}

// coreOutcome maps a core error by identity only (OUTCOMES.md, core row).
// errAdminAuthorityRequired is unexported and, by decision (b), stays Other:
// its pairs land in the mapping-gap bucket.
func coreOutcome(err error) result {
	switch {
	case err == nil:
		return result{Allowed, "nil"}
	case errors.Is(err, core.ErrPermissionDenied):
		return result{Denied, "ErrPermissionDenied"}
	case errors.Is(err, core.ErrBreakGlassListForbidden):
		return result{Denied, "ErrBreakGlassListForbidden"}
	case errors.Is(err, core.ErrAccessOutsideSchedule):
		return result{Denied, "ErrAccessOutsideSchedule"}
	case errors.Is(err, core.ErrConnectRefNotPermitted):
		return result{Denied, "ErrConnectRefNotPermitted"}
	}
	return result{Other, "untyped-error"}
}

// restOutcome maps an HTTP status (OUTCOMES.md, REST row). existing reports
// that the addressed target was seeded (always true in this harness — the
// precondition that lets 404 mean "denied").
func restOutcome(code int, body string) result {
	d := http.StatusText(code)
	switch {
	case code >= 200 && code < 300:
		return result{Allowed, d}
	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusNotFound:
		return result{Denied, d}
	case code == http.StatusBadGateway && strings.Contains(body, core.ErrConnectUnknownConnector.Error()):
		return result{Denied, "502-connect-collapse"}
	}
	return result{Other, d}
}

// grpcOutcome maps a gRPC error (OUTCOMES.md, gRPC row).
func grpcOutcome(err error) result {
	if err == nil {
		return result{Allowed, "OK"}
	}
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
		return result{Denied, st.Code().String()}
	case codes.FailedPrecondition:
		if strings.Contains(st.Message(), core.ErrConnectUnknownConnector.Error()) {
			return result{Denied, "FailedPrecondition-connect-collapse"}
		}
	}
	return result{Other, st.Code().String()}
}
