// lookup_verdict_status_oracle_test.go — oracle (h), #3457: a storage fault on a
// credential or permission LOOKUP must not be answered with a verdict.
//
// What was missing
// ----------------
// #3326 (PROD-OPS-1): with PostgreSQL unreachable, every valid machine token, PAT
// and session answered 401, was negative-cached and charged to the caller's IP.
// An operational drill found it. The faultstorage fuzzers drove the very same
// shape (a fault on the credential read) and accepted it, because no oracle
// judged the STATUS of a refused request: (c) only forbids success, (a)/(d) only
// compare state. A 401 or 403 looked like any other refusal.
//
// The rule
// --------
// A refused request whose injected fault hit a credential lookup or a permission
// lookup must not answer a verdict (HTTP 401/403, gRPC Unauthenticated/
// PermissionDenied): the credential or the caller's rights were never judged, so
// the answer is a retryable 503 / Unavailable (or another non-verdict failure).
// The only exceptions are the reviewed oracleAByDesignErrors rows that declare
// the verdict-shaped answer on purpose (the post-verdict login rows: the password
// or code matched, the fault came after, and the decided outcome is the wrong-
// credential response). No other exception exists; a new one needs a reason line
// and an issue, in a new registry file.
//
// The injected error is outage-shaped for these methods
// -----------------------------------------------------
// The fuzzer's usual injected error (errFuzzInjected) is an opaque errors.New.
// The permission-lookup classifier (core.IsAuthorizeTransient) deliberately
// leaves an error it does not recognise as a fail-closed DENIAL ("a verdict-shaped
// error must never be reported as an outage"), so with the opaque error a 403 on
// a permission lookup is the documented answer, not a defect. To judge what a
// database outage does, a fault on one of isLookupFaultMethod's methods is armed with
// errFuzzOutage, which wraps a refused connection (the shape pgx and database/sql
// give an unreachable database) around the usual message. The credential
// classification (credentialLookupError) treats every non-"not found" error as a
// fault, so it answers 503 for either shape; the permission lookups do not, and
// that is the half this shape makes visible.
//
// What this does not do
// ---------------------
//   - It reads the response status only. It does not prove the 503 carries
//     Retry-After, is uncached, or that no brute-force strike was charged; the
//     core and middleware tests of #3326 / #3853 own those.
//   - It judges the faulted call's own answer. A lookup whose failure is absorbed
//     by a fallback and the request then succeeds is oracle (c)'s business.
//   - It covers the ops in opCatalog and the lookup methods listed below. A
//     lookup method missing from credentialLookupFaultMethods / authzReadMethods is
//     not judged; TestLookupFaultMethods_AreStorageMethods only proves the listed
//     credential names exist.
package faultops

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// errFuzzOutage is errFuzzInjected shaped like an unreachable database: it still
// carries errFuzzInjected's message (log-substring evidence relies on it), and
// errors.Is/As see a refused TCP connection (a net.Error), which is what
// core.IsAuthorizeTransient and the transient classifications recognise.
var errFuzzOutage = fmt.Errorf("%w: %w", errFuzzInjected,
	&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})

// credentialLookupFaultMethods are the storage reads that decide whether a
// credential (session, PAT, machine token, federated machine) or its owning
// account exists and is usable: the Validate*Token lookups in internal/core
// (credentialLookupError call sites) and the account read they follow with.
var credentialLookupFaultMethods = []string{
	"GetSession",
	"GetUser",
	"GetPersonalAccessTokenByHash",
	"GetMachineIdentityCredentialByHash",
	"GetMachineIdentity",
	"GetMachineByOIDCSubject",
}

// isLookupFaultMethod reports whether method is one the rule judges: the credential lookups
// above and the permission lookups oracle (c) already knows (authzReadMethods).
func isLookupFaultMethod(method string) bool {
	if authzReadMethods[method] {
		return true
	}
	for _, m := range credentialLookupFaultMethods {
		if m == method {
			return true
		}
	}
	return false
}

// injectedErrorFor is the error the fuzzer arms for a fault on method.
func injectedErrorFor(method string) error {
	if isLookupFaultMethod(method) {
		return errFuzzOutage
	}
	return errFuzzInjected
}

// isVerdictShapedAnswer reports whether a refused op result answers a verdict:
// HTTP 401/403 or gRPC Unauthenticated/PermissionDenied (opResult.Detail's two
// formats, see httpResult and the gRPC result builders).
func isVerdictShapedAnswer(r opResult) bool {
	if r.Success {
		return false
	}
	d := r.Detail
	return strings.HasPrefix(d, "HTTP 401") || strings.HasPrefix(d, "HTTP 403") ||
		strings.HasPrefix(d, "Unauthenticated") || strings.HasPrefix(d, "PermissionDenied")
}

// verdictAnswerByDesign returns the reviewed oracleAByDesignErrors row, if any,
// for this (op, method, kind, nth): the post-verdict login rows, where the
// credential matched, the fault came after, and the refusal is the decided
// outcome. A row that pins a wrongCredentialResponse excuses the status only when
// the run answered byte-identically to it; a row without one (the WebAuthn rows)
// excuses it on the tuple alone, as the row itself does for the state diff.
func verdictAnswerByDesign(in oracleInput) *oracleAByDesignError {
	for i := range oracleAByDesignErrors {
		e := &oracleAByDesignErrors[i]
		if e.op != in.op || e.method != in.method || e.kind != in.kind {
			continue
		}
		if e.nth > 0 && e.nth != in.nth {
			continue
		}
		if e.wrongCredentialResponse != "" && in.result.Detail != e.wrongCredentialResponse {
			continue
		}
		return e
	}
	return nil
}

// lookupVerdictOrderDependent are ops whose verdict-shaped answer to a lookup fault
// is real (#3873) but not reproducible per drive: the first drive in a process
// answers 401 and later drives of the same (op, method, nth) do not, so a
// knownOpenTolerances row would read as dead on the staleness guard depending on
// test order (observed: 9 of 9 end-impersonation rows flip between two consecutive
// drives). Exempted by op, with the reason, until #3873 fixes the answer.
// Remove the entry in the PR that closes the end-impersonation case of #3873.
var lookupVerdictOrderDependent = map[string]string{
	"REST POST /api/v1/auth/end-impersonation": "#3873: answers 401 to a lookup outage on the first drive only; order-dependent, cannot carry a staleness-checked tolerance row",
}

// lookupVerdictViolation returns the oracle (h) finding for one run, or "" when
// the run is fine. in.kind KindEffectThenError is judged like KindError: the
// lookup returned its error either way.
func lookupVerdictViolation(in oracleInput) string {
	if !isLookupFaultMethod(in.method) || !isVerdictShapedAnswer(in.result) {
		return ""
	}
	if verdictAnswerByDesign(in) != nil || lookupVerdictOrderDependent[in.op] != "" {
		return ""
	}
	return fmt.Sprintf("ORACLE (h) VIOLATION — a storage fault on the lookup %s answered a verdict, not an outage "+
		"(expected 503 / Unavailable or another non-verdict failure): %s", in.method, in.result.Detail)
}

// checkLookupVerdictStatus reports oracle (h) through the fuzz verdict. A filed,
// not-yet-fixed finding may be tolerated the usual way, by a knownOpenTolerances
// row naming oracle "h" (matchingKnownOpen matches the letter exactly), with its
// issue and expiry; there is no other exemption.
func checkLookupVerdictStatus(t fuzzVerdict, label string, in oracleInput) {
	t.Helper()
	msg := lookupVerdictViolation(in)
	if msg == "" {
		return
	}
	if known := matchingKnownOpen(in, "h", nil); known != nil {
		t.Logf("KNOWN-OPEN (%s): %s: %s", known.findingDoc, label, msg)
		return
	}
	t.Errorf("%s: %s", label, msg)
}

func TestLookupFaultMethods_AreStorageMethods(t *testing.T) {
	all := map[string]bool{}
	for _, m := range storageInterfaceMethodNames() {
		all[m] = true
	}
	for _, m := range credentialLookupFaultMethods {
		if !all[m] {
			t.Errorf("credentialLookupFaultMethods names %q, which is not a storage.Storage method", m)
		}
	}
}

func TestErrFuzzOutage_IsOutageShapedAndKeepsTheInjectedMessage(t *testing.T) {
	if !errors.Is(errFuzzOutage, errFuzzInjected) {
		t.Fatal("errFuzzOutage must still be errFuzzInjected (log-substring evidence)")
	}
	if !errors.Is(errFuzzOutage, syscall.ECONNREFUSED) {
		t.Fatal("errFuzzOutage must look like a refused connection")
	}
	if _, ok := errors.AsType[net.Error](errFuzzOutage); !ok {
		t.Fatal("errFuzzOutage must be a net.Error")
	}
	if injectedErrorFor("LogAuditEvent") != errFuzzInjected {
		t.Fatal("a non-lookup method keeps the opaque injected error")
	}
	for _, m := range []string{"GetSession", "ResolveUserPermissionAt", "GetSecretAncestors"} {
		if injectedErrorFor(m) != errFuzzOutage {
			t.Fatalf("%s must be armed with the outage-shaped error", m)
		}
	}
}

// TestLookupVerdictViolation_Calibration pins oracle (h) in both directions on
// hand-built inputs: every verdict-shaped answer to a lookup fault is a finding,
// every outage-shaped or unrelated answer is not, and the only exemption is a
// reviewed wrongCredentialResponse row whose whole outcome the run reproduces.
func TestLookupVerdictViolation_Calibration(t *testing.T) {
	const (
		unauth = "HTTP 401: {\"code\":401,\"error\":\"Unauthorized\",\"message\":\"Invalid or expired token\"}\n"
		forbid = "HTTP 403: {\"code\":403,\"error\":\"Forbidden\",\"message\":\"permission denied\"}\n"
		unavl  = "HTTP 503: {\"code\":503,\"error\":\"ServiceUnavailable\"}\n"
	)
	in := func(op, method string, kind faultstorage.FaultKind, nth int, success bool, detail string) oracleInput {
		return oracleInput{op: op, method: method, kind: kind, nth: nth, result: opResult{Success: success, Detail: detail}}
	}
	const rest = "REST POST /api/v1/secrets/"
	for _, tc := range []struct {
		name      string
		in        oracleInput
		violation bool
	}{
		{"credential lookup answered 401 (the #3326 shape)", in(rest, "GetSession", faultstorage.KindError, 1, false, unauth), true},
		{"credential lookup answered 503", in(rest, "GetSession", faultstorage.KindError, 1, false, unavl), false},
		{"credential lookup, gRPC Unauthenticated", in("GRPC x", "GetPersonalAccessTokenByHash", faultstorage.KindError, 1, false, "Unauthenticated: invalid token"), true},
		{"credential lookup, gRPC Unavailable", in("GRPC x", "GetPersonalAccessTokenByHash", faultstorage.KindError, 1, false, "Unavailable: try again"), false},
		{"permission lookup answered 403", in(rest, "ResolveUserPermissionAt", faultstorage.KindError, 1, false, forbid), true},
		{"permission lookup, gRPC PermissionDenied", in("GRPC x", "ResolveMachinePermissionAt", faultstorage.KindError, 1, false, "PermissionDenied: no"), true},
		{"permission lookup answered 503", in(rest, "ResolveUserPermissionAt", faultstorage.KindError, 1, false, unavl), false},
		{"effect-then-error is judged like an error", in(rest, "GetSession", faultstorage.KindEffectThenError, 1, false, unauth), true},
		{"a verdict from a method that is not a lookup", in(rest, "LogAuditEvent", faultstorage.KindError, 1, false, forbid), false},
		{"a success is not judged here (oracle c owns it)", in(rest, "GetSession", faultstorage.KindError, 1, true, "HTTP 200: {}"), false},
		{"reviewed post-verdict login row, whole outcome reproduced",
			in("REST POST /auth/login", "GetUserPermissions", faultstorage.KindError, 1, false, wrongPasswordResponse), false},
		{"same login row, a different 401 body is not the decided outcome",
			in("REST POST /auth/login", "GetUserPermissions", faultstorage.KindError, 1, false, unauth), true},
		{"same login method on an op without a row",
			in(rest, "GetUserPermissions", faultstorage.KindError, 1, false, wrongPasswordResponse), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := lookupVerdictViolation(tc.in)
			if tc.violation && got == "" {
				t.Fatalf("expected an oracle (h) violation for %s %s -> %s", tc.in.op, tc.in.method, tc.in.result.Detail)
			}
			if !tc.violation && got != "" {
				t.Fatalf("unexpected oracle (h) violation: %s", got)
			}
		})
	}
}
