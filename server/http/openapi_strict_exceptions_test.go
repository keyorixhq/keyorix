package http

// openapi_strict_exceptions_test.go — the SHRINK-ONLY guard for the STRICT
// FuzzOpenAPIStateful gate (task V9). It enforces, against the REAL NewRouter
// stack, that testdata/openapi_strict_exceptions.tsv is exactly the set of
// still-unfixed undeclared-5xx defects strict mode waives:
//
//   - CAN ONLY SHRINK: every row has a deterministic reproducer that must still
//     return the listed undeclared 5xx. A defect that was fixed (no longer 5xx,
//     or now declared by the spec) makes its reproducer assertion fail, forcing
//     the row's removal. You cannot leave a stale waiver behind.
//   - CANNOT GROW SILENTLY: the (operation,status) set in the file must EXACTLY
//     equal the fuzzer's own waiver set (osKnownUndeclared5xx). A new undeclared
//     5xx cannot be waived in the fuzzer without a file row (issue + owner), and
//     no file row can exist without a matching fuzzer waiver. Strict mode is
//     separately FATAL on any undeclared 5xx not in osKnownUndeclared5xx, so a
//     genuinely new class fails the nightly gate until it is triaged into BOTH.
//
// This is the committed, deterministic proof that the waiver list is honest: it
// is watched to fail (red/green proof in the PR/report), not merely asserted.

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// osStrictExceptionsFile is read relative to the package dir (Go sets the test's
// working directory to the package directory).
const osStrictExceptionsFile = "testdata/openapi_strict_exceptions.tsv"

type osStrictException struct {
	op      string
	status  int
	verdict string
	issue   string
	owner   string
	reason  string
}

func osReadStrictExceptions(t *testing.T) []osStrictException {
	t.Helper()
	f, err := os.Open(osStrictExceptionsFile)
	if err != nil {
		t.Fatalf("open %s: %v", osStrictExceptionsFile, err)
	}
	defer f.Close()
	var rows []osStrictException
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if cols[0] == "operation" { // header
			continue
		}
		if len(cols) < 6 {
			t.Fatalf("malformed row (want 6 tab-separated cols): %q", line)
		}
		code, err := strconv.Atoi(cols[1])
		if err != nil {
			t.Fatalf("bad status in row %q: %v", line, err)
		}
		rows = append(rows, osStrictException{cols[0], code, cols[2], cols[3], cols[4], cols[5]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", osStrictExceptionsFile, err)
	}
	return rows
}

// osStrictReproducers returns, per operationId, a deterministic closure that
// drives the real router and returns the final HTTP status. Each one reproduces
// the exact still-unfixed defect its exceptions.tsv row documents. A row whose
// operation has no reproducer here is a hard failure (an untested waiver).
func osStrictReproducers(w *osWorld) map[string]func(t *testing.T) int {
	do := func(method, target, tok, body string) int {
		var req *http.Request
		if body != "" {
			req = httptest.NewRequest(method, target, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, target, nil)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return osExec(w, req).Code
	}
	sA := strconv.FormatUint(uint64(w.seedPools["secrets"][0]), 10)
	mach := w.tokens[osPrincMachine]
	admin := w.tokens[osPrincGlobalAdmin]
	projB := strconv.FormatUint(uint64(w.seedPools["projects"][1]), 10)
	envA := strconv.FormatUint(uint64(w.seedPools["environments"][0]), 10)

	// Family A: a machine principal on a secret read-metadata route reaches the
	// legacy default:500 branch (the admin gets 200).
	machineRead := func(sub string) func(t *testing.T) int {
		return func(t *testing.T) int {
			if mach == "" {
				t.Skip("machine token not seeded")
			}
			return do(http.MethodGet, "/api/v1/secrets/"+sA+"/"+sub, mach, "")
		}
	}
	// Family B: a duplicate-name template create — the DB unique violation is
	// classified errclass.Internal (undeclared 500) rather than 409 Conflict.
	dupCreate := func(path, body string) func(t *testing.T) int {
		return func(t *testing.T) int {
			_ = do(http.MethodPost, path, admin, body) // first create (201 or already-exists)
			return do(http.MethodPost, path, admin, body)
		}
	}

	return map[string]func(t *testing.T) int{
		"getSecretAuditTrail":           machineRead("audit"),
		"getSecretOwnershipHistory":     machineRead("ownership-history"),
		"listAccessors":                 machineRead("access"),
		"createSecretTemplate":          dupCreate("/api/v1/secret-templates", `{"name":"osf-strict-dup"}`),
		"createRejectionReasonTemplate": dupCreate("/api/v1/rejection-reason-templates", `{"name":"osf-strict-dup","reason":"because"}`),
		// An environment-scoped rotation policy whose environment (project A) does not
		// belong to the supplied project (B) hits core's PLAIN cross-tenant error, which
		// the handler's ErrInvalidInput-only check maps to an undeclared 500.
		"createRotationPolicy": func(t *testing.T) int {
			body := fmt.Sprintf(`{"name":"osf-strict-rp","scope":"environment","project_id":%s,"environment_id":%s,"interval_days":30}`, projB, envA)
			return do(http.MethodPost, "/api/v1/rotation-policies", admin, body)
		},
		"startImpersonation": func(t *testing.T) int {
			// A suspended/inactive target is refused "cannot impersonate a suspended
			// or inactive user" — not "yourself", not ErrUserNotFound — so the
			// handler switch falls through to the undeclared 500 (OPENAPI-STATEFUL-7).
			u, err := w.c.CreateUser(context.Background(), &core.CreateUserRequest{
				Username: "osf-imp-suspended", Email: "osf-imp-suspended@x.io", Password: osPassword,
			})
			if err != nil || u == nil {
				t.Fatalf("create impersonation target: %v", err)
			}
			if e := w.db.Model(&models.User{}).Where("id = ?", u.ID).
				Update("is_active", false).Error; e != nil {
				t.Fatalf("suspend target: %v", e)
			}
			return do(http.MethodPost, "/api/v1/admin/impersonate", admin,
				fmt.Sprintf(`{"user_id":%d}`, u.ID))
		},
	}
}

func TestOpenAPIStrictExceptions(t *testing.T) {
	osLoadSpec(t)
	w := osBuildWorld(t)
	t.Cleanup(func() {})

	rows := osReadStrictExceptions(t)
	if len(rows) == 0 {
		// An empty list is the SUCCESS end-state (every class fixed): assert it
		// matches the fuzzer waiver list rather than treating it as a test error.
		if len(osKnownUndeclared5xx) != 0 {
			t.Fatalf("exceptions.tsv is empty but osKnownUndeclared5xx still has %d waiver(s): remove them together", len(osKnownUndeclared5xx))
		}
		t.Log("exceptions list is empty — the undeclared-5xx class is fully closed")
		return
	}

	opByID := map[string]*osOp{}
	for i := range osOps {
		opByID[osOps[i].opID] = &osOps[i]
	}
	repro := osStrictReproducers(w)

	// (1) CAN ONLY SHRINK: every row still reproduces its undeclared 5xx.
	for _, row := range rows {
		t.Run("reproduces/"+row.op, func(t *testing.T) {
			o, ok := opByID[row.op]
			if !ok {
				t.Fatalf("exceptions.tsv names operation %q that openapi.yaml no longer declares — remove the row", row.op)
			}
			fn, ok := repro[row.op]
			if !ok {
				t.Fatalf("exceptions.tsv row %q has no deterministic reproducer in osStrictReproducers — an unwatched waiver is not a waiver", row.op)
			}
			got := fn(t)
			if got != row.status {
				t.Fatalf("op=%s: expected the listed undeclared status %d but got %d — if the defect is fixed, delete this row (the list can only shrink)", row.op, row.status, got)
			}
			if got < 500 {
				t.Fatalf("op=%s: listed status %d is not a 5xx; this file tracks undeclared 5xx only", row.op, got)
			}
			if osDeclaresStatus(o, got) {
				t.Fatalf("op=%s: status %d is now DECLARED by openapi.yaml — the spec gap is closed, delete this row", row.op, got)
			}
		})
	}

	// (2) CANNOT GROW SILENTLY: the file's (op,status) set == the fuzzer's waiver
	// set (osKnownUndeclared5xx). Neither can drift without the other.
	fileSet := map[string]bool{}
	for _, row := range rows {
		fileSet[row.op+"|"+strconv.Itoa(row.status)] = true
	}
	waiverSet := map[string]bool{}
	for _, k := range osKnownUndeclared5xx {
		if k.opID == "" {
			t.Fatalf("osKnownUndeclared5xx has an any-op waiver (id=%s) with no single operation — cannot be pinned to an exceptions.tsv row", k.id)
		}
		waiverSet[k.opID+"|"+strconv.Itoa(k.code)] = true
	}
	for key := range fileSet {
		if !waiverSet[key] {
			t.Errorf("exceptions.tsv has %q but the fuzzer does NOT waive it (osKnownUndeclared5xx): strict mode would fail on it — add the waiver or remove the row", key)
		}
	}
	for key := range waiverSet {
		if !fileSet[key] {
			t.Errorf("osKnownUndeclared5xx waives %q but exceptions.tsv has no row for it: a waiver with no documented issue/owner is how the list grows silently — add the row", key)
		}
	}
}
