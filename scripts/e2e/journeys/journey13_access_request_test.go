//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_AccessRequest is J26: a zero-grant user requests access to a
// project, an admin approves it and the requester can then read a secret
// they couldn't before; a second requester is denied and keeps no access; a
// third request is withdrawn by its own requester before anyone reviews it;
// and a requester who later holds review rights (via the first approval)
// cannot approve their own, separate, later request -- the maker-!=-checker
// guard (internal/core/invitations.go: "a requester cannot approve their own
// access request").
//
// `request access --project-id` is used throughout for the zero-grant
// requester (#2360, fixed): the project-NAME resolution every other request
// subcommand still uses (resolveRequestProjectID -> GET /api/v1/projects) is
// gated on a GLOBAL permission a zero-grant or project-scoped-only caller
// never holds (confirmed live by journey2's own N2 finding). #2360's own body
// names `request access`/`list`/`withdraw`/`review` as ALL affected and
// proposes `--project-id` on all four -- only `access` has shipped it so
// far. Withdraw and the self-approval-attempt below therefore go over REST
// directly (both routes accept any authenticated caller with no project-name
// resolution involved -- server/http/router.go: CreateAccessRequest and
// WithdrawAccessRequest carry no RequireScopedPermission), which is the same
// workaround shape the brief itself prescribes for the request step. Noted
// as a live, still-open gap in this journey's PR description, not re-filed
// (#2360 already covers it).
func TestJourney_AccessRequest(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j13-access-request"
		envName     = "development"
		secretName  = "prod-db-password"
		secretValue = "j13-secret-value-4f8a"
		userPass    = "Ferrous-Quartz-29-Dell!"
		requesterU  = "j13-requester"
		requesterEm = "j13-requester@example.invalid"
		deniedU     = "j13-denied"
		deniedEm    = "j13-denied@example.invalid"
	)

	adminToken := adminLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	// ── Setup: a project with a secret, and two zero-grant human users ──────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	projID := projectID(t, s, adminToken, projName)
	envID := environmentID(t, s, adminToken, projID, envName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", secretName,
		"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", secretValue)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", requesterU, "--email", requesterEm, "--password", userPass)
	runCLI(t, cliBin, aEnv, "user", "create", "--username", deniedU, "--email", deniedEm, "--password", userPass)

	requesterToken := adminLogin(t, s, requesterU, userPass)
	requesterEnvCLI := tokenEnv(s, requesterToken)
	deniedToken := adminLogin(t, s, deniedU, userPass)
	deniedEnvCLI := tokenEnv(s, deniedToken)

	ref := fmt.Sprintf("%s/%s/%s", projName, envName, secretName)

	// Before any request: neither user can read the secret.
	runCLIExpectErr(t, cliBin, requesterEnvCLI, "secret", "get", "--ref", ref)
	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)

	// ── Approve path: request -> approve -> requester can now read ──────────

	reqOut := runCLI(t, cliBin, requesterEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--role", "project_admin", "--reason", "need prod access")
	req1ID := parseAccessRequestID(t, reqOut)

	approveOut := runCLI(t, cliBin, aEnv, "request", "review",
		"--id", strconv.Itoa(req1ID), "--action", "approve", "--project", projName, "--role", "project_admin")
	if !strings.Contains(approveOut, "approved") {
		t.Fatalf("expected `request review --action approve` to confirm approval, got:\n%s", approveOut)
	}

	// The real outcome, not just the command's own exit status: the requester
	// could not read before, and can now.
	readOut := runCLI(t, cliBin, requesterEnvCLI, "secret", "get", "--ref", ref)
	if v := parseDecryptedValue(t, readOut); v != secretValue {
		t.Fatalf("approved requester's read: want %q, got %q", secretValue, v)
	}

	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.approved", fmt.Sprintf("access request %d", req1ID))

	// ── Self-approval is refused ─────────────────────────────────────────────
	// The requester now holds project_admin on projID (the grant just made),
	// so they hold roles.assign at that scope -- enough to pass the review
	// route's RequireScopedPermission gate -- and files a SEPARATE, later
	// request to reach the maker-!=-checker guard itself, not a permission
	// denial. Over REST directly (see this test's doc comment): the CLI's
	// `request review --project <name>` can't be driven by a project-scoped
	// (not global) caller either, the same #2360-shaped gap.

	selfReqEnv := restExpect(t, s, requesterToken, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/access-requests", projID),
		map[string]string{"suggested_role": "project_viewer", "reason": "second request, for the self-approval check"},
		http.StatusCreated)
	req2ID := decodeAccessRequestID(t, selfReqEnv.Data)

	selfApprove := restCall(t, s, requesterToken, http.MethodPut,
		fmt.Sprintf("/api/v1/projects/%d/access-requests/%d", projID, req2ID),
		map[string]string{"action": "approve"})
	if selfApprove.StatusCode != http.StatusForbidden {
		t.Fatalf("self-approval: want HTTP %d, got %d: %s", http.StatusForbidden, selfApprove.StatusCode, string(selfApprove.Raw))
	}
	if !strings.Contains(selfApprove.Message, "cannot approve their own") {
		t.Fatalf("self-approval: want the maker-!=-checker refusal message, got: %s", selfApprove.Message)
	}

	// ── Deny path: a second requester is rejected and keeps no access ───────

	deniedReqOut := runCLI(t, cliBin, deniedEnvCLI, "request", "access",
		"--project-id", strconv.Itoa(projID), "--reason", "also need access")
	req3ID := parseAccessRequestID(t, deniedReqOut)

	rejectOut := runCLI(t, cliBin, aEnv, "request", "review",
		"--id", strconv.Itoa(req3ID), "--action", "reject", "--project", projName, "--reason", "not justified")
	if !strings.Contains(rejectOut, "rejected") {
		t.Fatalf("expected `request review --action reject` to confirm rejection, got:\n%s", rejectOut)
	}

	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)
	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.rejected", fmt.Sprintf("access request %d", req3ID))

	// ── Withdraw path: the denied user requests again, then withdraws it
	// themselves before anyone reviews it ────────────────────────────────────

	withdrawReqEnv := restExpect(t, s, deniedToken, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/access-requests", projID),
		map[string]string{"reason": "trying again"}, http.StatusCreated)
	req4ID := decodeAccessRequestID(t, withdrawReqEnv.Data)

	restExpect(t, s, deniedToken, http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/access-requests/%d/withdraw", projID, req4ID), nil, http.StatusOK)

	listEnv := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/projects/%d/access-requests", projID), nil, http.StatusOK)
	var listData struct {
		AccessRequests []struct {
			ID    uint   `json:"ID"`
			State string `json:"State"`
		} `json:"access_requests"`
	}
	if err := json.Unmarshal(listEnv.Data, &listData); err != nil {
		t.Fatalf("decode access-requests list: %v\nraw: %s", err, listEnv.Data)
	}
	found := false
	for _, r := range listData.AccessRequests {
		if r.ID == req4ID {
			found = true
			if r.State != "withdrawn" {
				t.Fatalf("withdrawn request %d: want state \"withdrawn\", got %q", req4ID, r.State)
			}
		}
	}
	if !found {
		t.Fatalf("withdrawn request %d not found in project %d's access-request list", req4ID, projID)
	}
	// The withdrawer still has no access (withdrawing your own request must
	// not itself grant anything).
	runCLIExpectErr(t, cliBin, deniedEnvCLI, "secret", "get", "--ref", ref)
	assertAccessRequestAudit(t, s, adminToken, projID, "access_request.withdrawn", fmt.Sprintf("request %d", req4ID))
}

// accessRequestIDRe is anchored to the "Access requested: id=N" line
// specifically -- with --project-id, runRequestAccess ALSO prints "Requesting
// access to project id=<projectID>..." earlier in the same output, and a bare
// `id=(\d+)` regex matches that project-ID echo first (it comes first in the
// combined stdout), silently returning the wrong number.
var accessRequestIDRe = regexp.MustCompile(`Access requested: id=(\d+)`)

// parseAccessRequestID extracts the numeric request ID from `request
// access`'s stdout ("Access requested: id=%d project=...").
func parseAccessRequestID(t *testing.T, cliOutput string) int {
	t.Helper()
	m := accessRequestIDRe.FindStringSubmatch(cliOutput)
	if m == nil {
		t.Fatalf("could not find \"id=<N>\" in `request access` output:\n%s", cliOutput)
	}
	id, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse access request ID %q: %v", m[1], err)
	}
	return id
}

// decodeAccessRequestID extracts the numeric ID from a raw
// POST .../access-requests response's {"access_request": {"ID": N, ...}}
// body (models.AccessRequest's untagged, PascalCase wire shape).
func decodeAccessRequestID(t *testing.T, data json.RawMessage) uint {
	t.Helper()
	var wrapper struct {
		AccessRequest struct {
			ID uint `json:"ID"`
		} `json:"access_request"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("decode access_request response: %v\nraw: %s", err, data)
	}
	if wrapper.AccessRequest.ID == 0 {
		t.Fatalf("access_request response had no ID: %s", data)
	}
	return wrapper.AccessRequest.ID
}

// assertAccessRequestAudit confirms an audit event of the given action type,
// scoped to projID, whose description contains descSubstr, was recorded --
// the "assert the effect, not the return value" check for every access-
// request state transition above.
func assertAccessRequestAudit(t *testing.T, s *harness.Server, adminToken string, projID int, action, descSubstr string) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/audit/search?project_id=%d&action=%s&limit=50", projID, action), nil, http.StatusOK)
	var data struct {
		Events []struct {
			Description string `json:"description"`
		} `json:"events"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode audit search for action %q: %v\nraw: %s", action, err, env.Data)
	}
	for _, e := range data.Events {
		if strings.Contains(e.Description, descSubstr) {
			return
		}
	}
	t.Fatalf("no audit event with action %q and description containing %q found for project %d", action, descSubstr, projID)
}
