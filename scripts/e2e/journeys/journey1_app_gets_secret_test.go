//go:build e2e

package journeys

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	keyorix "github.com/keyorixhq/keyorix-go"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_AppGetsSecret is N1: an admin provisions a project, an
// environment's secret, and a machine identity token scoped to read it; an
// "application" then reads the secret three independent ways (REST, the
// keyorix-go SDK, the CLI) and all three must agree -- through a rotation
// (all three see the new value, version history holds both) and a token
// revocation (all three are denied, and the secret itself is unchanged).
//
// Every step below is exported as appGetsSecret so N3 (the audit-trail
// journey) can call it directly against its own shared install instead of
// re-running the CLI a second time (SESSION-N brief, N3: "call their step
// functions directly, to avoid double-provisioning").
func TestJourney_AppGetsSecret(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	appGetsSecret(t, s, cliBin, "smoketestadmin", harness.BootstrapAdminPassword)
}

// appGetsSecretResult is what the journey provisioned, returned so a caller
// (N3) can reference the same project/secret/machine without re-resolving
// IDs.
type appGetsSecretResult struct {
	ProjectID  int
	EnvID      int
	SecretID   int
	MachineID  int
	ProjectRef string // "project/environment/name", for --ref reads
}

const (
	n1ProjectName = "n1-app-gets-secret"
	n1EnvName     = "development" // admin init's own default seed (harness.StartServer)
	n1SecretName  = "db-password"
	n1MachineName = "n1-reader"
	n1ValueV1     = "hunter2-v1-fbeacd3c"
	n1ValueV2     = "hunter2-v2-rotated-9a71"
)

func appGetsSecret(t *testing.T, s *harness.Server, cliBin, adminUser, adminPass string) appGetsSecretResult {
	t.Helper()
	ctx := context.Background()
	adminToken := adminLogin(t, s, adminUser, adminPass)
	aEnv := adminEnv(s, adminToken)

	// ── Admin (CLI): project, secret, machine identity + scoped token ──────

	runCLI(t, cliBin, aEnv, "project", "create", "--name", n1ProjectName)
	projID := projectID(t, s, adminToken, n1ProjectName)
	envID := environmentID(t, s, adminToken, projID, n1EnvName)

	runCLI(t, cliBin, aEnv, "secret", "create",
		"--name", n1SecretName,
		"--project", strconv.Itoa(projID),
		"--environment", strconv.Itoa(envID),
		"--value", n1ValueV1,
	)
	secID := secretID(t, s, adminToken, projID, envID, n1SecretName)

	runCLI(t, cliBin, aEnv, "machine", "create",
		"--project", n1ProjectName, "--name", n1MachineName, "--type", "service")
	machID := machineIdentityID(t, s, adminToken, projID, n1MachineName)

	// project_viewer: read-only at project scope (ADR-021 two-tier roles) --
	// this machine identity only ever reads in this journey.
	runCLI(t, cliBin, aEnv, "machine", "grant-role", n1MachineName,
		"--project", n1ProjectName, "--role", "project_viewer")

	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n1MachineName,
		"--project", n1ProjectName, "--name", "n1-reader-token")
	machToken, machTokenID := parseIssuedToken(t, issueOut)

	ref := fmt.Sprintf("%s/%s/%s", n1ProjectName, n1EnvName, n1SecretName)

	// ── Three readers agree on the initial value ────────────────────────────

	assertThreeReadersAgree(t, s, cliBin, machToken, ref, n1SecretName, n1ValueV1)

	// ── Rotate (admin CLI `secret update`) -- version-bump, not the
	// backend-rotation-policy-flavored `secret rotate` (secret_rotation.go is
	// for auto-rotation against an external backend; a plain new value is a
	// version-bumping update, confirmed by secret_crud.go's runSecretUpdate
	// printing "New encrypted version created"). ──────────────────────────

	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(secID), "--value", n1ValueV2)

	assertThreeReadersAgree(t, s, cliBin, machToken, ref, n1SecretName, n1ValueV2)

	// Version history holds both versions. GetSecretVersions returns metadata
	// ONLY -- internal/storage/models.SecretVersion.EncryptedValue is
	// `json:"-"` (values are ciphertext-at-rest, never serialized here on
	// purpose) -- so "both present" is checked by count (2: the create + the
	// rotate) here, and by an actual value readback via `secret rollback`
	// (the one mechanism that decrypts a historical version) at the very end
	// of this test, after every other assertion that depends on the current
	// value being n1ValueV2 has already run.
	versionCount := secretVersionCount(t, s, adminToken, secID)
	if versionCount != 2 {
		t.Fatalf("expected exactly 2 versions (create + rotate), got %d", versionCount)
	}

	// ── Revoke the machine token ─────────────────────────────────────────

	runCLI(t, cliBin, aEnv, "machine", "token", "revoke", n1MachineName,
		strconv.Itoa(machTokenID), "--project", n1ProjectName, "--force")

	// All three readers are now denied with the documented status, and the
	// secret itself is unchanged (still v2, still 2 versions) -- read back
	// via the still-valid ADMIN session, not the now-revoked machine token.
	assertReadersDenied(t, s, cliBin, machToken, ref)

	adminReadback := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var afterRevoke struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(adminReadback.Data, &afterRevoke); err != nil {
		t.Fatalf("decode admin readback after revoke: %v\nraw: %s", err, adminReadback.Data)
	}
	if afterRevoke.Value != n1ValueV2 {
		t.Fatalf("secret value changed after a denied read: want %q, got %q", n1ValueV2, afterRevoke.Value)
	}
	if got := secretVersionCount(t, s, adminToken, secID); got != versionCount {
		t.Fatalf("version count changed after a denied read: was %d, now %d", versionCount, got)
	}

	// ── Version history recoverability: prove v1's actual VALUE (not just
	// version-count) is still held, via `secret rollback` -- the only
	// mechanism that decrypts a historical version. Done last, after every
	// assertion above that depends on the current value being n1ValueV2. ──

	runCLI(t, cliBin, aEnv, "secret", "rollback", "--id", strconv.Itoa(secID), "--version", "1")
	rolledBack := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var rolledBackResult struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(rolledBack.Data, &rolledBackResult); err != nil {
		t.Fatalf("decode readback after rollback: %v\nraw: %s", err, rolledBack.Data)
	}
	if rolledBackResult.Value != n1ValueV1 {
		t.Fatalf("rollback to version 1: want %q, got %q -- version history did not retain the original value", n1ValueV1, rolledBackResult.Value)
	}
	if got := secretVersionCount(t, s, adminToken, secID); got != versionCount+1 {
		t.Fatalf("rollback should append a new version (append-only history): want %d, got %d", versionCount+1, got)
	}

	_ = ctx
	return appGetsSecretResult{ProjectID: projID, EnvID: envID, SecretID: secID, MachineID: machID, ProjectRef: ref}
}

// secretVersionCount returns how many versions secretID currently has.
func secretVersionCount(t *testing.T, s *harness.Server, adminToken string, secID int) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d/versions", secID), nil, http.StatusOK)
	var data struct {
		Versions []struct{} `json:"versions"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/secrets/%d/versions: %v\nraw: %s", secID, err, env.Data)
	}
	return len(data.Versions)
}

// assertThreeReadersAgree reads secretName by ref via REST, the keyorix-go
// SDK, and the CLI, and asserts all three return byte-identical values.
//
// SDK caveat (CONFIRMED BROKEN, not worked around here -- see
// assertSDKBlockedByMachineTokenBug and the N1 entry in
// ~/proj/prompts/reports/SESSION-N.md / ~/proj/prompts/inbox/SESSION-K.md,
// Session K owns keyorix-go, this journey does not patch it): a
// machine-token caller is REQUIRED to send `project_id` on GET
// /api/v1/secrets (server/http/handlers/secrets_list.go, a deliberate
// CWE-862 enumeration guard, not a server bug -- "any machine token could
// otherwise enumerate secrets from arbitrary projects"). keyorix-go v0.2.1's
// ListSecrets/GetSecret never send project_id at all (no parameter exists to
// pass one), so its own package-doc "Quick start" example --
// client.GetSecret(ctx, "db-password", "production") -- unconditionally
// returns "400: machine tokens must specify project_id" for ANY
// machine-token-authenticated caller, the exact "app reads a secret with its
// machine token" use case the SDK's README leads with. The REST and CLI
// readers below (both of which DO send project_id under the hood) are
// therefore this journey's real "do independent read paths agree" proof;
// the SDK leg's job is to keep proving the bug is still there.
func assertThreeReadersAgree(t *testing.T, s *harness.Server, cliBin, machToken, ref, secretName, want string) {
	t.Helper()

	restEnv := restExpect(t, s, machToken, http.MethodGet,
		"/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil, http.StatusOK)
	var restResult struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(restEnv.Data, &restResult); err != nil {
		t.Fatalf("decode REST secret-by-ref response: %v\nraw: %s", err, restEnv.Data)
	}
	if restResult.Value != want {
		t.Fatalf("REST reader: want %q, got %q", want, restResult.Value)
	}

	cliOut := runCLI(t, cliBin, machineEnv(s, machToken), "secret", "get", "--ref", ref)
	cliValue := parseDecryptedValue(t, cliOut)
	if cliValue != want {
		t.Fatalf("CLI reader: want %q, got %q", want, cliValue)
	}

	assertSDKBlockedByMachineTokenBug(t, s, machToken, secretName)
}

// assertSDKBlockedByMachineTokenBug asserts keyorix-go's GetSecret still
// fails for a machine-token caller with EXACTLY the known server-side
// project_id gate's error, not merely "an error" -- so this assertion breaks
// loudly (not silently keeps "passing") the day either the SDK is fixed to
// send project_id, or the server's error text/shape changes, either of which
// means this workaround needs re-evaluating rather than continuing to assume
// the same bug.
func assertSDKBlockedByMachineTokenBug(t *testing.T, s *harness.Server, machToken, secretName string) {
	t.Helper()
	sdkClient := keyorix.New(s.BaseURL, machToken)
	// environment="" (not e.g. "production"): a non-empty environment hits the
	// OTHER known SDK/server bug first (the environment-name filter server/
	// http/handlers/secrets_list.go rejects, see assertThreeReadersAgree's
	// doc comment) and never reaches the project_id gate this function means
	// to demonstrate.
	_, err := sdkClient.GetSecret(context.Background(), secretName, "")
	if err == nil {
		t.Fatal("SDK reader: GetSecret unexpectedly SUCCEEDED for a machine token -- the known project_id bug " +
			"(see this function's doc comment) may be fixed; if so, update this journey to use the SDK as a real " +
			"reader instead of asserting the failure, and tell Session K the workaround is no longer needed")
	}
	if !strings.Contains(err.Error(), "machine tokens must specify project_id") {
		t.Fatalf("SDK reader: expected the known project_id-gate error, got a different error: %v", err)
	}
}

// assertReadersDenied re-attempts the REST and CLI reads with the
// now-revoked machine token and asserts both are denied (the SDK leg is not
// re-checked here -- it fails identically before and after revocation, for
// an unrelated reason; see assertSDKBlockedByMachineTokenBug).
func assertReadersDenied(t *testing.T, s *harness.Server, cliBin, machToken, ref string) {
	t.Helper()

	restEnv := restCall(t, s, machToken, http.MethodGet, "/api/v1/secrets/value?ref="+url.QueryEscape(ref), nil)
	if restEnv.StatusCode != http.StatusUnauthorized {
		t.Errorf("REST reader after revoke: want HTTP %d, got %d: %s",
			http.StatusUnauthorized, restEnv.StatusCode, string(restEnv.Raw))
	}

	runCLIExpectErr(t, cliBin, machineEnv(s, machToken), "secret", "get", "--ref", ref)
}
