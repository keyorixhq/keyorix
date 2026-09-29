//go:build e2e

// Package journeys contains Session N's customer-journey E2E tests. Unlike
// scripts/e2e's route-coverage smoke driver (which asserts "no 5xx anywhere"),
// each journey here asserts the RESULT of a realistic end-to-end scenario --
// read-back values, audit event counts, denial status codes -- exercised
// through the real keyorix-server binary, the real keyorix CLI binary, and
// the keyorix-go SDK, on a freshly bootstrapped install. Reuses
// scripts/e2e/harness for server boot/bootstrap (one boot sequence, not two
// -- see docs/TESTING_GUIDE.md's "Customer journeys" section).
package journeys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// maxRespBytes caps how much of any single API response a journey reads
// (16 MiB, matching scripts/e2e's client.go -- far above any real response
// here, just a backstop against an unbounded read).
const maxRespBytes = 16 << 20

// adminLogin performs POST /auth/login and returns the bearer token --
// journeys use this once, right after boot, to get an authenticated session
// for every admin-performed setup step (REST lookups and CLI env alike).
func adminLogin(t *testing.T, s *harness.Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(s.BaseURL+"/auth/login", "application/json", bytes.NewReader(body)) // #nosec G107 -- fixed test harness URL
	if err != nil {
		s.DumpLogAndFatal("POST /auth/login: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
		s.DumpLogAndFatal("POST /auth/login: HTTP %d: %s", resp.StatusCode, raw)
	}
	var env struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(&env); err != nil {
		t.Fatalf("decode /auth/login response: %v", err)
	}
	if env.Data.Token == "" {
		t.Fatal("/auth/login: no token in response")
	}
	return env.Data.Token
}

// restEnvelope mirrors server/http/handlers/helpers.go's sendSuccess/sendError
// JSON shape, same as scripts/e2e's own envelope type.
type restEnvelope struct {
	StatusCode int
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Message    string          `json:"message"`
	Raw        []byte
}

// restCall issues an authenticated REST request against s and returns the
// decoded envelope. Journeys use this for admin setup lookups (resolving a
// name to an ID after a CLI mutation) and for the REST leg of each journey's
// "read the same value N ways" assertion.
func restCall(t *testing.T, s *harness.Server, token, method, path string, body interface{}) restEnvelope {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s %s: marshal request body: %v", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.BaseURL+path, reader)
	if err != nil {
		t.Fatalf("%s %s: build request: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: request failed: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		t.Fatalf("%s %s: read response body: %v", method, path, err)
	}
	var env restEnvelope
	env.StatusCode = resp.StatusCode
	if len(respBytes) > 0 {
		if jerr := json.Unmarshal(respBytes, &env); jerr != nil {
			env.Raw = respBytes
		}
	}
	return env
}

// restExpect wraps restCall and fatally fails if the response status isn't
// one of want -- used for admin setup steps a journey has no reason to
// expect anything but success from (unlike a denial-path assertion, which
// calls restCall directly and checks the status itself).
func restExpect(t *testing.T, s *harness.Server, token, method, path string, body interface{}, want int) restEnvelope {
	t.Helper()
	env := restCall(t, s, token, method, path, body)
	if env.StatusCode != want {
		t.Fatalf("%s %s: expected HTTP %d, got %d: %s", method, path, want, env.StatusCode, string(env.Raw))
	}
	return env
}

// runCLI runs the built keyorix CLI binary with args against server s,
// using env (which must carry KEYORIX_SERVER and KEYORIX_TOKEN on top of
// s.CLIEnv()'s isolated HOME/PATH). Fails the test with the combined
// output on a non-zero exit -- every CLI step in a journey is expected to
// succeed unless the caller is specifically testing a denial, in which case
// use runCLIExpectErr instead.
func runCLI(t *testing.T, cliBin string, env []string, args ...string) string {
	t.Helper()
	out, err := runCLIRaw(cliBin, env, args...)
	if err != nil {
		t.Fatalf("keyorix %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// runCLIExpectErr runs the CLI expecting a non-zero exit (a denial path) and
// returns its combined output for the caller to assert on -- fails the test
// if the command unexpectedly succeeds.
func runCLIExpectErr(t *testing.T, cliBin string, env []string, args ...string) string {
	t.Helper()
	out, err := runCLIRaw(cliBin, env, args...)
	if err == nil {
		t.Fatalf("keyorix %s: expected a failure, command succeeded:\n%s", strings.Join(args, " "), out)
	}
	return out
}

func runCLIRaw(cliBin string, env []string, args ...string) (string, error) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- cliBin is this test's own built binary path, args are the test's own fixed arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built, with the journey's own fixed arguments; no external input reaches it
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// adminEnv returns the environment a `keyorix` CLI invocation needs to act
// as the admin session token (project/secret/machine setup steps).
func adminEnv(s *harness.Server, adminToken string) []string {
	return append(s.CLIEnv(), "KEYORIX_SERVER="+s.BaseURL, "KEYORIX_TOKEN="+adminToken)
}

// machineEnv returns the environment a `keyorix` CLI invocation needs to act
// as a machine identity's issued bearer token (the three-readers steps).
func machineEnv(s *harness.Server, machineToken string) []string {
	return append(s.CLIEnv(), "KEYORIX_SERVER="+s.BaseURL, "KEYORIX_TOKEN="+machineToken)
}

// ── ID resolution (admin REST lookups after a CLI mutation) ────────────────

// projectID resolves a project name to its numeric ID via GET /api/v1/projects,
// the same route the CLI's own resolveMachineProjectID uses.
func projectID(t *testing.T, s *harness.Server, adminToken, name string) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/projects", nil, http.StatusOK)
	var data struct {
		Projects []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/projects: %v\nraw: %s", err, env.Data)
	}
	for _, p := range data.Projects {
		if p.Name == name {
			return p.ID
		}
	}
	t.Fatalf("project %q not found in GET /api/v1/projects response: %s", name, env.Data)
	return 0
}

// environmentID resolves an environment name (within a project) to its
// numeric ID via GET /api/v1/projects/{id}/environments.
func environmentID(t *testing.T, s *harness.Server, adminToken string, projID int, envName string) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/environments", projID), nil, http.StatusOK)
	var data struct {
		Environments []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET /api/v1/projects/%d/environments: %v\nraw: %s", projID, err, env.Data)
	}
	for _, e := range data.Environments {
		if e.Name == envName {
			return e.ID
		}
	}
	t.Fatalf("environment %q not found in project %d's environments: %s", envName, projID, env.Data)
	return 0
}

// secretID resolves a secret's name (within a project/environment) to its
// numeric ID via GET /api/v1/secrets?project_id=..&environment_id=...
func secretID(t *testing.T, s *harness.Server, adminToken string, projID, envID int, name string) int {
	t.Helper()
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d&environment_id=%d", projID, envID)
	env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		Secrets []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
	}
	for _, sec := range data.Secrets {
		if sec.Name == name {
			return sec.ID
		}
	}
	t.Fatalf("secret %q not found in project %d env %d: %s", name, projID, envID, env.Data)
	return 0
}

// machineIdentityID resolves a machine identity's name (within a project) to
// its numeric ID via GET /api/v1/projects/{id}/machine-identities.
func machineIdentityID(t *testing.T, s *harness.Server, adminToken string, projID int, name string) int {
	t.Helper()
	path := fmt.Sprintf("/api/v1/projects/%d/machine-identities", projID)
	env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		MachineIdentities []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"machine_identities"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
	}
	for _, m := range data.MachineIdentities {
		if m.Name == name {
			return m.ID
		}
	}
	t.Fatalf("machine identity %q not found in project %d: %s", name, projID, env.Data)
	return 0
}

// ── CLI stdout parsing (steps whose result is only ever shown once) ────────

var (
	tokenLineRe = regexp.MustCompile(`(?m)^Token:\s+(\S+)$`)
	tokenIDRe   = regexp.MustCompile(`(?m)^ID:\s+(\d+)$`)
)

// parseIssuedToken extracts the raw bearer token and its numeric ID from
// `machine token issue`'s stdout -- the token is shown exactly once (it is
// hashed at rest, per ADR-030) so this is the only way a caller can obtain
// it, mirroring how a real operator would have to copy it from the terminal.
func parseIssuedToken(t *testing.T, cliOutput string) (token string, id int) {
	t.Helper()
	tm := tokenLineRe.FindStringSubmatch(cliOutput)
	if tm == nil {
		t.Fatalf("could not find 'Token:' line in `machine token issue` output:\n%s", cliOutput)
	}
	im := tokenIDRe.FindStringSubmatch(cliOutput)
	if im == nil {
		t.Fatalf("could not find 'ID:' line in `machine token issue` output:\n%s", cliOutput)
	}
	var idVal int
	if _, err := fmt.Sscanf(im[1], "%d", &idVal); err != nil {
		t.Fatalf("parse token ID %q: %v", im[1], err)
	}
	return tm[1], idVal
}

// decryptedValueRe matches the value line `secret get --ref ...`/`secret get
// --show-value` prints under the "Decrypted Value" / "---------------"
// header (cli/cmd/secret_crud.go's displaySecret).
var decryptedValueRe = regexp.MustCompile(`(?s)Decrypted Value\n-+\n(.*?)\n`)

// parseDecryptedValue extracts the secret value from `secret get`'s stdout.
func parseDecryptedValue(t *testing.T, cliOutput string) string {
	t.Helper()
	m := decryptedValueRe.FindStringSubmatch(cliOutput)
	if m == nil {
		t.Fatalf("could not find 'Decrypted Value' block in `secret get` output:\n%s", cliOutput)
	}
	return m[1]
}

var _ = context.Background // keep context imported for callers that need it
