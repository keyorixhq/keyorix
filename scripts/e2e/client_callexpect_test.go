//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// callExpectMismatchChildEnv marks the child process of
// TestCallExpect_MismatchMessageCarriesBody: only there does the mismatch run.
const callExpectMismatchChildEnv = "KEYORIX_E2E_CALLEXPECT_MISMATCH_CHILD"

// scimErrorBody is an RFC 7644 error: valid JSON that parses as the envelope
// (unknown fields ignored), so env.Raw stays empty for it.
const scimErrorBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"409","detail":"callexpect-marker userName taken"}`

// TestCallExpect_MismatchMessageCarriesBody pins that a callExpect status
// mismatch prints the response body, also when the body is JSON that parses
// as the envelope (every SCIM answer). callExpect reports through t.Errorf on
// a *testing.T, so the mismatch runs in a child process and this test reads
// the child's output.
func TestCallExpect_MismatchMessageCarriesBody(t *testing.T) {
	if os.Getenv(callExpectMismatchChildEnv) == "1" {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(scimErrorBody))
		}))
		defer srv.Close()
		newClient(t, srv.URL).callExpect(http.MethodPost, "POST /scim/v2/Users", "/scim/v2/Users", nil, http.StatusCreated)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCallExpect_MismatchMessageCarriesBody$", "-test.v")
	cmd.Env = append(os.Environ(), callExpectMismatchChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("child run passed, but callExpect must report the 409 against want 201:\n%s", out)
	}
	if !strings.Contains(string(out), "got 409") {
		t.Fatalf("child output has no status mismatch report:\n%s", out)
	}
	if !strings.Contains(string(out), "callexpect-marker userName taken") {
		t.Errorf("callExpect mismatch message does not carry the response body:\n%s", out)
	}
}
