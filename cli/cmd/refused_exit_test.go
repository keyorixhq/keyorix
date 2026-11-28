package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused call (403, 404) or a broken audit chain must end the process non-zero and
// show the server's message once: not as "%!w(<nil>)", not as a bare "HTTP 403", not
// twice. The cases go through Run, the function main() exits with, against the httptest
// fake server the other cmd tests use.

type refusedCall struct {
	name string
	args []string
	// refused says which request the server refuses; every other request gets the
	// happy-path answer (only 'secret delete' makes more than one call).
	refused func(r *http.Request) bool
}

func refusedCalls() []refusedCall {
	all := func(*http.Request) bool { return true }
	return []refusedCall{
		{"secret delete: lookup by id", []string{"secret", "delete", "--id", "5", "--force"},
			func(r *http.Request) bool { return r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5" }},
		{"secret delete: the DELETE itself", []string{"secret", "delete", "--id", "5", "--force"},
			func(r *http.Request) bool { return r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/5" }},
		{"secret restore", []string{"secret", "restore", "--id", "5"}, all},
		{"share create", []string{"share", "create", "--secret-id", "5", "--recipient-id", "2", "--permission", "read"}, all},
		{"audit verify", []string{"audit", "verify"}, all},
		{"audit verify --full", []string{"audit", "verify", "--full"}, all},
	}
}

// refusalServer answers the refused request with status and a JSON error carrying msg,
// and everything else with what a healthy server returns for 'secret delete'.
func refusalServer(t *testing.T, status int, msg string, refused func(*http.Request) bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/version":
			http.NotFound(w, r)
		case refused(r):
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"code":%d,"error":"refused","message":%q}`, status, msg)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5":
			_, _ = fmt.Fprint(w, `{"data":{"id":5,"name":"db-pass"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5/versions":
			_, _ = fmt.Fprint(w, `{"data":{"versions":[{"version_number":1}]}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5/dependencies":
			_, _ = fmt.Fprint(w, `{"data":{"secret_id":5,"depends_on":[],"dependents":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runRefused runs the CLI and returns the exit code and everything it wrote.
func runRefused(t *testing.T, srv *httptest.Server, args []string) (code int, stdout, stderr string) {
	t.Helper()
	isolateCredentials(t)
	t.Setenv(allowInsecureSecretFlagsEnv, "")
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
	resetAllFlags(rootCmd)
	var runErr string
	stdout, stderr = captureStdoutAndStderr(t, func() {
		var buf strings.Builder
		code = Run(args, &buf)
		runErr = buf.String()
	})
	return code, stdout, stderr + runErr
}

func TestRefusedCallsExitNonZeroAndShowTheServerMessageOnce(t *testing.T) {
	statuses := []struct {
		status int
		code   int
	}{
		{http.StatusForbidden, exitPermission},
		{http.StatusNotFound, exitNotFound},
	}
	for _, rc := range refusedCalls() {
		for _, st := range statuses {
			t.Run(fmt.Sprintf("%s/%d", rc.name, st.status), func(t *testing.T) {
				msg := fmt.Sprintf("the-server-says-no-%d-for-%s", st.status, strings.ReplaceAll(rc.name, " ", "-"))
				srv := refusalServer(t, st.status, msg, rc.refused)
				code, stdout, stderr := runRefused(t, srv, rc.args)
				if code != st.code {
					t.Errorf("exit code = %d, want %d\nstdout: %q\nstderr: %q", code, st.code, stdout, stderr)
				}
				if n := strings.Count(stdout+stderr, msg); n != 1 {
					t.Errorf("the server's message appears %d times, want once\nstdout: %q\nstderr: %q", n, stdout, stderr)
				}
				if strings.Contains(stdout+stderr, "%!") {
					t.Errorf("output holds a broken format verb: %q", stdout+stderr)
				}
				if strings.Contains(stdout, msg) {
					t.Errorf("the refusal went to stdout, not stderr: %q", stdout)
				}
			})
		}
	}
}

// An audit chain the server reports as broken is not a refusal but must fail the same
// way: non-zero, with the reason shown. The reason is part of the report on stdout and
// of the one-line error on stderr, so each stream carries it once.
func TestAuditVerifyBrokenChainExitsNonZero(t *testing.T) {
	const reason = "hash-mismatch-at-the-tail"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":{"valid":false,"first_broken_id":7,"reason":%q}}`, reason)
	}))
	t.Cleanup(srv.Close)

	code, stdout, stderr := runRefused(t, srv, []string{"audit", "verify"})
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d\nstdout: %q\nstderr: %q", code, exitFailure, stdout, stderr)
	}
	if n := strings.Count(stdout, reason); n != 1 {
		t.Errorf("stdout names the reason %d times, want once: %q", n, stdout)
	}
	if n := strings.Count(stderr, reason); n != 1 {
		t.Errorf("stderr names the reason %d times, want once: %q", n, stderr)
	}
	if !strings.Contains(stderr, "FAILED") {
		t.Errorf("stderr does not say the verification failed: %q", stderr)
	}
}
