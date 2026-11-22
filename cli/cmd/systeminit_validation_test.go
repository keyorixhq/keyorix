package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// serverEmailRule is a copy of the rule internal/core/users.go applies to an email
// (emailRegex). cli/ is a separate module and cannot import it; the e2e check of a
// real `system init` on a fresh data dir is what ties the two together.
var serverEmailRule = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// #4216: `keyorix system init` with no --admin-email must not send an address the
// server refuses.
func TestSystemInit_DefaultAdminEmailPassesTheServerRule(t *testing.T) {
	f := systemInitCmd.Flags().Lookup("admin-email")
	if f == nil {
		t.Fatal("no --admin-email flag")
	}
	if !serverEmailRule.MatchString(f.DefValue) {
		t.Fatalf("default --admin-email %q fails the server's email rule", f.DefValue)
	}
}

// The flag's help names the default and says it is a placeholder with no mailbox, so
// an operator who wants password-reset mail knows to pass their own address.
func TestSystemInit_AdminEmailHelpNamesTheDefault(t *testing.T) {
	f := systemInitCmd.Flags().Lookup("admin-email")
	if f == nil {
		t.Fatal("no --admin-email flag")
	}
	if !containsAll(f.Usage, f.DefValue, "placeholder") {
		t.Fatalf("--admin-email help does not name its default and say it is a placeholder: %q", f.Usage)
	}
}

// runInitAgainst runs `system init` against a server answering status/body and
// returns the error text.
func runInitAgainst(t *testing.T, status int, body string) string {
	t.Helper()
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	systemInitServer = srv.URL
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "secret123")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "bootstrap-tok")

	err := runSystemInit(systemInitCmd, nil)
	if err == nil {
		t.Fatalf("expected an error for HTTP %d", status)
	}
	return err.Error()
}

// A validation refusal names the rejected input and the flag that fixes it, and never
// sends the operator to "ask a project admin / request access": nobody is signed in
// yet and no permission is missing.
func TestRunSystemInit_ValidationRefusalHasNoAccessHint(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		flag   string
	}{
		"typed 400 for the email": {
			http.StatusBadRequest,
			`{"error":"ValidationError","message":"Validation error: email address is not valid (expected name@domain.tld)","details":{"field":"email"}}`,
			"--admin-email",
		},
		"typed 400 for the username": {
			http.StatusBadRequest,
			`{"error":"ValidationError","message":"Validation error: username must be between 3 and 64 characters","details":{"field":"username"}}`,
			"--admin-username",
		},
		// A server from before the typed code answers every validation failure 403 "Error",
		// with core's "failed to create admin user: " wrap in front (the body an
		// origin/main 59873ae6 server sends for --admin-email bad).
		"older server 403": {
			http.StatusForbidden,
			`{"error":"Error","message":"failed to create admin user: Validation error: Validation error: Email"}`,
			"--admin-email",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := runInitAgainst(t, c.status, c.body)
			if !containsAll(got, "bootstrap server failed", "Validation error", c.flag) {
				t.Fatalf("error does not show the validation text and name %s: %q", c.flag, got)
			}
			for _, bad := range []string{"request access", "ask a project admin", "do not have permission"} {
				if strings.Contains(got, bad) {
					t.Fatalf("validation refusal carries the access hint %q: %q", bad, got)
				}
			}
		})
	}
}

// The token refusals keep their own 403 hint and nothing else changes for them.
func TestRunSystemInit_TokenRefusalKeepsItsHint(t *testing.T) {
	got := runInitAgainst(t, http.StatusForbidden,
		`{"error":"InvalidBootstrapToken","message":"invalid bootstrap token"}`)
	if !containsAll(got, "invalid bootstrap token", "KEYORIX_BOOTSTRAP_TOKEN") {
		t.Fatalf("token refusal lost its next step: %q", got)
	}
	if strings.Contains(got, "--admin-email") {
		t.Fatalf("token refusal talks about the email: %q", got)
	}
}

// A server with API initialisation disabled answers 403 "Error" too; the older-server
// validation fallback must not re-label it as a refusal of the admin details.
func TestRunSystemInit_DisabledTokenRefusalIsNotValidation(t *testing.T) {
	got := runInitAgainst(t, http.StatusForbidden,
		`{"error":"Error","message":"system initialisation over the API is disabled: invalid bootstrap token"}`)
	if !containsAll(got, "system initialisation over the API is disabled", "403") {
		t.Fatalf("disabled-API refusal lost its text: %q", got)
	}
	for _, bad := range []string{"--admin-email", "--admin-username"} {
		if strings.Contains(got, bad) {
			t.Fatalf("disabled-API refusal is labelled a validation refusal (%s): %q", bad, got)
		}
	}
}

// A 403 that is neither a token refusal nor validation (a policy refusal, say) keeps
// the standard permission hint.
func TestRunSystemInit_OtherForbiddenKeepsStandardHint(t *testing.T) {
	got := runInitAgainst(t, http.StatusForbidden, `{"error":"Forbidden","message":"not allowed"}`)
	if !containsAll(got, "not allowed", "403", "ask a project admin") {
		t.Fatalf("standard 403 hint changed: %q", got)
	}
}

// An --admin-email the generated client refuses to encode never reaches the server. The
// operator is told it is the flag (not a connection failure: "contact <server>: json:
// error calling MarshalJSON"), is not asked for a password first, and is not sent to
// "request access".
func TestRunSystemInit_UnencodableAdminEmailNamesTheFlagAndSendsNothing(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const supplied = "not-an-email"
	systemInitServer = srv.URL
	systemInitAdminEmail = supplied
	// No KEYORIX_ADMIN_PASSWORD: reaching the password step would prompt and fail
	// with a different error, so the flag error must come first.
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "bootstrap-tok")

	err := runSystemInit(systemInitCmd, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid --admin-email")
	}
	got := err.Error()
	if !containsAll(got, "--admin-email", "valid") {
		t.Fatalf("error does not name --admin-email: %q", got)
	}
	for _, bad := range []string{"contact ", "MarshalJSON", "request access", "ask a project admin", "password", supplied} {
		if strings.Contains(got, bad) {
			t.Fatalf("error carries %q: %q", bad, got)
		}
	}
	if hits != 0 {
		t.Fatalf("the server was contacted %d time(s); an invalid flag must not send anything", hits)
	}
	if ee, ok := errors.AsType[*exitError](err); !ok || ee.code != exitUsage {
		t.Fatalf("error is not a usage-coded exit error (want code %d): %#v", exitUsage, err)
	}
}
