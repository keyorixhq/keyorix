package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// #2937 / #2938: a non-2xx response must always show the server's message, and a
// require_mfa wall must say what to do next. Before, ~140 call sites printed a
// bare "HTTP 403".

func TestHTTPStatusError(t *testing.T) {
	mfa := `{"code":403,"error":"MFAEnrollmentRequired","message":"This deployment requires multi-factor authentication. Enrol MFA to continue."}`
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		"conflict message":    {`{"error":"ConflictError","message":"Secret with this name already exists"}`, []string{"failed to create secret: Secret with this name already exists (HTTP 409)"}},
		"no body":             {``, []string{"failed to create secret: HTTP 409"}},
		"not the error shape": {`<html>nope</html>`, []string{"failed to create secret: HTTP 409"}},
		"mfa wall":            {mfa, []string{"Enrol MFA to continue. (HTTP 409)", "keyorix mfa enroll", "keyorix mfa activate", "keyorix login"}},
	} {
		t.Run(name, func(t *testing.T) {
			err := httpStatusError("failed to create secret", 409, []byte(tc.body))
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q does not contain %q", err, w)
				}
			}
			for _, r := range err.Error() {
				if unicode.IsControl(r) {
					t.Fatalf("error %q carries control rune %U", err, r)
				}
			}
		})
	}
}

func TestHTTPStatusError_OtherErrorCodesGetNoMFAHint(t *testing.T) {
	err := httpStatusError("x", 403, []byte(`{"error":"Forbidden","message":"permission denied"}`))
	if strings.Contains(err.Error(), "mfa") {
		t.Fatalf("unrelated 403 got an MFA hint: %q", err)
	}
}

// TestCommandsSurfaceServerErrorMessage drives real commands (break-glass, share,
// secret get/list) against a server that answers 403 with the MFA wall: the CLI
// must print the server's message and the next step, not "HTTP 403".
func TestCommandsSurfaceServerErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"code":403,"error":"MFAEnrollmentRequired","message":"This deployment requires multi-factor authentication. Enrol MFA to continue."}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)

	bgProject, bgJustify = 1, "incident"
	defer func() { bgProject, bgJustify = 0, "" }()
	shareListSecretID = 1

	for name, run := range map[string]func() error{
		"break-glass activate": func() error { return runBGActivate(bgActivateCmd, nil) },
		"share list":           func() error { return runShareList(shareListCmd, nil) },
		"secret list":          func() error { return runSecretList(secretListCmd, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = run() })
			if err == nil {
				t.Fatal("want an error")
			}
			for _, w := range []string{"Enrol MFA to continue.", "(HTTP 403)", "keyorix mfa enroll"} {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

// TestNoBareHTTPStatusErrors is the family guard: no command may build an error
// from just the status code ("...: HTTP %d") and drop the response body. Use
// httpStatusError / apiError. The allowlist is the few sites that are not an API
// error response (version probe, pre-init probe, a 404 with a fixed message).
func TestNoBareHTTPStatusErrors(t *testing.T) {
	allowed := map[string]bool{
		"client.go":          true, // apiError / httpStatusError themselves + version probe
		"systeminit.go":      true, // pre-init probe: not an API error envelope
		"project_resolve.go": true, // fixed 404 wording
	}
	bare := regexp.MustCompile(`fmt\.Errorf\("[^"]*HTTP %d`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || allowed[f] {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if bare.MatchString(line) {
				t.Errorf("%s:%d drops the server's error message: %s\n\tuse httpStatusError(what, resp.StatusCode(), resp.Body)", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// The hint must name only commands that exist and must not recommend the
// insecure --mfa-code flag (the CLI itself warns about it; plain `keyorix login`
// prompts for the code).
func TestHTTPStatusError_MFAHintNamesRealCommandsAndNotInsecureFlag(t *testing.T) {
	err := httpStatusError("x", 403, []byte(`{"error":"MFAEnrollmentRequired","message":"MFA required."}`))
	for _, w := range []string{"`keyorix mfa enroll`", "`keyorix mfa activate`", "`keyorix login`"} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("hint %q does not mention %s", err, w)
		}
	}
	for _, bad := range []string{"--mfa-code", "auth mfa"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("hint %q must not mention %s", err, bad)
		}
	}
	// Every command the hint names is registered under the root command.
	for _, sub := range []string{"enroll", "activate"} {
		if c, _, ferr := rootCmd.Find([]string{"mfa", sub}); ferr != nil || c == nil || c.Name() != sub {
			t.Fatalf("hint names `keyorix mfa %s` but the command is not registered: %v", sub, ferr)
		}
	}
	if c, _, ferr := rootCmd.Find([]string{"login"}); ferr != nil || c == nil || c.Name() != "login" {
		t.Fatalf("hint names `keyorix login` but the command is not registered: %v", ferr)
	}
}

// A server (or anything in front of it) controls the message text; it must not be
// able to put terminal escapes in front of the operator (same oracle as
// FuzzApiError, INV-CLI-13).
func TestHTTPStatusError_StripsTerminalEscapesFromServerMessage(t *testing.T) {
	msg := "bad\u001b[31m red\u001b]0;pwned\u0007 \u009b2J end\r\nnext"
	enc, _ := json.Marshal(msg)
	body := fmt.Sprintf(`{"error":"Forbidden","message":%s}`, enc)
	err := httpStatusError("failed to share secret", 403, []byte(body))
	for _, r := range err.Error() {
		if unicode.IsControl(r) {
			t.Fatalf("error %q carries control rune %U", err, r)
		}
	}
	if !strings.Contains(err.Error(), "(HTTP 403)") {
		t.Fatalf("error %q lost its status", err)
	}
}

// SHARE-2 deferred this to #2947: a refused `share create` must say why, not
// just "HTTP 403".
func TestShareCreateRefusalShowsServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"code":403,"error":"Forbidden","message":"You need write access to this secret to share it."}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)

	oldID, oldRecipient, oldPerm := shareCreateSecretID, shareCreateRecipientID, shareCreatePermission
	shareCreateSecretID, shareCreateRecipientID, shareCreatePermission = 1, 2, "read"
	defer func() {
		shareCreateSecretID, shareCreateRecipientID, shareCreatePermission = oldID, oldRecipient, oldPerm
	}()

	var err error
	captureStdout(t, func() { err = runShareCreate(shareCreateCmd, nil) })
	if err == nil {
		t.Fatal("want an error")
	}
	for _, w := range []string{"failed to share secret", "You need write access to this secret to share it.", "(HTTP 403)"} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not contain %q", err, w)
		}
	}
}
