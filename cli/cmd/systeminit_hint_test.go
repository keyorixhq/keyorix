package cmd

import (
	"regexp"
	"testing"
)

// TestSystemInitError_BootstrapTokenRefusalHasItsOwnHint: a wrong bootstrap token is
// a 403 from the server, but the generic 403 hint ("ask a project admin, or request
// access") sends the operator to the wrong place. The refusal gets its own hint, and
// the text carries no internal reference.
func TestSystemInitError_BootstrapTokenRefusalHasItsOwnHint(t *testing.T) {
	body := []byte(`{"success":false,"error":"Error","message":"invalid bootstrap token"}`)

	err := systemInitError(403, body)
	if err == nil {
		t.Fatal("want an error for a 403")
	}
	got := err.Error()

	const want = "bootstrap server failed: invalid bootstrap token (HTTP 403)" +
		" Next step: check that KEYORIX_BOOTSTRAP_TOKEN / KEYORIX_BOOTSTRAP_TOKEN_FILE" +
		" matches the token the server was started with."
	if got != want {
		t.Fatalf("hint drifted.\n got: %q\nwant: %q", got, want)
	}
	for _, generic := range []string{"ask a project admin", "request access"} {
		if regexp.MustCompile(regexp.QuoteMeta(generic)).MatchString(got) {
			t.Fatalf("bootstrap-token refusal still carries the generic 403 hint %q: %q", generic, got)
		}
	}
	if regexp.MustCompile(`#[0-9]{3,}|design §|ADR-|pre-#|§`).MatchString(got) {
		t.Fatalf("internal reference in customer-facing output: %q", got)
	}
	if code, _ := classifyError(err, true); code != exitPermission {
		t.Fatalf("exit code = %d, want %d (a 403 keeps its permission exit code)", code, exitPermission)
	}
}

// TestSystemInitError_OtherAnswersKeepStandardHandling: only the token refusal changes.
func TestSystemInitError_OtherAnswersKeepStandardHandling(t *testing.T) {
	// A 403 that is not the token refusal keeps the generic hint.
	err := systemInitError(403, []byte(`{"error":"Error","message":"validation failed"}`))
	if err == nil || !regexp.MustCompile(`request access`).MatchString(err.Error()) {
		t.Fatalf("a non-token 403 must keep the standard 403 hint, got %v", err)
	}
	// API init disabled on the server is a different remedy than a mistyped token.
	err = systemInitError(403, []byte(`{"error":"Error","message":"system initialisation over the API is disabled: invalid bootstrap token"}`))
	if err == nil || regexp.MustCompile(`was started with`).MatchString(err.Error()) {
		t.Fatalf("the API-init-disabled refusal must not get the wrong-token hint, got %v", err)
	}
	// A non-JSON body falls back to the bare status.
	err = systemInitError(500, []byte(`oops`))
	if err == nil || err.Error() != "bootstrap server failed: HTTP 500" {
		t.Fatalf("got %v", err)
	}
}
