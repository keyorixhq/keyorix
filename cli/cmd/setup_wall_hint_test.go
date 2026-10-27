package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryAccountSetupCodeHasItsOwnNextStep: the server's account-setup wall
// (server/middleware/auth.go accountSetupRequiredResponse) answers 403 with one of a
// few error codes. Each needs its own " Next step: ...": without one the CLI falls back
// to the generic 403 hint "ask a project admin, or request access", which is wrong
// advice for an admin who must change a one-time password after `admin recover-admin`
// (DEMO-1, #3744). The codes are read from the server source, so a new setup code
// without a CLI hint fails here. Does not see codes the wall builds by concatenation
// or that live outside accountSetupRequiredResponse.
func TestEveryAccountSetupCodeHasItsOwnNextStep(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "server", "middleware", "auth.go"))
	if err != nil {
		t.Fatalf("read server auth middleware: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func accountSetupRequiredResponse(")
	if start < 0 {
		t.Fatal("accountSetupRequiredResponse not found in server/middleware/auth.go: update this guard")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("end of accountSetupRequiredResponse not found")
	}
	codes := regexp.MustCompile(`\bcode\s*:?=\s*"([A-Za-z]+)"`).FindAllStringSubmatch(body[start:start+end], -1)
	if len(codes) < 2 {
		t.Fatalf("found %d setup error codes, want at least 2 (MFAEnrollmentRequired, PasswordChangeRequired): the guard no longer sees the wall", len(codes))
	}
	generic := statusHint("list secrets", 403)
	for _, m := range codes {
		hint := nextStepHint(apiErrorBody{Error: m[1]})
		if hint == "" || hint == generic || strings.Contains(hint, "request access") {
			t.Errorf("setup error code %q has no specific next step (got %q)", m[1], hint)
		}
	}
}
