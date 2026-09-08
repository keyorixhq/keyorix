// remote_proxy_correctness_checks_test.go — red-then-green validation for
// each of the 5 static checks in remote_proxy_correctness_audit_test.go
// (checks 1-4: issue #1786 part 2, step 3; check 5: issue #1786 part 3,
// added directly from a confirmed historical defect — see blankParams' own
// doc comment).
//
// Every check below is exercised against a small in-memory source snippet —
// never a real file — so validating the checker never risks leaving planted
// bugs in the tree. Each check gets its own RED case (a snippet that should
// trip it) and GREEN case (a structurally similar snippet that should not),
// asserted individually per this file's own instruction: "a clean sweep from
// an unvalidated checker is worse than no sweep because it will be
// believed." TestRemoteProxyStaticAuditReport's clean 1-finding result over
// 214 real methods is only trustworthy once every check below is shown to
// both fire and stay silent on demand.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseSnippetFunc parses src (a complete, minimal Go source file) and
// returns its single top-level function declaration.
func parseSnippetFunc(t *testing.T, src string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parsing snippet: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok {
			if fn != nil {
				t.Fatalf("snippet declares more than one function")
			}
			fn = f
		}
	}
	if fn == nil {
		t.Fatalf("snippet declares no function")
	}
	return fn
}

// checksFor parses src, locates its single call site, and returns every
// finding checkCallSite produces for it. Fails the test outright if the
// snippet's call site isn't found — a broken snippet must not silently read
// as "zero findings" (which would look identical to "checker validated
// clean").
func checksFor(t *testing.T, src string) []proxyFinding {
	t.Helper()
	fn := parseSnippetFunc(t, src)
	sites := directCallSites(fn, map[string]bool{})
	if len(sites) != 1 {
		t.Fatalf("snippet must have exactly one call site, found %d — fix the snippet, not the checker", len(sites))
	}
	info := methodInfo{Name: fn.Name.Name, File: "synthetic.go", Line: 1, Decl: fn}
	return checkCallSite(info, sites[0])
}

func hasCheck(findings []proxyFinding, check string) bool {
	for _, f := range findings {
		if f.Check == check {
			return true
		}
	}
	return false
}

const checkSnippetPreamble = `package store

import (
	"context"
	"fmt"
)

`

// --- Check 1: dropped inputs ---

func TestCheck1_DroppedInput_FiresOnViolation(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) DroppedInputRed(ctx context.Context, id uint, filter string) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "dropped-input") {
		t.Fatalf("expected a dropped-input finding for the unused 'filter' parameter, got: %+v", findings)
	}
}

func TestCheck1_DroppedInput_SilentOnCorrect(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) DroppedInputGreen(ctx context.Context, id uint, filter string) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d?filter=%s", id, filter))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if hasCheck(findings, "dropped-input") {
		t.Fatalf("expected no dropped-input finding — every parameter is referenced, got: %+v", findings)
	}
}

// --- Check 2: swallowed errors ---

func TestCheck2_SwallowedError_FiresOnViolation_NoGuardAtAll(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) SwallowedErrorRedNoGuard(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	_ = err
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "swallowed-error") {
		t.Fatalf("expected a swallowed-error finding — the call's err is discarded via _ with no err != nil guard, got: %+v", findings)
	}
}

func TestCheck2_SwallowedError_FiresOnViolation_GuardDoesNotReturn(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) SwallowedErrorRedFallsThrough(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		fmt.Println("saw an error but kept going:", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "swallowed-error") {
		t.Fatalf("expected a swallowed-error finding — the err != nil guard logs and falls through instead of returning, got: %+v", findings)
	}
}

func TestCheck2_SwallowedError_SilentOnCorrect(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) SwallowedErrorGreen(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if hasCheck(findings, "swallowed-error") {
		t.Fatalf("expected no swallowed-error finding — both guards check and return, got: %+v", findings)
	}
}

// --- Check 3: context substitution ---

func TestCheck3_ContextSubstitution_FiresOnViolation(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) ContextSubstitutionRed(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(context.Background(), fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "context-substitution") {
		t.Fatalf("expected a context-substitution finding — the call uses context.Background() instead of ctx, got: %+v", findings)
	}
}

func TestCheck3_ContextSubstitution_SilentOnCorrect(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) ContextSubstitutionGreen(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if hasCheck(findings, "context-substitution") {
		t.Fatalf("expected no context-substitution finding — ctx is forwarded verbatim, got: %+v", findings)
	}
}

// --- Check 4: silent zero returns ---

func TestCheck4_SilentZeroReturn_FiresOnViolation(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) SilentZeroRed(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", nil
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "silent-zero-return") {
		t.Fatalf("expected a silent-zero-return finding — the err != nil branch returns a nil error, got: %+v", findings)
	}
}

func TestCheck4_SilentZeroReturn_SilentOnCorrect(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) SilentZeroGreen(ctx context.Context, id uint) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if hasCheck(findings, "silent-zero-return") {
		t.Fatalf("expected no silent-zero-return finding — both guards return a real error, got: %+v", findings)
	}
}

// --- Check 5: blank-identifier parameters (issue #1786 part 3) ---

func TestCheck5_BlankIdentifierParam_FiresOnViolation(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) BlankIdentifierParamRed(ctx context.Context, id uint, _ string) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d", id))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if !hasCheck(findings, "blank-identifier-param") {
		t.Fatalf("expected a blank-identifier-param finding — the third parameter is declared _, got: %+v", findings)
	}
}

func TestCheck5_BlankIdentifierParam_SilentOnCorrect(t *testing.T) {
	src := checkSnippetPreamble + `func (rs *RemoteStorage) BlankIdentifierParamGreen(ctx context.Context, id uint, filter string) (string, error) {
	resp, err := rs.client.Get(ctx, fmt.Sprintf("/api/v1/thing/%d?filter=%s", id, filter))
	if err != nil {
		return "", fmt.Errorf("failed: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("failed")
	}
	return "", nil
}
`
	findings := checksFor(t, src)
	if hasCheck(findings, "blank-identifier-param") {
		t.Fatalf("expected no blank-identifier-param finding — every parameter is named, got: %+v", findings)
	}
}
