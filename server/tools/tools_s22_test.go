// tools_s22_test.go — additional coverage for test_runner.go.
//
// Targets the one branch of RunCoverageReport still uncovered after s18/s21:
// the `go tool cover -html` FAILURE branch (the `if err := cmd.Run(); err !=
// nil { ... }` block around line 248 that prints "Could not generate HTML
// coverage report"). s18/s21 only ever exercised the success side of that
// branch (a populated coverage.out lets `go tool cover -html` succeed).
//
// `go tool cover -html=coverage.out -o coverage.html` fails deterministically
// when "coverage.html" already exists as a directory (open: is a directory),
// which lets us hit the failure branch without any flakiness or reliance on a
// broken toolchain/environment.
package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. RunCoverageReport's return value alone does not
// distinguish the html/func warning branches from their success counterparts
// (both leave the overall error nil), so asserting on printed output is the
// only way to pin which branch actually ran.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()

	_ = w.Close()
	<-done
	return buf.String()
}

// TestRunCoverageReport_S22_HTMLWriteFailure exercises the html-generation
// failure branch of RunCoverageReport by pre-creating "coverage.html" as a
// directory inside the temp module. `go tool cover -html -o coverage.html`
// cannot open a directory for writing, so it fails deterministically and
// RunCoverageReport prints the "Could not generate HTML coverage report"
// warning instead of the success message. The func-summary step reads only
// coverage.out (unaffected by coverage.html), so its success branch is still
// exercised in the same run — isolating exactly the failure branch under test
// without disturbing the sibling success branch s21 already covers.
func TestRunCoverageReport_S22_HTMLWriteFailure(t *testing.T) {
	// A real non-test source file is required so `go test -coverprofile`
	// produces a populated (not mode-only) coverage.out — see s21's
	// makePassingModule, reused here.
	tmp := makePassingModule(t, "covs22html")

	if err := os.Mkdir(filepath.Join(tmp, "coverage.html"), 0o750); err != nil {
		t.Fatalf("mkdir coverage.html: %v", err)
	}

	chdirTo(t, tmp)

	tr := NewTestRunner(false, 60*time.Second)

	var err error
	output := captureStdout(t, func() {
		err = tr.RunCoverageReport()
	})

	if err != nil {
		t.Fatalf("RunCoverageReport() = %v, want nil (an html-generation failure is only a warning, not a returned error)", err)
	}
	if !strings.Contains(output, "Could not generate HTML coverage report") {
		t.Errorf("output = %q, want it to contain the HTML-generation warning", output)
	}
	if strings.Contains(output, "Coverage report generated: coverage.html") {
		t.Errorf("output unexpectedly contains the HTML success message: %q", output)
	}
	// The func-summary step is unaffected by coverage.html being a directory,
	// so its success branch should still print.
	if !strings.Contains(output, "Coverage Summary:") {
		t.Errorf("output = %q, want the func-summary success block to still print", output)
	}
}
