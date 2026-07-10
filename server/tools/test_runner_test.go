package main

import (
	"strings"
	"testing"
	"time"
)

func TestNewTestRunner(t *testing.T) {
	tr := NewTestRunner(true, 5*time.Minute)
	if !tr.verbose {
		t.Error("expected verbose to be true")
	}
	if tr.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want %v", tr.timeout, 5*time.Minute)
	}
}

// TestRunTestSuite_RejectsInvalidPathBeforeExec proves runTestSuite's own
// validateTestPath gate (#129 notes this call site had none originally) short
// -circuits BEFORE reaching exec.Command — an invalid path must error out
// immediately rather than ever being handed to `go test` as an argument.
func TestRunTestSuite_RejectsInvalidPathBeforeExec(t *testing.T) {
	tr := NewTestRunner(false, time.Second)
	err := tr.runTestSuite("/etc/passwd", "malicious suite")
	if err == nil {
		t.Fatal("expected an error for a path outside the allowlist, got nil")
	}
	if !strings.Contains(err.Error(), "invalid test path") {
		t.Errorf("error = %v, want it to identify the path as invalid (not a test-execution failure)", err)
	}
}

// #129: validateTestPath used to check the "./" prefix on the ALREADY-CLEANED path
// (filepath.Clean strips a leading "./"), so it rejected every legitimate input
// unconditionally — RunBenchmarks' only caller silently skipped every benchmark. This
// pins that every real call site's actual paths are now accepted, and that the
// traversal/allowlist guards still hold.
func TestValidateTestPath(t *testing.T) {
	valid := []string{
		"./http", "./http/handlers",
		"./grpc", "./grpc/services",
		"./middleware",
		"./validation",
		"./services",
	}
	for _, p := range valid {
		if err := validateTestPath(p); err != nil {
			t.Errorf("validateTestPath(%q) = %v, want nil", p, err)
		}
	}

	invalid := map[string]string{
		"http/handlers":    "missing ./ prefix must be rejected",
		"/etc/passwd":      "absolute path must be rejected",
		"./../secrets":     "directory traversal must be rejected",
		"./http/../../etc": "directory traversal via a nested .. must be rejected",
		"./cmd":            "a directory outside the allowlist must be rejected",
		"./httpx":          "a directory name merely PREFIXED by an allowed one must be rejected (not a real subdirectory)",
		"./middlewareEvil": "same prefix-confusion check for middleware",
		"":                 "empty path must be rejected",
	}
	for p, reason := range invalid {
		if err := validateTestPath(p); err == nil {
			t.Errorf("validateTestPath(%q) = nil, want an error (%s)", p, reason)
		}
	}
}
