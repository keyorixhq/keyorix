package main

import "testing"

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
