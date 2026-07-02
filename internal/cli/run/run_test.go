package run

import (
	"os"
	"strings"
	"testing"
)

// TestBuildChildEnv_Default_InheritsFullParentEnv proves the long-standing, backward-
// compatible default: with cleanEnv=false, the child gets the ENTIRE parent environment
// (including variables unrelated to the injected secrets) plus the injected secrets.
func TestBuildChildEnv_Default_InheritsFullParentEnv(t *testing.T) {
	t.Setenv("KEYORIX_RUN_TEST_UNRELATED", "leftover-from-shell")

	got := buildChildEnv(map[string]string{"DB_PASSWORD": "s3cr3t"}, false)

	if !containsEnv(got, "KEYORIX_RUN_TEST_UNRELATED", "leftover-from-shell") {
		t.Fatalf("default (no --clean-env) must still inherit unrelated parent vars, got: %v", got)
	}
	if !containsEnv(got, "DB_PASSWORD", "s3cr3t") {
		t.Fatalf("injected secret missing from child env: %v", got)
	}
}

// TestBuildChildEnv_CleanEnv_OnlyInjectedSecretsAndBaseline proves the #164 fix: with
// cleanEnv=true (--clean-env), the child must NOT inherit unrelated parent environment
// variables — only the explicitly injected secrets plus the minimal PATH/HOME baseline.
func TestBuildChildEnv_CleanEnv_OnlyInjectedSecretsAndBaseline(t *testing.T) {
	t.Setenv("KEYORIX_RUN_TEST_UNRELATED", "leftover-from-shell")
	t.Setenv("KEYORIX_TOKEN", "should-not-leak-into-clean-child")

	got := buildChildEnv(map[string]string{"DB_PASSWORD": "s3cr3t"}, true)

	if containsEnv(got, "KEYORIX_RUN_TEST_UNRELATED", "leftover-from-shell") {
		t.Fatalf("--clean-env must NOT inherit unrelated parent vars, got: %v", got)
	}
	if containsEnv(got, "KEYORIX_TOKEN", "should-not-leak-into-clean-child") {
		t.Fatalf("--clean-env must NOT leak the parent's KEYORIX_TOKEN, got: %v", got)
	}
	if !containsEnv(got, "DB_PASSWORD", "s3cr3t") {
		t.Fatalf("injected secret missing from clean child env: %v", got)
	}

	// Only PATH/HOME (if set) plus the one injected secret should be present.
	for _, kv := range got {
		key := strings.SplitN(kv, "=", 2)[0]
		if key != "PATH" && key != "HOME" && key != "DB_PASSWORD" {
			t.Fatalf("--clean-env leaked unexpected variable %q into child env: %v", key, got)
		}
	}
}

// TestBuildChildEnv_CleanEnv_BaselineMatchesParent confirms the minimal PATH/HOME baseline
// is actually populated from the parent when clean-env is requested, so the child can still
// locate binaries and its home directory.
func TestBuildChildEnv_CleanEnv_BaselineMatchesParent(t *testing.T) {
	wantPath, ok := os.LookupEnv("PATH")
	if !ok {
		t.Skip("PATH not set in test environment")
	}
	got := buildChildEnv(nil, true)
	if !containsEnv(got, "PATH", wantPath) {
		t.Fatalf("--clean-env must carry over the parent PATH baseline, got: %v", got)
	}
}

func containsEnv(env []string, key, val string) bool {
	target := key + "=" + val
	for _, kv := range env {
		if kv == target {
			return true
		}
	}
	return false
}
