package run

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterSensitiveEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/dev",
		"KEYORIX_TOKEN=super-secret-token",
		"KEYORIX_API_KEY=kx_api_abc",
		"KEYORIX_REMOTE_API_KEY=kx_remote_abc",
		"KEYORIX_BOOTSTRAP_TOKEN=boot-tok",
		"KEYORIX_PASSWORD=hunter2",
		"KEYORIX_MASTER_PASSWORD=hunter3",
		"KEYORIX_TARGET_KEK=base64kek",
		"KEYORIX_DYNAMIC_ADMIN_DSN=postgres://u:p@h/db",
		"KEYORIX_PROJECT=payments", // not a credential — must survive
		"KEYORIX_SERVER=https://x", // not a credential — must survive
		"KEYORIX_ENV=production",   // not a credential — must survive
	}

	out := filterSensitiveEnv(in)

	t.Run("strips every Keyorix credential var", func(t *testing.T) {
		for _, sensitive := range []string{
			"KEYORIX_TOKEN=super-secret-token",
			"KEYORIX_API_KEY=kx_api_abc",
			"KEYORIX_REMOTE_API_KEY=kx_remote_abc",
			"KEYORIX_BOOTSTRAP_TOKEN=boot-tok",
			"KEYORIX_PASSWORD=hunter2",
			"KEYORIX_MASTER_PASSWORD=hunter3",
			"KEYORIX_TARGET_KEK=base64kek",
			"KEYORIX_DYNAMIC_ADMIN_DSN=postgres://u:p@h/db",
		} {
			assert.NotContains(t, out, sensitive, "%s must not leak into the child environment", sensitive)
		}
	})

	t.Run("keeps ordinary and non-credential Keyorix vars intact", func(t *testing.T) {
		for _, keep := range []string{
			"PATH=/usr/bin",
			"HOME=/home/dev",
			"KEYORIX_PROJECT=payments",
			"KEYORIX_SERVER=https://x",
			"KEYORIX_ENV=production",
		} {
			assert.Contains(t, out, keep, "%s should still be passed to the child", keep)
		}
	})
}

func TestIsSensitiveKeyorixEnv(t *testing.T) {
	cases := map[string]bool{
		"KEYORIX_TOKEN":         true,
		"KEYORIX_API_KEY":       true,
		"KEYORIX_SIEM_TOKEN":    true,
		"KEYORIX_SMTP_PASSWORD": true,
		"KEYORIX_TARGET_KEK":    true,
		"KEYORIX_PROJECT":       false,
		"KEYORIX_SERVER":        false,
		"PATH":                  false,
		"SOME_OTHER_APP_TOKEN":  false, // not KEYORIX_-prefixed
	}
	for key, want := range cases {
		assert.Equal(t, want, isSensitiveKeyorixEnv(key), "key=%s", key)
	}
}

// TestBuildChildEnv_Default_InheritsFullParentEnv proves the long-standing, backward-
// compatible default: with cleanEnv=false, the child gets the parent environment (minus
// Keyorix's own credential vars — filterSensitiveEnv, #103) plus the injected secrets.
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

// TestBuildChildEnv_Default_StillFiltersSensitiveKeyorixVars proves the #103 fix survives
// #164's refactor: even in the default (cleanEnv=false) path, Keyorix's own credential
// vars must still be stripped from the child environment.
func TestBuildChildEnv_Default_StillFiltersSensitiveKeyorixVars(t *testing.T) {
	t.Setenv("KEYORIX_TOKEN", "should-not-leak-by-default-either")

	got := buildChildEnv(nil, false)

	if containsEnv(got, "KEYORIX_TOKEN", "should-not-leak-by-default-either") {
		t.Fatalf("default (no --clean-env) must still filter Keyorix's own credential vars, got: %v", got)
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
