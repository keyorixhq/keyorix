// run_dangerous_env_test.go — #G39 detection_idea: test the denylist against the
// full universe of dangerous variable names it's supposed to cover (not spot
// checks), and confirm a secret whose derived key collides with one of them is
// dropped rather than silently injected to override PATH/LD_PRELOAD/etc. in the
// launched child process.
package run

import (
	"testing"
)

func TestDropDangerousEnvKeys_DropsEveryReservedName(t *testing.T) {
	reserved := []string{
		"LD_PRELOAD", "BASH_ENV", "NODE_OPTIONS", "PATH", "PERL5OPT", "RUBYOPT", "GIT_SSH_COMMAND",
	}
	envVars := map[string]string{"DATABASE_URL": "postgres://x"}
	for _, name := range reserved {
		envVars[name] = "attacker-controlled-value"
	}

	got := dropDangerousEnvKeys(envVars)

	if _, ok := got["DATABASE_URL"]; !ok {
		t.Error("an unrelated secret must survive the filter")
	}
	for _, name := range reserved {
		if _, ok := got[name]; ok {
			t.Errorf("reserved name %q must be dropped, not passed through to the child process", name)
		}
	}
	if len(got) != 1 {
		t.Errorf("expected exactly 1 surviving entry, got %d: %v", len(got), got)
	}
}

// TestDropDangerousEnvKeys_CoversFamiliesNotJustPriorInstances is the CLI-RUN-001
// release-gate re-verification (2026-09-09) regression test: the original
// dangerousEnvVarNames exact list missed DYLD_INSERT_LIBRARIES (named in the
// finding's own exploit scenario, confirmed live via a real dylib-injection PoC)
// and every other sibling of an already-covered mechanism family. This asserts
// the FAMILY is covered, not just the one instance that happened to get reported.
func TestDropDangerousEnvKeys_CoversFamiliesNotJustPriorInstances(t *testing.T) {
	reserved := []string{
		// Already covered by the pre-2026-09-09 exact list:
		"LD_PRELOAD", "BASH_ENV", "NODE_OPTIONS", "PATH", "PERL5OPT", "RUBYOPT", "GIT_SSH_COMMAND",
		// Missing siblings the prefix-family fix must now catch:
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "LD_AUDIT",
		"NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PERL5LIB",
		"GCONV_PATH", "MALLOC_CONF", "IFS", "ENV", "HOME", "SHELL",
	}
	envVars := map[string]string{"DATABASE_URL": "postgres://x"}
	for _, name := range reserved {
		envVars[name] = "attacker-controlled-value"
	}

	got := dropDangerousEnvKeys(envVars)

	if _, ok := got["DATABASE_URL"]; !ok {
		t.Error("an unrelated, legitimate secret must survive the filter")
	}
	for _, name := range reserved {
		if _, ok := got[name]; ok {
			t.Errorf("reserved name %q must be dropped, not passed through to the child process", name)
		}
	}
	if len(got) != 1 {
		t.Errorf("expected exactly 1 surviving entry, got %d: %v", len(got), got)
	}
}

// TestIsDangerousEnvKey_LegitimateNamesSurvive confirms the fix is a filter, not
// a denylist so broad it blocks everything — a handful of ordinary, unrelated
// secret-derived env keys must still pass through untouched.
func TestIsDangerousEnvKey_LegitimateNamesSurvive(t *testing.T) {
	legit := []string{"DATABASE_URL", "STRIPE_API_KEY", "REDIS_URL", "APP_PORT", "LOG_LEVEL"}
	for _, name := range legit {
		if isDangerousEnvKey(name) {
			t.Errorf("isDangerousEnvKey(%q) = true, want false — a legitimate secret name must not be blocked", name)
		}
	}
}

func TestDropDangerousEnvKeys_EmptyMapNoop(t *testing.T) {
	got := dropDangerousEnvKeys(map[string]string{})
	if len(got) != 0 {
		t.Errorf("expected an empty map, got %v", got)
	}
}

// TestToEnvKey_SecretNameCollidesWithReservedVar proves the actual attack
// primitive end-to-end: a secret literally NAMED "path" (a legitimate, valid
// secret name — Keyorix only enforces length server-side) derives the exact env
// key dropDangerousEnvKeys must catch.
func TestToEnvKey_SecretNameCollidesWithReservedVar(t *testing.T) {
	cases := map[string]string{
		"path":         "PATH",
		"ld-preload":   "LD_PRELOAD",
		"bash.env":     "BASH_ENV",
		"node options": "NODE_OPTIONS",
	}
	for secretName, wantKey := range cases {
		if got := toEnvKey(secretName); got != wantKey {
			t.Errorf("toEnvKey(%q) = %q, want %q", secretName, got, wantKey)
		}
		if !isDangerousEnvKey(wantKey) {
			t.Errorf("isDangerousEnvKey must cover %q (derived from secret name %q)", wantKey, secretName)
		}
	}
}
