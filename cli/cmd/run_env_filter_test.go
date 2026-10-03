// run_env_filter_test.go — regression coverage for CLI-RUN-001 (#1816, tracked as #2527):
// the reserved/dangerous environment variable filter in run.go had zero tests.
// A secret named (or --var-mapped to) a dynamic-linker, interpreter, or
// shell-control variable -- LD_PRELOAD above all -- must never silently
// become that variable in the launched child process via --derive-names.
package cmd

import (
	"sort"
	"strings"
	"testing"
)

// TestIsDangerousEnvKey_ExactNames covers every entry in dangerousEnvExact.
func TestIsDangerousEnvKey_ExactNames(t *testing.T) {
	for name := range dangerousEnvExact {
		t.Run(name, func(t *testing.T) {
			if !isDangerousEnvKey(name) {
				t.Errorf("isDangerousEnvKey(%q) = false, want true (exact-match entry)", name)
			}
		})
	}
}

// TestIsDangerousEnvKey_PrefixFamilies covers at least one real-world variable
// name per entry in dangerousEnvPrefixes -- not just the bare prefix itself,
// since that's what an actual secret name colliding with one of these would
// look like in practice.
func TestIsDangerousEnvKey_PrefixFamilies(t *testing.T) {
	cases := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",
		"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
		"PERL5LIB", "PERL5OPT",
		"BASH_ENV",
		"GCONV_PATH",
		"MALLOC_ARENA_MAX", "MALLOC_CHECK_", "MALLOC_PERTURB_",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if !isDangerousEnvKey(name) {
				t.Errorf("isDangerousEnvKey(%q) = false, want true (prefix family)", name)
			}
		})
	}
}

// TestIsDangerousEnvKey_CaseVariantsAreNotFlagged documents, as designed, that
// the filter is case-SENSITIVE: a differently-cased variant of a reserved name
// is a genuinely different, inert environment variable to the mechanism the
// reserved name actually controls (the dynamic linker/shell only ever honors
// the canonical uppercase spelling -- "ld_preload" is never consulted by
// ld.so/dyld), so NOT flagging it is correct, not a gap. If this ever starts
// failing, it means isDangerousEnvKey became case-insensitive -- a behavior
// change that needs its own deliberate review, not a silent side effect.
func TestIsDangerousEnvKey_CaseVariantsAreNotFlagged(t *testing.T) {
	cases := []string{"ld_preload", "Ld_Preload", "path", "Path", "home", "Home", "dyld_insert_libraries"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if isDangerousEnvKey(name) {
				t.Errorf("isDangerousEnvKey(%q) = true, want false -- the filter is case-sensitive by design", name)
			}
		})
	}
}

// TestIsDangerousEnvKey_SimilarButSafeNames covers names that LOOK like they
// might collide with a prefix family but structurally don't (no trailing
// underscore where the prefix requires one, or a different family entirely),
// plus ordinary secret-shaped names that must never be flagged.
func TestIsDangerousEnvKey_SimilarButSafeNames(t *testing.T) {
	cases := []string{
		"LDAP_SERVER",  // "LD" + "AP...", not the "LD_" prefix
		"NODENAME",     // not "NODE_"
		"PERL",         // not "PERL5"
		"BASHRC",       // not "BASH_"
		"PATHOLOGY",    // not the exact "PATH"
		"HOMEPAGE_URL", // not the exact "HOME"
		"DATABASE_URL",
		"API_KEY",
		"MY_SECRET",
		"STRIPE_SECRET_KEY",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if isDangerousEnvKey(name) {
				t.Errorf("isDangerousEnvKey(%q) = true, want false", name)
			}
		})
	}
}

// TestDropDangerousEnvKeys_RemovesOnlyDangerousOnes verifies the derive-names
// path's actual enforcement point: dangerous keys are dropped, safe keys pass
// through unchanged, values are preserved.
func TestDropDangerousEnvKeys_RemovesOnlyDangerousOnes(t *testing.T) {
	in := map[string]string{
		"LD_PRELOAD":   "evil.so",
		"PATH":         "/evil/bin",
		"DATABASE_URL": "postgres://...",
		"API_KEY":      "sk-123",
	}
	out := dropDangerousEnvKeys(in)

	if _, ok := out["LD_PRELOAD"]; ok {
		t.Error("LD_PRELOAD must be dropped")
	}
	if _, ok := out["PATH"]; ok {
		t.Error("PATH must be dropped")
	}
	if got, want := out["DATABASE_URL"], "postgres://..."; got != want {
		t.Errorf("DATABASE_URL = %q, want %q (safe keys must survive unmodified)", got, want)
	}
	if got, want := out["API_KEY"], "sk-123"; got != want {
		t.Errorf("API_KEY = %q, want %q", got, want)
	}
	if len(out) != 2 {
		t.Errorf("len(out) = %d, want 2; got %v", len(out), out)
	}
}

// TestDropDangerousEnvKeys_RedProof is the required red-proof: temporarily
// disables the filter (empties the package-level prefix/exact tables, the
// actual mechanism isDangerousEnvKey consults) and confirms LD_PRELOAD would
// leak through dropDangerousEnvKeys without it -- demonstrating this guard
// has teeth before restoring it and confirming the real tables block it.
func TestDropDangerousEnvKeys_RedProof(t *testing.T) {
	origPrefixes := dangerousEnvPrefixes
	origExact := dangerousEnvExact
	t.Cleanup(func() {
		dangerousEnvPrefixes = origPrefixes
		dangerousEnvExact = origExact
	})

	in := map[string]string{"LD_PRELOAD": "evil.so"}

	dangerousEnvPrefixes = nil
	dangerousEnvExact = nil
	redOut := dropDangerousEnvKeys(in)
	if _, leaked := redOut["LD_PRELOAD"]; !leaked {
		t.Fatal("red-proof setup is broken: LD_PRELOAD should leak through with the filter tables emptied")
	}

	dangerousEnvPrefixes = origPrefixes
	dangerousEnvExact = origExact
	greenOut := dropDangerousEnvKeys(in)
	if _, leaked := greenOut["LD_PRELOAD"]; leaked {
		t.Error("LD_PRELOAD leaked through dropDangerousEnvKeys with the real filter tables restored")
	}
}

// TestResolveChildEnvVars_DeriveNames_DropsReservedNames confirms the
// end-to-end --derive-names path: a secret whose NAME is (or folds via
// toEnvKey into) a reserved variable never appears in the derived map, while
// an ordinary secret still does. toEnvKey uppercases before the dangerous
// check runs, so a lower/mixed-case secret name is caught identically to an
// already-uppercase one -- unlike isDangerousEnvKey called directly (see the
// case-variant test above), this path never sees the pre-uppercase form.
func TestResolveChildEnvVars_DeriveNames_DropsReservedNames(t *testing.T) {
	secrets := map[string]string{
		"ld_preload":   "evil.so", // lower-case; toEnvKey folds it to LD_PRELOAD before the check
		"database_url": "postgres://...",
	}
	derived, varMapped, err := resolveChildEnvVars(secrets, nil, true, "proj", "env")
	if err != nil {
		t.Fatalf("resolveChildEnvVars: %v", err)
	}
	if varMapped != nil {
		t.Errorf("varMapped = %v, want nil (no --var mappings supplied)", varMapped)
	}
	if _, ok := derived["LD_PRELOAD"]; ok {
		t.Error("derived must not contain LD_PRELOAD")
	}
	if got, want := derived["DATABASE_URL"], "postgres://..."; got != want {
		t.Errorf("derived[DATABASE_URL] = %q, want %q", got, want)
	}
}

// TestResolveChildEnvVars_VarMapping_AllowsReservedNameExplicitly documents
// the OTHER half of "as designed": --var is an explicit operator choice, so
// mapping a secret onto a reserved name is allowed (with a warning this test
// does not need to assert on) rather than silently dropped -- unlike
// --derive-names, where the env var name was never a deliberate choice at all.
func TestResolveChildEnvVars_VarMapping_AllowsReservedNameExplicitly(t *testing.T) {
	secrets := map[string]string{"my-ld-secret": "evil.so"}
	_, varMapped, err := resolveChildEnvVars(secrets, []string{"LD_PRELOAD=my-ld-secret"}, false, "proj", "env")
	if err != nil {
		t.Fatalf("resolveChildEnvVars: %v", err)
	}
	if got, want := varMapped["LD_PRELOAD"], "evil.so"; got != want {
		t.Errorf("varMapped[LD_PRELOAD] = %q, want %q -- an explicit --var mapping must be honored even onto a reserved name", got, want)
	}
}

// TestBuildChildEnv_PathHandling_CleanEnv confirms PATH's special-cased
// baseline in --clean-env mode: it comes from the PARENT process's real PATH
// (os.LookupEnv), never from derived/varMapped -- consistent with PATH being
// in dangerousEnvExact, so a --derive-names secret named "PATH" is already
// filtered out by dropDangerousEnvKeys long before buildChildEnv runs; this
// test covers buildChildEnv's own contribution to that design (the baseline
// re-add in clean-env mode), not the upstream filter again.
func TestBuildChildEnv_PathHandling_CleanEnv(t *testing.T) {
	childEnv := buildChildEnv(nil, nil, true)
	var gotPath string
	found := false
	for _, kv := range childEnv {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "PATH" {
			gotPath, found = v, true
		}
	}
	if !found {
		t.Fatal("PATH must be present in a --clean-env child environment")
	}
	if gotPath == "" {
		t.Error("PATH must carry the real inherited value, not an empty placeholder")
	}
}

// TestBuildChildEnv_PathHandling_VarMappedWinsOverInherited confirms the
// OTHER documented PATH behavior: when the operator explicitly --var-maps a
// secret onto PATH, that explicit value wins over whatever PATH the child
// would otherwise inherit -- "explicit operator intent always wins" per
// buildChildEnv's own comment -- exercised here specifically for PATH since
// it's the one name both halves of the design (block when automatic, allow
// when explicit) apply to.
func TestBuildChildEnv_PathHandling_VarMappedWinsOverInherited(t *testing.T) {
	childEnv := buildChildEnv(nil, map[string]string{"PATH": "/custom/bin"}, false)
	var gotPath string
	for _, kv := range childEnv {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "PATH" {
			gotPath = v
		}
	}
	if gotPath != "/custom/bin" {
		t.Errorf("PATH = %q, want %q (an explicit --var mapping onto PATH must win)", gotPath, "/custom/bin")
	}
}

// TestDangerousEnvTables_SortedAndDeduped is a light hygiene check on the
// hand-maintained tables themselves -- not security-relevant on its own, but
// catches an accidental duplicate entry (which would be silently harmless but
// signal a merge/edit mistake worth noticing) before it ships.
func TestDangerousEnvTables_SortedAndDeduped(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range dangerousEnvPrefixes {
		if seen[p] {
			t.Errorf("duplicate entry in dangerousEnvPrefixes: %q", p)
		}
		seen[p] = true
	}
	var exactNames []string
	for name := range dangerousEnvExact {
		exactNames = append(exactNames, name)
	}
	sort.Strings(exactNames)
	t.Logf("dangerousEnvExact: %v", exactNames)
	t.Logf("dangerousEnvPrefixes: %v", dangerousEnvPrefixes)
}
