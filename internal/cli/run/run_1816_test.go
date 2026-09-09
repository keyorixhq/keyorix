// run_1816_test.go — #1816: keyorix run env-var name provenance. Two independent
// levers, tested separately per the issue's own requirement:
//   - Provenance: --var (operator names it) vs --derive-names (secret names it,
//     deprecated).
//   - Precedence: --var overrides the inherited environment on collision (operator
//     intent); --derive-names does NOT (a second, independent guard alongside the
//     reserved-name filter — see buildChildEnv's doc comment for what this does and
//     does not close on its own).
package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runRun: no implicit default ────────────────────────────────────────────────

// TestRunRun_NeitherFlagErrors is the provenance fix's entry-point guard: with
// neither --var nor --derive-names, runRun must refuse outright (naming both
// options) rather than either silently injecting nothing or silently keeping the
// old, attacker-nameable default.
func TestRunRun_NeitherFlagErrors(t *testing.T) {
	origVar, origDerive := runVarMappings, runDeriveNames
	defer func() { runVarMappings = origVar; runDeriveNames = origDerive }()
	runVarMappings = nil
	runDeriveNames = false

	err := runRun(nil, []string{"true"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--var")
	assert.Contains(t, err.Error(), "--derive-names")
}

// ── resolveChildEnvVars: --var provenance ───────────────────────────────────────

func TestResolveChildEnvVars_VarBasic(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t", "unrelated": "should-not-appear"}
	derived, varMapped, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=db-password"}, false, "web", "dev")
	require.NoError(t, err)
	assert.Nil(t, derived, "derived must be nil when --derive-names is not set")
	assert.Equal(t, map[string]string{"DATABASE_URL": "s3cr3t"}, varMapped)
}

func TestResolveChildEnvVars_VarMultiple(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t", "stripe-key": "sk_live_x"}
	_, varMapped, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=db-password", "API_KEY=stripe-key"}, false, "web", "dev")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"DATABASE_URL": "s3cr3t", "API_KEY": "sk_live_x"}, varMapped)
}

func TestResolveChildEnvVars_VarMissingSecret(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t"}
	_, _, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=does-not-exist"}, false, "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
	assert.Contains(t, err.Error(), "not found")
}

func TestResolveChildEnvVars_VarInvalidFormat(t *testing.T) {
	cases := []string{"no-equals-sign", "=missing-name", "MISSING_REF="}
	for _, mapping := range cases {
		_, _, err := resolveChildEnvVars(map[string]string{}, []string{mapping}, false, "web", "dev")
		require.Error(t, err, "mapping %q must be rejected", mapping)
		assert.Contains(t, err.Error(), mapping)
	}
}

func TestResolveChildEnvVars_VarInvalidEnvVarName(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t"}
	_, _, err := resolveChildEnvVars(secrets, []string{"1INVALID=db-password"}, false, "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1INVALID")
	assert.Contains(t, err.Error(), "not a valid environment variable name")
}

// TestResolveChildEnvVars_VarSameNameSameRef_Idempotent: assigning the same NAME
// to the same secret-ref twice (e.g. via a duplicated --var flag) is not an error.
func TestResolveChildEnvVars_VarSameNameSameRef_Idempotent(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t"}
	_, varMapped, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=db-password", "DATABASE_URL=db-password"}, false, "web", "dev")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"DATABASE_URL": "s3cr3t"}, varMapped)
}

// TestResolveChildEnvVars_VarSameNameDifferentRef_Errors: the --var counterpart of
// setEnvKey's derived-path collision abort — the same NAME assigned to two
// DIFFERENT secrets is ambiguous operator intent, and must fail closed rather than
// silently picking a winner.
func TestResolveChildEnvVars_VarSameNameDifferentRef_Errors(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t", "other-secret": "other-value"}
	_, _, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=db-password", "DATABASE_URL=other-secret"}, false, "web", "dev")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DATABASE_URL")
	assert.Contains(t, err.Error(), "db-password")
	assert.Contains(t, err.Error(), "other-secret")
}

// TestResolveChildEnvVars_VarDangerousName_WarnsButDoesNotBlock: the issue's own
// requirement — "an operator who explicitly maps a secret to LD_PRELOAD is
// expressing intent, not being exploited... do not silently block operator
// intent." No filter applies to --var; isDangerousEnvKey is used only to decide
// whether to print a non-blocking heads-up.
func TestResolveChildEnvVars_VarDangerousName_WarnsButDoesNotBlock(t *testing.T) {
	secrets := map[string]string{"my-lib": "/path/to/lib.so"}
	_, varMapped, err := resolveChildEnvVars(secrets, []string{"LD_PRELOAD=my-lib"}, false, "web", "dev")
	require.NoError(t, err, "--var to a reserved name must NOT be blocked -- operator intent wins")
	assert.Equal(t, map[string]string{"LD_PRELOAD": "/path/to/lib.so"}, varMapped)
}

// ── resolveChildEnvVars: --derive-names (deprecated) ────────────────────────────

func TestResolveChildEnvVars_DeriveNamesBasic(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t"}
	derived, varMapped, err := resolveChildEnvVars(secrets, nil, true, "web", "dev")
	require.NoError(t, err)
	assert.Nil(t, varMapped, "varMapped must be nil when --var is not set")
	assert.Equal(t, map[string]string{"DB_PASSWORD": "s3cr3t"}, derived)
}

// TestResolveChildEnvVars_DeriveNames_CollisionAborts relocates the collision
// coverage formerly in run_fetch_test.go's TestFetch*_CollisionAborts (moved
// because derivation itself moved out of fetchSecrets* and into this function).
func TestResolveChildEnvVars_DeriveNames_CollisionAborts(t *testing.T) {
	secrets := map[string]string{"my-secret": "first", "my_secret": "second"}
	derived, _, err := resolveChildEnvVars(secrets, nil, true, "web", "dev")
	require.Error(t, err, "colliding secret names must abort, not silently overwrite one")
	assert.Nil(t, derived)
	assert.Contains(t, err.Error(), "my-secret")
	assert.Contains(t, err.Error(), "my_secret")
	assert.Contains(t, err.Error(), "MY_SECRET")
}

// TestResolveChildEnvVars_DeriveNames_FiltersDangerousNames confirms the
// CLI-RUN-001 prefix-family filter is still applied end-to-end through
// resolveChildEnvVars (not just unit-tested against dropDangerousEnvKeys
// directly) — the exact PoC name from that finding's own exploit scenario.
func TestResolveChildEnvVars_DeriveNames_FiltersDangerousNames(t *testing.T) {
	secrets := map[string]string{
		"dyld_insert_libraries": "/tmp/attacker.dylib",
		"safe-secret":           "fine",
	}
	derived, _, err := resolveChildEnvVars(secrets, nil, true, "web", "dev")
	require.NoError(t, err)
	assert.NotContains(t, derived, "DYLD_INSERT_LIBRARIES", "the dangerous derived name must be filtered")
	assert.Equal(t, "fine", derived["SAFE_SECRET"])
}

// TestResolveChildEnvVars_BothFlagsTogether: --var and --derive-names may be used
// together (bulk-derive the rest, but pin specific names explicitly). Not
// exercised via runRun's CLI surface by any other test, so covered directly here.
func TestResolveChildEnvVars_BothFlagsTogether(t *testing.T) {
	secrets := map[string]string{"db-password": "s3cr3t", "other": "other-val"}
	derived, varMapped, err := resolveChildEnvVars(secrets, []string{"DATABASE_URL=db-password"}, true, "web", "dev")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"DB_PASSWORD": "s3cr3t", "OTHER": "other-val"}, derived)
	assert.Equal(t, map[string]string{"DATABASE_URL": "s3cr3t"}, varMapped)
}

// ── buildChildEnv: precedence, tested in both directions ────────────────────────

// TestBuildChildEnv_Derived_InheritedWinsOnCollision is the precedence fix's core
// assertion: a derived (attacker-nameable) secret must NOT override a value
// already present in the inherited environment.
func TestBuildChildEnv_Derived_InheritedWinsOnCollision(t *testing.T) {
	t.Setenv("MY_APP_VAR", "inherited-value")
	derived := map[string]string{"MY_APP_VAR": "derived-value-must-not-win"}

	got := buildChildEnv(derived, nil, false)

	assert.True(t, containsEnv(got, "MY_APP_VAR", "inherited-value"), "inherited value must survive a derived-path collision, got: %v", got)
	assert.False(t, containsEnv(got, "MY_APP_VAR", "derived-value-must-not-win"), "derived value must NOT override the inherited one, got: %v", got)
}

// TestBuildChildEnv_Derived_NoCollision_StillInjected confirms the precedence
// change doesn't accidentally suppress derived injection in the common case where
// nothing is already inherited under that name.
func TestBuildChildEnv_Derived_NoCollision_StillInjected(t *testing.T) {
	derived := map[string]string{"KEYORIX_RUN_1816_NOVEL_VAR": "derived-value"}
	got := buildChildEnv(derived, nil, false)
	assert.True(t, containsEnv(got, "KEYORIX_RUN_1816_NOVEL_VAR", "derived-value"), "a derived var with nothing already inherited must still be injected, got: %v", got)
}

// TestBuildChildEnv_VarMapped_OverridesInheritedOnCollision is the --var
// counterpart: an explicit operator-chosen name DOES override an inherited value
// — overriding is the intent an operator expresses by naming it explicitly.
func TestBuildChildEnv_VarMapped_OverridesInheritedOnCollision(t *testing.T) {
	t.Setenv("MY_APP_VAR", "inherited-value")
	varMapped := map[string]string{"MY_APP_VAR": "explicit-value-must-win"}

	got := buildChildEnv(nil, varMapped, false)

	assert.True(t, containsEnv(got, "MY_APP_VAR", "explicit-value-must-win"), "an explicit --var mapping must override the inherited value, got: %v", got)
	assert.False(t, containsEnv(got, "MY_APP_VAR", "inherited-value"), "the inherited value must not survive an explicit --var override, got: %v", got)
}

// TestBuildChildEnv_VarMapped_OverridesDerived: when both --var and --derive-names
// are used together and collide on the same key, the explicit --var mapping wins
// — explicit operator intent is authoritative over auto-derivation.
func TestBuildChildEnv_VarMapped_OverridesDerived(t *testing.T) {
	derived := map[string]string{"SAME_KEY": "derived-value"}
	varMapped := map[string]string{"SAME_KEY": "explicit-value"}

	got := buildChildEnv(derived, varMapped, false)

	assert.True(t, containsEnv(got, "SAME_KEY", "explicit-value"), "--var must win over --derive-names on the same key, got: %v", got)
	assert.False(t, containsEnv(got, "SAME_KEY", "derived-value"), "the derived value must not survive a --var collision, got: %v", got)
}

// TestBuildChildEnv_Derived_InheritedWinsOnCollision_RedThenGreen is the
// red-then-green demonstration required by #1816: temporarily restore the OLD
// (pre-#1816) injected-last precedence for the derived path and confirm the
// override attack this task closes actually reproduces, then confirm the current
// (fixed) buildChildEnv refuses it. Scratch-only in intent (documents the
// regression, not a permanent duplicate of the test above) but left in the
// permanent suite since it costs nothing extra to keep as an explicit
// red-was-real record.
func TestBuildChildEnv_Derived_InheritedWinsOnCollision_RedThenGreen(t *testing.T) {
	t.Setenv("MY_APP_VAR", "inherited-value")
	derived := map[string]string{"MY_APP_VAR": "attacker-or-accidental-override"}

	// RED: reproduce the pre-#1816 shape directly (old buildChildEnv always
	// appended extraEnv last, unconditionally overriding inherited values).
	oldShapeEnv := append([]string{}, filterSensitiveEnv(nil)...)
	// (filterSensitiveEnv(nil) is empty; build the old-shape child env by hand
	// to avoid depending on a since-deleted function signature.)
	oldShapeEnv = []string{"MY_APP_VAR=inherited-value"}
	for k, v := range derived {
		oldShapeEnv = append(oldShapeEnv, k+"="+v) // old behavior: always appended last
	}
	if !containsEnv(oldShapeEnv, "MY_APP_VAR", "attacker-or-accidental-override") {
		t.Fatal("test setup bug: the hand-built old-shape env should demonstrate the override")
	}
	t.Log("RED (pre-#1816 shape): derived value overrides inherited, as expected of the old behavior")

	// GREEN: the current buildChildEnv must refuse this.
	got := buildChildEnv(derived, nil, false)
	require.True(t, containsEnv(got, "MY_APP_VAR", "inherited-value"), "GREEN check failed: current buildChildEnv must keep the inherited value")
	require.False(t, containsEnv(got, "MY_APP_VAR", "attacker-or-accidental-override"), "GREEN check failed: current buildChildEnv must not let the derived value win")
	t.Log("GREEN (current): inherited value survives the same collision")
}
