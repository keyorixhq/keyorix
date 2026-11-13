package configcompat

import (
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/fuzzing/configspace"
)

func mustModel(t *testing.T) *configspace.Model {
	t.Helper()
	m, err := configspace.LoadModel()
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	return m
}

func newEnv(t *testing.T) *Env {
	t.Helper()
	return NewEnv(t.TempDir())
}

// TestSeedsPresent confirms the committed old-config corpus covers the chosen
// revs — the ground truth the whole differential rests on.
func TestSeedsPresent(t *testing.T) {
	seeds := SeedConfigs()
	if len(seeds) == 0 {
		t.Fatal("no embedded seed configs")
	}
	for _, rev := range Revs {
		found := false
		for name := range seeds {
			if strings.HasPrefix(name, rev+"__") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no seed config for rev %s", rev)
		}
	}
}

// TestSeedsDoNotPanicAndAreDeterministic runs the I1 robustness oracle on every
// committed seed — the corpus itself must be green.
func TestSeedsDoNotPanicAndAreDeterministic(t *testing.T) {
	env := newEnv(t)
	for name, data := range SeedConfigs() {
		for _, fnd := range CheckI1Robust(env.Load, data) {
			t.Errorf("seed %s: %s", name, fnd)
		}
	}
}

// TestI2_DefaultPostureMatchesAllowlist is the I2 default-drift guard: the
// posture predicates that hold on a DEFAULTS-ONLY config must exactly equal the
// committed allowlist (default_posture.tsv). A new holding posture here means a
// default silently weakened the baseline; a stale row means the allowlist rotted.
func TestI2_DefaultPostureMatchesAllowlist(t *testing.T) {
	m := mustModel(t)
	env := newEnv(t)
	r := env.Load([]byte("")) // empty file = all defaults
	if r.Cfg == nil {
		t.Fatalf("empty config did not load: %s", r.Verdict)
	}
	live := map[string]bool{}
	for _, id := range m.PostureHolds(r.Cfg) {
		live[id] = true
	}
	allow := defaultPostureSet()
	for id := range live {
		if !allow[id] {
			t.Errorf("posture %s holds on a defaults-only config but is NOT in default_posture.tsv "+
				"(a default may have silently weakened the baseline) — add a row with a reason if intended", id)
		}
	}
	for id := range allow {
		if !live[id] {
			t.Errorf("default_posture.tsv lists %s but it no longer holds on a defaults-only config (stale allowlist row)", id)
		}
	}
	// surface the live set to make a mismatch easy to reconcile
	var ids []string
	for id := range live {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Logf("defaults-only posture set: %v", ids)
}

// TestI3_AllAliasPairsEquivalent is the real I3 production guard AND its green
// proof: for every deprecated-alias pair the loader honours, a config written
// with the old key must load, warn by name, and be fingerprint-identical to the
// same config written with the new key. Runs against the real config.Load.
func TestI3_AllAliasPairsEquivalent(t *testing.T) {
	m := mustModel(t)
	env := newEnv(t)
	pairs := aliasPairs()
	if len(pairs) == 0 {
		t.Fatal("no alias pairs")
	}
	for _, p := range pairs {
		for _, fnd := range CheckI3(m, env.Load, p, true) {
			t.Errorf("alias %s -> %s: %s", p.Old, p.New, fnd)
		}
	}
}

// ---- Planted red/green proofs (production code is NOT edited; defects are
// injected behaviourally so each oracle is proven non-vacuous). ----

// scrubKeyNames simulates a regression where refusals stop naming the offending
// key (the I1 fail-closed property is lost).
func scrubKeyNames(inner LoadFunc) LoadFunc {
	return func(data []byte) LoadResult {
		r := inner(data)
		r.Verdict = keyEcho.ReplaceAllString(r.Verdict, "a redacted error")
		return r
	}
}

// panicLoader simulates a loader that panics.
func panicLoader(_ []byte) LoadResult { return LoadResult{Panicked: true, Verdict: "panic"} }

// dropWarnings simulates a regression where a deprecated key is accepted but its
// warning is dropped (silent alias).
func dropWarnings(inner LoadFunc) LoadFunc {
	return func(data []byte) LoadResult {
		r := inner(data)
		r.Warnings = nil
		return r
	}
}

func TestI1Named_PlantRedGreen(t *testing.T) {
	m := mustModel(t)
	env := newEnv(t)
	const probe = "cc1planted"
	// GREEN: real loader names the unknown key.
	if fnd := CheckI1Named(m, env.Load, probe); len(fnd) != 0 {
		t.Fatalf("green: real loader should name the unknown key, got %v", fnd)
	}
	// RED: a loader that scrubs key names is caught.
	if fnd := CheckI1Named(m, scrubKeyNames(env.Load), probe); len(fnd) == 0 {
		t.Fatal("red: scrubbed-key-name loader should be flagged by I1 but was not (oracle vacuous)")
	}
}

func TestI1Robust_PlantRedGreen(t *testing.T) {
	env := newEnv(t)
	good := []byte("storage:\n  type: sqlite\n")
	// GREEN
	if fnd := CheckI1Robust(env.Load, good); len(fnd) != 0 {
		t.Fatalf("green: real loader should not report I1 robustness findings, got %v", fnd)
	}
	// RED: panic
	if fnd := CheckI1Robust(panicLoader, good); len(fnd) == 0 {
		t.Fatal("red: panicking loader should be flagged by I1 but was not")
	}
	// RED: canary value leaked in an error (non-key echo).
	leaky := func(_ []byte) LoadResult { return LoadResult{Verdict: "load: bad value " + Canary} }
	if fnd := CheckI1Robust(leaky, good); len(fnd) == 0 {
		t.Fatal("red: canary-leaking loader should be flagged by I1 but was not")
	}
}

func TestI2_PlantRedGreen(t *testing.T) {
	m := mustModel(t)
	env := newEnv(t)
	// A config that explicitly opts into P10 (a catch-all trusted-proxy range)
	// on a listener that is not enabled, so it validates and CheckI2 runs on it.
	data := []byte("storage:\n  type: sqlite\n  database:\n    path: k.db\nserver:\n  http:\n    trusted_proxies: [\"0.0.0.0/0\"]\n")
	r := env.Load(data)
	if r.Cfg == nil || isRefusal(r.Verdict) {
		t.Fatalf("setup: trusted-proxy config did not load+validate: %s", r.Verdict)
	}
	defaults := defaultPostureSet()
	// GREEN: the real explicit-presence function sees server.http.trusted_proxies,
	// so P10 is explained — no finding.
	if fnd := CheckI2(m, r, data, defaults, rawHasPath); len(fnd) != 0 {
		t.Fatalf("green: explicit P10 opt-in should be explained, got %v", fnd)
	}
	// RED: an explicit-checker that never finds a key flags P10 as a silently
	// weakened default.
	never := func(_ []byte, _ string) bool { return false }
	fnd := CheckI2(m, r, data, defaults, never)
	foundP10 := false
	for _, f := range fnd {
		if f.Key == "P10" {
			foundP10 = true
		}
	}
	if !foundP10 {
		t.Fatalf("red: expected a P10 I2 finding with a blind explicit-checker, got %v", fnd)
	}
}

func TestI3_PlantRedGreen(t *testing.T) {
	m := mustModel(t)
	env := newEnv(t)
	pairs := aliasPairs()
	real := pairs[0]
	// GREEN: a real alias pair is equivalent and named.
	if fnd := CheckI3(m, env.Load, real, true); len(fnd) != 0 {
		t.Fatalf("green: real alias pair %v should be equivalent, got %v", real, fnd)
	}
	// RED (meaning change): a bogus "alias" whose old and new keys mean
	// different things must be caught as a fingerprint divergence.
	bogus := AliasPair{Old: "security.require_mfa", New: "security.insecure_allow_unsafe_file_permissions"}
	if fnd := CheckI3(m, env.Load, bogus, true); len(fnd) == 0 {
		t.Fatal("red: a meaning-changing bogus alias should be flagged by I3 but was not")
	}
	// RED (silent alias): a loader that drops the deprecation warning is caught.
	if fnd := CheckI3(m, dropWarnings(env.Load), real, true); len(fnd) == 0 {
		t.Fatal("red: a warning-dropping loader should be flagged by I3 but was not")
	}
}
