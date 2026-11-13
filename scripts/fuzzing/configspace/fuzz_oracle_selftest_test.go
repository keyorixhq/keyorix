package configspace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestCanaryOracleSelfTest proves the I4 oracle of FuzzConfigLoadValidate in both
// directions: an echoed key name is not a leak, a planted value leak still is.
func TestCanaryOracleSelfTest(t *testing.T) {
	cases := []struct {
		name string
		text string
		leak bool
	}{
		{"rewritten unknown key echo", `load: yaml: unknown key "` + fuzzCanary + `" at the top level of the file (check its spelling and section in docs/CONFIGURATION.md)`, false},
		{"raw yaml field echo", `load: yaml: unmarshal errors: line 1: field ` + fuzzCanary + ` not found in type config.Config`, false},
		{"no canary", `validate: storage.type is required`, false},
		{"planted value leak", `validate: siem.token "` + fuzzCanary + `" is too short`, true},
		{"planted dsn leak", `load: dial postgres://k:` + fuzzCanary + `@db.example.com:5432/k failed`, true},
		{"key echo plus value leak", `unknown key "` + fuzzCanary + `" at the top level of the file; token=` + fuzzCanary, true},
		{"key echo then value after quote", `unknown key "x" at the top level; got ` + fuzzCanary, true},
	}
	for _, c := range cases {
		if got := canaryLeaksAsValue(c.text); got != c.leak {
			t.Errorf("%s: canaryLeaksAsValue = %v, want %v\n  text: %s", c.name, got, c.leak, c.text)
		}
	}
}

// TestCanaryAsTopLevelKeyIsNotALeak drives the real loader with the canary as an unknown
// top-level key, the shape CI run 43424626656 (shard 5) flagged.
func TestCanaryAsTopLevelKeyIsNotALeak(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keyorix.yaml")
	if err := os.WriteFile(p, []byte(fuzzCanary+": 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("unknown top-level key was accepted")
	}
	if canaryLeaksAsValue("load: " + err.Error()) {
		t.Fatalf("echoed key name flagged as a value leak: %v", err)
	}
}
