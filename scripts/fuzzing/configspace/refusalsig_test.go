package configspace

import (
	"strings"
	"testing"
)

// TestRefusalKey_TiedToCauseNotLineOrPath proves the refusal-unnamed dedupe key is a
// masked signature of the refusal CAUSE: two different refusals never share a key, and the
// same refusal with a different line number, file path, quoted value or log timestamp
// keeps its key. This is what stops minimisation drifting between causes.
//
// Red/green (planted-mutation) note: replace maskRefusal's body with `return s` (identity,
// the degenerate "no masking") and the "same refusal, different line/path/..." cases go
// red; replace it with `return ""` (constant, the shape of the old firstAssign key that
// ignored the text entirely) and the "two different refusals" case goes red. Both were
// watched red, then reverted — the mutation is not committed.
func TestRefusalKey_TiedToCauseNotLineOrPath(t *testing.T) {
	// Two genuinely different refusals must get different keys.
	differentPairs := [][2]string{
		{
			"failed to unmarshal config: yaml: unmarshal errors:\n  line 51: cannot unmarshal !!str `maybe` into bool",
			"failed to unmarshal config: yaml: unmarshal errors:\n  line 52: cannot unmarshal !!str `big` into int64",
		},
		{
			"storage.database.pooler \"pgbouncer-session\" applies only to storage.type postgres; remove it",
			"storage.database.audit_durability is \"strict\" but the deprecated storage.database.insecure_audit_skip_durable_sync: true means \"standard\"; remove the deprecated key",
		},
		{
			"KEK salt file /a/b/fx/empty has invalid size 0 bytes (expected 32)",
			"wrapped DEK file /a/b/fx/x is too small (12 bytes) to be a valid wrapped key",
		},
	}
	for i, p := range differentPairs {
		if k0, k1 := refusalKey(p[0]), refusalKey(p[1]); k0 == k1 {
			t.Errorf("different refusals %d share a key: %q", i, k0)
		}
	}

	// The SAME refusal with a volatile token changed (line number, path, quoted value,
	// timestamp) must keep its key.
	sameGroups := [][]string{
		{ // line number varies
			"failed to unmarshal config: yaml: unmarshal errors:\n  line 51: cannot unmarshal !!str `maybe` into bool",
			"failed to unmarshal config: yaml: unmarshal errors:\n  line 207: cannot unmarshal !!str `maybe` into bool",
		},
		{ // file path varies
			"cannot open /mnt/data/run1/fx/missing (no such file or directory)",
			"cannot open /tmp/run2/certs/server.crt (no such file or directory)",
		},
		{ // quoted value and byte size vary
			"KEK salt file /a/b/empty has invalid size 0 bytes (expected 32)",
			"KEK salt file /c/d/short has invalid size 7 bytes (expected 32)",
		},
	}
	for i, g := range sameGroups {
		first := refusalKey(g[0])
		for _, s := range g[1:] {
			if k := refusalKey(s); k != first {
				t.Errorf("same refusal %d got different keys: %q vs %q", i, first, k)
			}
		}
	}
}

// TestLastRefusalLine_YAMLContinuation checks that a YAML unmarshal error (header line,
// then an indented "line N:" detail) is captured as one operative line, not just the
// indented tail, so its masked key keeps the distinguishing wording.
func TestLastRefusalLine_YAMLContinuation(t *testing.T) {
	log := "2026/11/13 18:36:47 Failed to load configuration: failed to unmarshal config: yaml: unmarshal errors:\n  line 51: cannot unmarshal !!str `maybe` into bool\n"
	got := lastRefusalLine(log)
	if want := "yaml: unmarshal errors: line 51: cannot unmarshal !!str `maybe` into bool"; !strings.Contains(got, want) {
		t.Errorf("lastRefusalLine did not prepend the header:\n got  %q", got)
	}
	// a plain single-line fatal is returned as-is (its own last line)
	single := "2026/11/13 18:36:50 HTTP server error: failed to load TLS certificate: tls: found a certificate rather than a key\n"
	if got := lastRefusalLine(single); !strings.HasSuffix(got, "rather than a key") {
		t.Errorf("lastRefusalLine mangled a single-line fatal: %q", got)
	}
}
