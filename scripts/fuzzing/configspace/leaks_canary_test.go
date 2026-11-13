package configspace

import "testing"

// TestLeaksCanary pins the I4 oracle: a canary echoed as an unknown key name is tolerated,
// a canary in any other part of an error text is a leak (watched red when the regexp was
// widened to swallow the whole message, and when the helper always returned false).
func TestLeaksCanary(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		want    bool
	}{
		{"no canary", "load: failed to unmarshal config", false},
		{"unknown key echo", `load: yaml: line 1: unknown key "` + fuzzCanary + `" at the top level of the file`, false},
		{"canary in a value", `validate: storage.database.dsn: invalid "postgres://k:` + fuzzCanary + `@h/db"`, true},
		{"canary after an unknown key echo", `unknown key "x" ... ` + fuzzCanary, true},
		{"key echo and value", `unknown key "` + fuzzCanary + `" ... token ` + fuzzCanary, true},
		{"quoted but not an unknown-key message", `bad value "` + fuzzCanary + `"`, true},
	}
	for _, c := range cases {
		if got := leaksCanary(c.verdict); got != c.want {
			t.Errorf("%s: leaksCanary = %v, want %v", c.name, got, c.want)
		}
	}
}
