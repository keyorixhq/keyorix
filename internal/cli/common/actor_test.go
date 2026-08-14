package common

import "testing"

// #150: KEYORIX_CLI_ACTOR lets an operator self-assert their own numeric user ID
// so local-CLI mutations against a shared backend aren't attributed to actorID=0.
func TestResolveActorID(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want uint
	}{
		{"unset", "", 0},
		{"valid", "42", 42},
		{"zero explicit", "0", 0},
		{"non-numeric", "not-a-number", 0},
		{"negative", "-1", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.env == "" {
				t.Setenv(cliActorEnvVar, "")
			} else {
				t.Setenv(cliActorEnvVar, c.env)
			}
			if got := ResolveActorID(); got != c.want {
				t.Errorf("ResolveActorID() with %s=%q = %d, want %d", cliActorEnvVar, c.env, got, c.want)
			}
		})
	}
}

// TestResolveActorLabel is the #G67 detection_idea for the string-typed
// attribution fields (core.CreateSecretRequest.CreatedBy/UpdatedBy) that
// previously hardcoded the literal "cli-user" regardless of KEYORIX_CLI_ACTOR:
// setting the env var to a specific ID must be reflected in the resolved label,
// and the existing "cli-user" default must survive when it's unset/invalid —
// exactly the fallback ResolveActorID() itself already uses for 0.
func TestResolveActorLabel(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
	}{
		{"unset", "", "cli-user"},
		{"valid", "42", "42"},
		{"zero explicit", "0", "cli-user"},
		{"non-numeric", "not-a-number", "cli-user"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(cliActorEnvVar, c.env)
			if got := ResolveActorLabel(); got != c.want {
				t.Errorf("ResolveActorLabel() with %s=%q = %q, want %q", cliActorEnvVar, c.env, got, c.want)
			}
		})
	}
}
