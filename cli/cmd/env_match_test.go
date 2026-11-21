package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

func envs(pairs ...any) []apiclient.Environment {
	var out []apiclient.Environment
	for i := 0; i < len(pairs); i += 2 {
		id, name := pairs[i].(int), pairs[i+1].(string)
		out = append(out, apiclient.Environment{Id: &id, Name: &name})
	}
	return out
}

// The server allows "Prod" and "prod" in one project. An exact name must reach its
// own environment whichever is listed first, never the other one.
func TestMatchEnvironmentID_ExactBeatsCaseFold(t *testing.T) {
	list := envs(1, "prod", 2, "Prod")
	for name, want := range map[string]int{"prod": 1, "Prod": 2} {
		got, err := matchEnvironmentID(list, name)
		if err != nil || got != want {
			t.Fatalf("name %q: got %d, %v; want %d", name, got, err, want)
		}
	}
}

// A name that only differs in case still resolves while it is unambiguous, so
// existing `--env production` usage against `Production` keeps working.
func TestMatchEnvironmentID_UniqueCaseFoldStillResolves(t *testing.T) {
	got, err := matchEnvironmentID(envs(7, "Production", 8, "staging"), "production")
	if err != nil || got != 7 {
		t.Fatalf("got %d, %v; want 7", got, err)
	}
}

// Two environments that fold to the requested name and neither is exact: refuse,
// naming both, rather than picking the first listed.
func TestMatchEnvironmentID_AmbiguousCaseFoldRefused(t *testing.T) {
	got, err := matchEnvironmentID(envs(1, "prod", 2, "Prod"), "PROD")
	if err == nil {
		t.Fatalf("resolved %d for an ambiguous name; want an error", got)
	}
	if got != 0 || !strings.Contains(err.Error(), `"prod"`) || !strings.Contains(err.Error(), `"Prod"`) {
		t.Fatalf("got %d, %v; want 0 and an error naming both candidates", got, err)
	}
}

func TestMatchEnvironmentID_NoMatchReturnsZero(t *testing.T) {
	got, err := matchEnvironmentID(envs(1, "prod"), "dev")
	if err != nil || got != 0 {
		t.Fatalf("got %d, %v; want 0, nil", got, err)
	}
}
