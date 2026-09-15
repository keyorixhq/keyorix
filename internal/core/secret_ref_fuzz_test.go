package core

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseSecretRef fuzzes ParseSecretRef, which splits a caller-supplied
// "project/environment/name" reference into its three components. The ref reaches
// this parser straight from CLI args, API paths, and federated-secret lookups, so
// it is untrusted, and a malformed ref must be rejected cleanly rather than yield
// a partially-populated tuple that later addresses the wrong secret.
//
// Invariants: (a) never panics; (b) on success every component is non-empty AND
// carries no surrounding whitespace (the parser trims), so a caller never routes
// on a blank or space-padded segment; (c) on error all three components are empty,
// so a rejected ref cannot leak a partial project/environment/name.
func FuzzParseSecretRef(f *testing.F) {
	seeds := []string{
		"proj/env/name",
		"  proj / env / name  ",
		"a/b/c/d",          // too many segments
		"proj/env",         // too few
		"proj//name",       // blank middle
		"/env/name",        // blank project
		"proj/env/",        // blank name
		"",                 // empty
		"   ",              // whitespace only
		"proj/env/name/",   // trailing slash -> 4 segments after split? (SplitN=3)
		"a/b/c d",          // space inside name
		"проект/среда/имя", // non-ASCII
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		var project, environment, name string
		var err error
		fuzzutil.Guard(t.Fatalf, "ParseSecretRef", func() {
			project, environment, name, err = ParseSecretRef(ref)
		})

		if err != nil {
			if project != "" || environment != "" || name != "" {
				t.Fatalf("ParseSecretRef(%q) errored but returned a partial tuple: project=%q environment=%q name=%q err=%v", ref, project, environment, name, err)
			}
			return
		}
		// Success: no empty component, and each already trimmed (idempotent trim).
		for label, v := range map[string]string{"project": project, "environment": environment, "name": name} {
			if v == "" {
				t.Fatalf("ParseSecretRef(%q) succeeded with an empty %s: project=%q environment=%q name=%q", ref, label, project, environment, name)
			}
			if v != strings.TrimSpace(v) {
				t.Fatalf("ParseSecretRef(%q) succeeded with an untrimmed %s=%q", ref, label, v)
			}
		}
	})
}
