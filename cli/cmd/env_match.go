package cmd

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// matchEnvironmentID resolves an environment NAME to its id within the project
// listing envs. The server keeps (project, name) unique case-SENSITIVELY, so "Prod"
// and "prod" can both exist in one project; a case-insensitive first-match would
// then silently pick whichever is listed first, which for `run` injects another
// environment's secrets and for `rbac` grants a role on the wrong environment.
//
// Order: an exact match wins. Otherwise a case-insensitive match is accepted only if
// it is unique (so `--env production` still reaches `Production` when nothing else
// folds to it). More than one case-insensitive match is an error naming the
// candidates, never a guess. Returns 0 and a nil error when nothing matches, so each
// caller keeps its own not-found message.
func matchEnvironmentID(envs []apiclient.Environment, name string) (int, error) {
	var folded []apiclient.Environment
	for _, e := range envs {
		if e.Name == nil {
			continue
		}
		if *e.Name == name {
			return derefInt(e.Id), nil
		}
		if strings.EqualFold(*e.Name, name) {
			folded = append(folded, e)
		}
	}
	switch len(folded) {
	case 0:
		return 0, nil
	case 1:
		return derefInt(folded[0].Id), nil
	}
	names := make([]string, len(folded))
	for i, e := range folded {
		names[i] = fmt.Sprintf("%q", *e.Name)
	}
	return 0, fmt.Errorf("environment %q is ambiguous: it matches %s differing only in case; use the exact name", name, strings.Join(names, ", "))
}
