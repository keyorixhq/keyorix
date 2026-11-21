package cmd

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// matchEnvironmentIndex resolves an environment NAME against the listed names and
// returns the index of the match, or -1 when nothing matches. The server keeps
// (project, name) unique case-SENSITIVELY, so "Prod" and "prod" can both exist in one
// project; a case-insensitive first-match would then silently pick whichever is listed
// first, which for `run` injects another environment's secrets, for `rbac` grants a
// role on the wrong environment and for `secret create` writes into the wrong one.
//
// Order: an exact match wins. Otherwise a case-insensitive match is accepted only if it
// is unique (so `--env production` still reaches `Production` when nothing else folds to
// it). More than one case-insensitive match is an error naming the candidates, never a
// guess. A nil entry is skipped.
func matchEnvironmentIndex(names []*string, want string) (int, error) {
	var folded []int
	for i, n := range names {
		if n == nil {
			continue
		}
		if *n == want {
			return i, nil
		}
		if strings.EqualFold(*n, want) {
			folded = append(folded, i)
		}
	}
	switch len(folded) {
	case 0:
		return -1, nil
	case 1:
		return folded[0], nil
	}
	quoted := make([]string, len(folded))
	for k, i := range folded {
		quoted[k] = fmt.Sprintf("%q", *names[i])
	}
	return -1, fmt.Errorf("environment %q is ambiguous: it matches %s differing only in case; use the exact name", want, strings.Join(quoted, ", "))
}

// matchEnvironmentID is matchEnvironmentIndex over an environment listing, returning the
// matched environment's id. It returns 0 and a nil error when nothing matches, so each
// caller keeps its own not-found message.
func matchEnvironmentID(envs []apiclient.Environment, name string) (int, error) {
	names := make([]*string, len(envs))
	for i := range envs {
		names[i] = envs[i].Name
	}
	i, err := matchEnvironmentIndex(names, name)
	if err != nil || i < 0 {
		return 0, err
	}
	return derefInt(envs[i].Id), nil
}
