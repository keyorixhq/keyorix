package secret

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGCP implements gcpSecretsAPI over in-memory maps keyed by the full secret
// resource name ("projects/p/secrets/<name>").
type fakeGCP struct {
	names     []string
	values    map[string]string
	noVersion map[string]bool // names whose latest version is missing/disabled (ok=false)
}

func (f *fakeGCP) listSecrets(_ context.Context, _ string) ([]string, error) { return f.names, nil }

func (f *fakeGCP) accessLatest(_ context.Context, name string) (string, bool, error) {
	if f.noVersion[name] {
		return "", false, nil
	}
	return f.values[name], true, nil
}

func TestCollectGCP(t *testing.T) {
	gcpPrefix = ""
	importNoExplode = false
	api := &fakeGCP{
		names: []string{
			"projects/p/secrets/plain",
			"projects/p/secrets/prod-db",
			"projects/p/secrets/novers",
		},
		values: map[string]string{
			"projects/p/secrets/plain":   "just-a-string",
			"projects/p/secrets/prod-db": `{"username":"u","password":"p"}`,
		},
		noVersion: map[string]bool{"projects/p/secrets/novers": true},
	}

	entries, err := collectGCP(context.Background(), api, "p")
	require.NoError(t, err)

	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	assert.Equal(t, "just-a-string", got["plain"])
	assert.Equal(t, "u", got["prod-db-username"], "JSON values explode into one secret per field")
	assert.Equal(t, "p", got["prod-db-password"])
	_, hasNoVers := got["novers"]
	assert.False(t, hasNoVers, "a secret with no accessible version is skipped")
}

func TestCollectGCP_PrefixFilter(t *testing.T) {
	gcpPrefix = "prod-"
	importNoExplode = true
	api := &fakeGCP{
		names: []string{
			"projects/p/secrets/dev-x",
			"projects/p/secrets/prod-y",
			"projects/p/secrets/prod-z",
		},
		values: map[string]string{
			"projects/p/secrets/dev-x":  "1",
			"projects/p/secrets/prod-y": "2",
			"projects/p/secrets/prod-z": "3",
		},
	}

	entries, err := collectGCP(context.Background(), api, "p")
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"prod-y", "prod-z"}, names)
	gcpPrefix = ""
}

func TestFetchFromGCP_RequiresProject(t *testing.T) {
	gcpProject = ""
	_, err := fetchFromGCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GCP project")
}
