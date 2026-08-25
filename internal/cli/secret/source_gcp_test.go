package secret

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// TestCollectGCP_SkipIsCounted verifies the no-accessible-version skip is
// tallied in sourceSkipCount (not just printed), so runImport's final summary
// can report it alongside destination-side skips.
func TestCollectGCP_SkipIsCounted(t *testing.T) {
	gcpPrefix = ""
	importNoExplode = false
	sourceSkipCount = 0
	api := &fakeGCP{
		names: []string{
			"projects/p/secrets/kept",
			"projects/p/secrets/novers-1",
			"projects/p/secrets/novers-2",
		},
		values:    map[string]string{"projects/p/secrets/kept": "v"},
		noVersion: map[string]bool{"projects/p/secrets/novers-1": true, "projects/p/secrets/novers-2": true},
	}

	entries, err := collectGCP(context.Background(), api, "p")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, 2, sourceSkipCount, "both no-version secrets are counted as skipped")
}

func TestFetchFromGCP_RequiresProject(t *testing.T) {
	gcpProject = ""
	_, err := fetchFromGCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GCP project")
}

// TestIsNoAccessibleVersion pins the gRPC-status-to-skip mapping that
// accessLatest relies on to decide "skip this secret" vs "fail the whole
// import". NotFound and FailedPrecondition are the two statuses Secret
// Manager actually returns for "no accessible version" — anything else
// (PermissionDenied, Unavailable, a non-status error) must NOT be treated as
// a skip, or a transient/auth failure on one secret would silently drop it
// instead of failing the import loudly.
func TestIsNoAccessibleVersion(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"NotFound is a skip", status.Error(codes.NotFound, "secret not found"), true},
		{"FailedPrecondition is a skip", status.Error(codes.FailedPrecondition, "version destroyed"), true},
		{"PermissionDenied is NOT a skip", status.Error(codes.PermissionDenied, "no access"), false},
		{"Unavailable is NOT a skip", status.Error(codes.Unavailable, "transient"), false},
		{"a plain non-status error is NOT a skip", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isNoAccessibleVersion(tc.err))
		})
	}
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
