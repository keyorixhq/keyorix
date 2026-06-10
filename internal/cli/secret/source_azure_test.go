package secret

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAzure implements azureSecretsAPI over an in-memory map.
type fakeAzure struct {
	values map[string]string
}

func (f *fakeAzure) listNames(ctx context.Context) ([]string, error) {
	names := make([]string, 0, len(f.values))
	for k := range f.values {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

func (f *fakeAzure) getValue(ctx context.Context, name string) (string, error) {
	return f.values[name], nil
}

func TestCollectAzure(t *testing.T) {
	importNoExplode = false
	api := &fakeAzure{values: map[string]string{
		"stripe-key": "sk_live_xyz",
		"db-conn":    `{"host":"h","password":"pw"}`,
		"empty":      "",
	}}

	entries, err := collectAzure(context.Background(), api)
	require.NoError(t, err)

	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	assert.Equal(t, "sk_live_xyz", got["stripe-key"])
	assert.Equal(t, "h", got["db-conn-host"])
	assert.Equal(t, "pw", got["db-conn-password"])
	_, hasEmpty := got["empty"]
	assert.False(t, hasEmpty, "empty values are skipped")
}
