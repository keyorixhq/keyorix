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

// TestCollectAzure_ValuelessSecretIsSkippedByNameAndCounted pins the fix for
// the silent-drop finding: a Key Vault secret with no accessible value (e.g.
// disabled, or a certificate-only secret where getValue returns "") must be
// (a) reported by name at the point it's skipped, not silently dropped, and
// (b) tallied in sourceSkipCount so the final import summary can report it.
func TestCollectAzure_ValuelessSecretIsSkippedByNameAndCounted(t *testing.T) {
	importNoExplode = false
	sourceSkipCount = 0
	api := &fakeAzure{values: map[string]string{
		"disabled-secret": "",
	}}

	var entries []secretEntry
	var err error
	out := captureStdout(t, func() {
		entries, err = collectAzure(context.Background(), api)
	})
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Equal(t, 1, sourceSkipCount, "the valueless secret must be counted as skipped")
	assert.Contains(t, out, "disabled-secret", "the skip must name the secret, not just count it")
	assert.Contains(t, out, "Skipped")
}

// TestCollectAzure_MixedBatch_SkipCountIsExact drives a batch with both kinds
// of secret through collectAzure and checks the skip tally lands exactly on
// the valueless ones — neither over- nor under-counting the imported entries.
func TestCollectAzure_MixedBatch_SkipCountIsExact(t *testing.T) {
	importNoExplode = false
	sourceSkipCount = 0
	api := &fakeAzure{values: map[string]string{
		"good-1":     "value-1",
		"good-2":     "value-2",
		"disabled-1": "",
		"disabled-2": "",
	}}

	entries, err := collectAzure(context.Background(), api)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "only the two valued secrets become entries")
	assert.Equal(t, 2, sourceSkipCount, "exactly the two valueless secrets are counted as skipped")
}
