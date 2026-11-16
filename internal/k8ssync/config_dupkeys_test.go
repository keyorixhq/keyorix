package k8ssync

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The agent config is operator-provided, but the YAML library charges O(n^2) for a
// mapping that repeats a key (https://github.com/yaml/go-yaml/issues/510), so a
// duplicate key is rejected before decoding.
func TestLoadConfig_DuplicateKeyRejected(t *testing.T) {
	p := writeConfig(t, "keyorix_url: https://keyorix.internal\nproject_id: 1\nproject_id: 2\n")
	_, err := LoadConfig(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already defined")
}

// The library alone allocates about 1.4 GB for 20000 repeats, so roughly 14 MB
// (quadratic) for 2000; the pre-check stays well under the 8 MiB bound.
func TestLoadConfig_ManyDuplicateKeysFailQuickly(t *testing.T) {
	p := writeConfig(t, strings.Repeat("interval: 1m\n", 2000))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := LoadConfig(p)
	runtime.ReadMemStats(&after)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already defined")
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20))
}
