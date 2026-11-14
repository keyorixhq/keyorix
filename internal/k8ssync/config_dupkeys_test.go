package k8ssync

import (
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

func TestLoadConfig_ManyDuplicateKeysFailQuickly(t *testing.T) {
	p := writeConfig(t, strings.Repeat("interval: 1m\n", 20000))
	_, err := LoadConfig(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already defined")
}
