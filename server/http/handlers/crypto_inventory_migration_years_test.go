package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// An explicit `migration_years: 0` means "no migration time", not "use the default
// 3"; only an absent key gets the default. The config is parsed from YAML, the way
// a real keyorix.yaml reaches the handler.
func TestCryptoInventoryPolicy_MigrationYearsZeroIsExplicit(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want int
	}{
		"absent key keeps the default": {"quantum_horizon: 2031-03-04\n", 3},
		"empty section":                {"{}\n", 3},
		"explicit zero":                {"migration_years: 0\n", 0},
		"explicit value":               {"migration_years: 7\n", 7},
	} {
		t.Run(name, func(t *testing.T) {
			var cc config.CryptoInventoryConfig
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &cc))
			p, err := cryptoInventoryPolicy(cc)
			require.NoError(t, err)
			assert.Equal(t, tc.want, p.MigrationYears)
			assert.NoError(t, p.Validate(), "zero migration years is a valid policy")
		})
	}
}
