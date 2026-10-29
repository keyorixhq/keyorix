package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCryptoInventoryConfig_ZeroValueIsValidAndMeansDefaults(t *testing.T) {
	c := &Config{}
	require.NoError(t, validateCryptoInventorySection(c))
	h, err := c.CryptoInventory.ParsedHorizon()
	require.NoError(t, err)
	assert.True(t, h.IsZero(), "unset horizon must stay zero so the caller applies the documented default")
}

func TestCryptoInventoryConfig_ParsesHorizon(t *testing.T) {
	c := &Config{CryptoInventory: CryptoInventoryConfig{QuantumHorizon: "2032-06-30", MigrationYears: IntPtr(5), UnboundedLifetimeYears: 20}}
	require.NoError(t, validateCryptoInventorySection(c))
	h, err := c.CryptoInventory.ParsedHorizon()
	require.NoError(t, err)
	assert.Equal(t, 2032, h.Year())
	assert.Equal(t, 6, int(h.Month()))
}

func TestCryptoInventoryConfig_RejectsBadValues(t *testing.T) {
	for name, cc := range map[string]CryptoInventoryConfig{
		"horizon not a date":      {QuantumHorizon: "soon"},
		"horizon wrong format":    {QuantumHorizon: "30/06/2032"},
		"negative migration":      {MigrationYears: IntPtr(-1)},
		"negative unbounded life": {UnboundedLifetimeYears: -5},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateCryptoInventorySection(&Config{CryptoInventory: cc})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "crypto_inventory")
		})
	}
}

func TestCryptoInventoryConfig_RegisteredInValidators(t *testing.T) {
	c := &Config{CryptoInventory: CryptoInventoryConfig{QuantumHorizon: "nonsense"}}
	var failed bool
	for _, v := range configValidators {
		if v(c) != nil {
			failed = true
		}
	}
	assert.True(t, failed, "an invalid crypto_inventory section must be rejected by Validate")
}

// An explicit `migration_years: 0` must stay distinguishable from an absent key:
// the first means zero migration time, the second the documented default.
func TestCryptoInventoryConfig_MigrationYearsZeroIsDistinctFromAbsent(t *testing.T) {
	var absent, zero, five CryptoInventoryConfig
	require.NoError(t, yaml.Unmarshal([]byte("quantum_horizon: 2031-03-04\n"), &absent))
	require.NoError(t, yaml.Unmarshal([]byte("migration_years: 0\n"), &zero))
	require.NoError(t, yaml.Unmarshal([]byte("migration_years: 5\n"), &five))

	assert.Nil(t, absent.MigrationYears, "absent key stays unset so the default applies")
	require.NotNil(t, zero.MigrationYears, "explicit 0 must be recorded as set")
	assert.Equal(t, 0, *zero.MigrationYears)
	require.NotNil(t, five.MigrationYears)
	assert.Equal(t, 5, *five.MigrationYears)

	for _, cc := range []CryptoInventoryConfig{absent, zero, five} {
		require.NoError(t, validateCryptoInventorySection(&Config{CryptoInventory: cc}))
	}
}
