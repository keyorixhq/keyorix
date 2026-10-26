package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoInventoryConfig_ZeroValueIsValidAndMeansDefaults(t *testing.T) {
	c := &Config{}
	require.NoError(t, validateCryptoInventorySection(c))
	h, err := c.CryptoInventory.ParsedHorizon()
	require.NoError(t, err)
	assert.True(t, h.IsZero(), "unset horizon must stay zero so the caller applies the documented default")
}

func TestCryptoInventoryConfig_ParsesHorizon(t *testing.T) {
	c := &Config{CryptoInventory: CryptoInventoryConfig{QuantumHorizon: "2032-06-30", MigrationYears: 5, UnboundedLifetimeYears: 20}}
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
		"negative migration":      {MigrationYears: -1},
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
