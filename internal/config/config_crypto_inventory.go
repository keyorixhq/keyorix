package config

import (
	"fmt"
	"time"
)

// CryptoInventoryConfig tunes the quantum-risk score of the crypto inventory /
// CBOM (RD-CBOM-1, GET /api/v1/compliance/crypto-inventory). Every field is
// optional: an unset field means the documented default (horizon 2035-01-01,
// migration 3 years, unbounded lifetime 10 years), which the cryptoinventory
// package owns so the defaults live in exactly one place.
type CryptoInventoryConfig struct {
	// QuantumHorizon is the date (YYYY-MM-DD) by which a cryptographically
	// relevant quantum computer is assumed to exist.
	QuantumHorizon string `yaml:"quantum_horizon"`
	// MigrationYears is how long moving off a quantum-vulnerable algorithm takes.
	// A pointer so an explicit 0 ("no migration time") differs from an absent key,
	// which keeps the default of 3.
	MigrationYears *int `yaml:"migration_years"`
	// UnboundedLifetimeYears is the lifetime assumed for a key with no expiry.
	UnboundedLifetimeYears int `yaml:"unbounded_lifetime_years"`
}

// ParsedHorizon returns the configured horizon, or the zero time when unset.
func (c CryptoInventoryConfig) ParsedHorizon() (time.Time, error) {
	if c.QuantumHorizon == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", c.QuantumHorizon)
	if err != nil {
		return time.Time{}, fmt.Errorf("crypto_inventory.quantum_horizon %q must be a date like 2035-01-01", c.QuantumHorizon)
	}
	return t, nil
}

// validateCryptoInventorySection checks the crypto-inventory settings (Validate step).
func validateCryptoInventorySection(c *Config) error {
	if _, err := c.CryptoInventory.ParsedHorizon(); err != nil {
		return err
	}
	if my := c.CryptoInventory.MigrationYears; my != nil && *my < 0 {
		return fmt.Errorf("crypto_inventory.migration_years must be >= 0, got %d", *my)
	}
	if c.CryptoInventory.UnboundedLifetimeYears < 0 {
		return fmt.Errorf("crypto_inventory.unbounded_lifetime_years must be >= 0, got %d", c.CryptoInventory.UnboundedLifetimeYears)
	}
	return nil
}
