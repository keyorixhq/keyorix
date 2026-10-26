package cryptoinventory

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Policy configures the quantum-risk assessment.
//
// The model is Mosca's inequality: a key is at risk when the time it must stay
// secure (X) plus the time needed to migrate off it (Y) exceeds the time until a
// cryptographically relevant quantum computer exists (Z, the Horizon).
type Policy struct {
	// Horizon is the date by which a cryptographically relevant quantum computer
	// is assumed to exist. Default 2035-01-01, the year NIST IR 8547 (draft)
	// disallows quantum-vulnerable public-key algorithms.
	Horizon time.Time `json:"horizon"`
	// MigrationYears is Y: how long moving off a vulnerable algorithm takes. Default 3.
	MigrationYears int `json:"migration_years"`
	// UnboundedLifetimeYears is X for an asset with no expiry. Default 10.
	UnboundedLifetimeYears int `json:"unbounded_lifetime_years"`
}

// DefaultPolicy returns the documented defaults.
func DefaultPolicy() Policy {
	return Policy{
		Horizon:                time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		MigrationYears:         3,
		UnboundedLifetimeYears: 10,
	}
}

// Validate reports a malformed policy.
func (p Policy) Validate() error {
	switch {
	case p.Horizon.IsZero():
		return fmt.Errorf("quantum horizon is not set")
	case p.MigrationYears < 0:
		return fmt.Errorf("migration_years must be >= 0, got %d", p.MigrationYears)
	case p.UnboundedLifetimeYears < 1:
		return fmt.Errorf("unbounded_lifetime_years must be >= 1, got %d", p.UnboundedLifetimeYears)
	}
	return nil
}

const (
	hoursPerYear = 24 * 365.25
	// levelHigh / levelMedium are the score cut-offs for the risk level.
	levelHigh   = 70
	levelMedium = 40
)

// kind is how a quantum computer affects an algorithm.
type kind int

const (
	kindPQ kind = iota // post-quantum or hybrid
	kindStrongSymmetric
	kindReducedSymmetric
	kindClassicalAsymmetric
	kindUnknown
)

// Assess scores one asset against the policy at time now.
//
//   - Classical public-key algorithms (RSA, ECDSA, Ed25519, ECDH) are broken by
//     Shor's algorithm: base score 60 (70 for RSA below 2048 bits).
//   - Symmetric/hash primitives only lose half their strength to Grover: 256-bit
//     and above score 5, 192-bit 15, 128-bit 30.
//   - Post-quantum and hybrid algorithms score 5.
//   - An unclassifiable algorithm fails closed to 40 (medium).
//
// Below the strong-symmetric floor the score rises by up to (100 - base) times a
// weight (1.0 classical, 0.5 unknown, 0.3 reduced symmetric) when the asset's
// remaining lifetime plus migration time runs past the horizon.
func (p Policy) Assess(a Asset, now time.Time) Risk {
	k, base, vulnerable, why := classify(a)
	reasons := []string{why}
	score := float64(base)

	weight := map[kind]float64{kindClassicalAsymmetric: 1, kindUnknown: 0.5, kindReducedSymmetric: 0.3}[k]
	if weight > 0 {
		end, ended, lifeNote := p.lifetimeEnd(a, now)
		reasons = append(reasons, lifeNote)
		if !ended {
			toHorizon := math.Max(0, p.Horizon.Sub(now).Hours()/hoursPerYear)
			exposure := end.Sub(now).Hours()/hoursPerYear + float64(p.MigrationYears)
			if exposure > toHorizon {
				frac := 1.0
				if toHorizon > 0 {
					frac = math.Min(1, (exposure-toHorizon)/toHorizon)
				}
				score += float64(100-base) * weight * frac
				reasons = append(reasons, fmt.Sprintf(
					"in use for %.1fy plus %dy migration, past the %s quantum horizon",
					exposure-float64(p.MigrationYears), p.MigrationYears, p.Horizon.Format("2006-01-02")))
			} else {
				reasons = append(reasons, fmt.Sprintf(
					"retired (%.1fy + %dy migration) before the %s quantum horizon",
					exposure-float64(p.MigrationYears), p.MigrationYears, p.Horizon.Format("2006-01-02")))
			}
		}
	}

	s := int(math.Round(math.Min(100, math.Max(0, score))))
	level := LevelLow
	switch {
	case s >= levelHigh:
		level = LevelHigh
	case s >= levelMedium:
		level = LevelMedium
	}
	return Risk{Score: s, Level: level, QuantumVulnerable: vulnerable, Reasons: reasons}
}

// lifetimeEnd is when the asset stops being used. ended is true for an asset that
// is already expired.
func (p Policy) lifetimeEnd(a Asset, now time.Time) (end time.Time, ended bool, note string) {
	switch {
	case a.ExpiresAt != nil:
		if !a.ExpiresAt.After(now) {
			return now, true, "already expired"
		}
		return *a.ExpiresAt, false, "expires " + a.ExpiresAt.UTC().Format("2006-01-02")
	case a.AssumedLifetimeDays > 0:
		return now.AddDate(0, 0, a.AssumedLifetimeDays), false,
			fmt.Sprintf("expiry unknown: assumed %dd rotation", a.AssumedLifetimeDays)
	default:
		return now.AddDate(p.UnboundedLifetimeYears, 0, 0), false,
			fmt.Sprintf("no expiry: assumed %dy lifetime", p.UnboundedLifetimeYears)
	}
}

func classify(a Asset) (k kind, base int, vulnerable bool, why string) {
	name := a.Algorithm
	if name == "" {
		name = "unspecified algorithm"
	}
	switch {
	case a.PostQuantum:
		return kindPQ, 5, false, fmt.Sprintf("%s is post-quantum or hybrid", name)
	case a.Asymmetric:
		base = 60
		if strings.HasPrefix(strings.ToUpper(a.Algorithm), "RSA") && a.KeySizeBits > 0 && a.KeySizeBits < 2048 {
			base = 70
		}
		return kindClassicalAsymmetric, base, true,
			fmt.Sprintf("%s is classical public-key cryptography, broken by Shor's algorithm on a quantum computer", name)
	case a.KeySizeBits >= 256:
		return kindStrongSymmetric, 5, false, fmt.Sprintf("%s (%d-bit) keeps >=128-bit strength against Grover's algorithm", name, a.KeySizeBits)
	case a.KeySizeBits >= 192:
		return kindReducedSymmetric, 15, false, fmt.Sprintf("%s (%d-bit) drops to ~%d-bit strength against Grover's algorithm", name, a.KeySizeBits, a.KeySizeBits/2)
	case a.KeySizeBits >= 128:
		return kindReducedSymmetric, 30, false, fmt.Sprintf("%s (%d-bit) drops to ~64-bit strength against Grover's algorithm", name, a.KeySizeBits)
	default:
		return kindUnknown, 40, false, fmt.Sprintf("%s cannot be classified: scored medium (fail closed)", name)
	}
}
