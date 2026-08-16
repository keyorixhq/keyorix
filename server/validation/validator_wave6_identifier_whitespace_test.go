// validator_wave6_identifier_whitespace_test.go — Wave 6 batch 4: regression
// coverage for identifierRegex/validateIdentifier's whitespace-spoofing gap
// (findings-server/validation.json#2). The [a-zA-Z0-9 _-] charset alone lets a
// name be all whitespace, or have leading/trailing/repeated internal
// whitespace, defeating the anti-spoofing intent the `identifier` rule is
// documented to provide: e.g. "   ", "  my project  ", and "my  project" all
// satisfy the raw charset check yet are visually blank or confusable with a
// legitimate name.
package validation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidate_Wave6_IdentifierAllWhitespaceRejected verifies that a name
// composed entirely of whitespace (renders blank in any UI) is rejected.
func TestValidate_Wave6_IdentifierAllWhitespaceRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: "   "}), "all-whitespace name must be rejected")
}

// TestValidate_Wave6_IdentifierLeadingTrailingWhitespaceRejected verifies that
// leading/trailing whitespace around an otherwise-valid name is rejected.
func TestValidate_Wave6_IdentifierLeadingTrailingWhitespaceRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: " myproject "}), "leading/trailing whitespace must be rejected")
	require.Error(t, v.Validate(payload{Name: "myproject "}), "trailing whitespace alone must be rejected")
	require.Error(t, v.Validate(payload{Name: " myproject"}), "leading whitespace alone must be rejected")
}

// TestValidate_Wave6_IdentifierRepeatedInternalWhitespaceRejected verifies
// that repeated internal whitespace (a spoofing vector distinct from — but
// visually similar to — a single-space name) is rejected.
func TestValidate_Wave6_IdentifierRepeatedInternalWhitespaceRejected(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: "my  project"}), "double internal space must be rejected")
	require.Error(t, v.Validate(payload{Name: "Support  Team"}), "double internal space must be rejected")
}

// TestValidate_Wave6_IdentifierLegitimateNamesStillPass verifies that normal
// names — including one with a single internal space — are unaffected by
// the new whitespace-structure check.
func TestValidate_Wave6_IdentifierLegitimateNamesStillPass(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "myproject"}))
	require.NoError(t, v.Validate(payload{Name: "My Project"}), "a single internal space must still be accepted")
	require.NoError(t, v.Validate(payload{Name: "prod-db_01"}))
}

// TestValidate_Wave6_IdentifierEmptyStringStillPasses verifies the new
// whitespace check does not change the pre-existing, documented behavior
// that an empty string passes `identifier` (enforce non-empty via `required`).
func TestValidate_Wave6_IdentifierEmptyStringStillPasses(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: ""}))
}
