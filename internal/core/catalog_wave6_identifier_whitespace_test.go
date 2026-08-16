// catalog_wave6_identifier_whitespace_test.go — Wave 6 batch 4: regression
// coverage for catalog.go's validateIdentifier/identifierRegex whitespace-
// spoofing gap (findings-server/validation.json#2), mirroring the fix and
// tests in server/validation/validator.go. The [a-zA-Z0-9 _-] charset alone
// let a project name be all whitespace, or have leading/trailing/repeated
// internal whitespace, defeating the anti-homograph/anti-spoofing intent
// documented on identifierRegex (G38): e.g. "   ", "  my project  ", and
// "my  project" all satisfied the raw charset check yet are visually blank
// or confusable with a legitimate name.
package core

import "testing"

func TestValidateIdentifier_Wave6_AllWhitespaceRejected(t *testing.T) {
	if err := validateIdentifier("   "); err == nil {
		t.Error("all-whitespace name must be rejected")
	}
}

func TestValidateIdentifier_Wave6_LeadingTrailingWhitespaceRejected(t *testing.T) {
	if err := validateIdentifier(" myproject "); err == nil {
		t.Error("leading/trailing whitespace must be rejected")
	}
	if err := validateIdentifier("myproject "); err == nil {
		t.Error("trailing whitespace alone must be rejected")
	}
	if err := validateIdentifier(" myproject"); err == nil {
		t.Error("leading whitespace alone must be rejected")
	}
}

func TestValidateIdentifier_Wave6_RepeatedInternalWhitespaceRejected(t *testing.T) {
	if err := validateIdentifier("my  project"); err == nil {
		t.Error("double internal space must be rejected")
	}
	if err := validateIdentifier("Support  Team"); err == nil {
		t.Error("double internal space must be rejected")
	}
}

func TestValidateIdentifier_Wave6_LegitimateNamesStillPass(t *testing.T) {
	if err := validateIdentifier("myproject"); err != nil {
		t.Errorf("expected no error for plain name, got %v", err)
	}
	if err := validateIdentifier("My Project"); err != nil {
		t.Errorf("expected a single internal space to be accepted, got %v", err)
	}
	if err := validateIdentifier("prod-db_01"); err != nil {
		t.Errorf("expected no error for hyphen/underscore name, got %v", err)
	}
}

// TestValidateProjectName_Wave6_WhitespaceOnlyRejected exercises the same gap
// through the public validateProjectName entry point (used by CreateProject /
// CreateProjectWithEnvs), confirming the fix closes the gap end-to-end and
// not just at the internal helper.
func TestValidateProjectName_Wave6_WhitespaceOnlyRejected(t *testing.T) {
	if err := validateProjectName("   "); err == nil {
		t.Error("all-whitespace project name must be rejected")
	}
	if err := validateProjectName("My Project"); err != nil {
		t.Errorf("expected a legitimate project name to be accepted, got %v", err)
	}
}
