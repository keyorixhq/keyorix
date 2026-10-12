package admin

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/startup"
)

// #2940: `admin validate` ended "All validations passed!" and then told a healthy
// install to re-run `init --overwrite-existing` and `migrate`.
func TestValidateRecommendations_HealthyInstallGetsNone(t *testing.T) {
	if recs := validateRecommendations(&startup.ValidationResult{}); len(recs) != 0 {
		t.Fatalf("healthy install got recommendations: %v", recs)
	}
	// The auto-fix notice is informational; it must not trigger the re-init advice.
	r := &startup.ValidationResult{Warnings: []string{"Automatic file-permission fixing is on (...)"}}
	if recs := validateRecommendations(r); len(recs) != 0 {
		t.Fatalf("auto-fix notice produced recommendations: %v", recs)
	}
}

func TestValidateRecommendations_NeverSuggestsReinit(t *testing.T) {
	r := &startup.ValidationResult{
		Errors:   []string{"boom"},
		Warnings: []string{"File permission checks are disabled", "Encryption is disabled"},
	}
	recs := validateRecommendations(r)
	if len(recs) < 3 {
		t.Fatalf("findings should produce recommendations, got %v", recs)
	}
	for _, rec := range recs {
		if strings.Contains(rec, "overwrite-existing") || strings.Contains(rec, "migrate") {
			t.Fatalf("recommendation %q is not tied to a finding", rec)
		}
	}
}
