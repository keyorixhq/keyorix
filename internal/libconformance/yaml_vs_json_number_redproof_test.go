package libconformance

import "testing"

// TestYAMLNumberPrecisionOnlyFloat64Rounding: number-precision is allowlisted only when the
// JSON value is exactly the float64 rounding of the YAML value. Any other numeric
// difference is number-differs and stays off the allowlist.
func TestYAMLNumberPrecisionOnlyFloat64Rounding(t *testing.T) {
	const exact = int64(12345678901234567) // not float64-representable
	rounded := float64(exact)
	if int64(rounded) == exact {
		t.Fatal("test premise: 12345678901234567 must not be float64-exact")
	}
	if m := treeCompare(rounded, exact); m == nil || m.key != "number-precision" {
		t.Fatalf("float64 rounding must be number-precision, got %v", m)
	}
	if m := treeCompare(float64(7), int64(8)); m == nil || m.key != "number-differs" || yamlDiffAllow().allows(m.key) {
		t.Fatalf("a non-rounding numeric difference must be a non-allowlisted number-differs, got %v", m)
	}
}
