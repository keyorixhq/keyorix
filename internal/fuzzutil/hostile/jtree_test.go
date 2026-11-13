package hostile

import "testing"

// TestHasDuplicateKeys pins the duplicate-member definition the targets rely
// on: encoding/json matches member names case-insensitively, so a body whose
// names differ only by case has no single correct reading either.
func TestHasDuplicateKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"exact duplicate", `{"a":1,"a":2}`, true},
		{"case-variant duplicate", `{"DATA":1,"data":{}}`, true},
		{"nested case-variant duplicate", `{"x":{"Value":1,"value":2}}`, true},
		{"distinct names", `{"a":1,"b":2}`, false},
		{"same name in sibling objects", `{"a":{"k":1},"b":{"k":2}}`, false},
		{"unparseable", `{"a":`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasDuplicateKeys([]byte(tc.body)); got != tc.want {
				t.Fatalf("HasDuplicateKeys(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
