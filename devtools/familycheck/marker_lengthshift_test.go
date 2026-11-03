package main

import (
	"strings"
	"testing"
)

// TestDismissalReason_LowercaseLengthShift pins that the marker is located on
// the ORIGINAL body. strings.ToLower changes the byte length of some runes
// (U+0130 'İ' is 2 bytes and lowercases to 1; U+023A 'Ⱥ' is 2 bytes and
// lowercases to 3: both directions occur), so an offset found in the lowered
// copy must never be used to slice the original.
func TestDismissalReason_LowercaseLengthShift(t *testing.T) {
	const marker = "family-check: intentional"
	pad := strings.Repeat("İ", 40) // shifts a lowered-copy offset by -40 bytes

	tests := []struct {
		name       string
		body       string
		wantOK     bool
		wantReason string
	}{
		{
			name:       "no shifting rune (baseline)",
			body:       "intro\n" + marker + " Alpha\nnext line\n",
			wantOK:     true,
			wantReason: "Alpha",
		},
		{
			name:       "shifting runes before the marker line that names the family",
			body:       pad + "\n" + marker + " Alpha\nnext line\n",
			wantOK:     true,
			wantReason: "Alpha",
		},
		{
			name:       "shifting runes, marker in upper case",
			body:       pad + "\nFAMILY-CHECK: INTENTIONAL Alpha\nnext line\n",
			wantOK:     true,
			wantReason: "Alpha",
		},
		{
			name:   "shifting runes, marker line names another family, later line names ours",
			body:   pad + "\n" + marker + " Beta\nAlpha is mentioned here\n",
			wantOK: false,
		},
		{
			// Fail-open, shrinking: the lowered copy is shorter, so an offset
			// from it lands before the marker and pulls "Alpha" into the slice.
			name:   "fail-open shrink: marker names another family, Alpha precedes it on the line",
			body:   strings.Repeat("İ", 10) + " Alpha " + marker + " Beta\n",
			wantOK: false,
		},
		{
			// Fail-open, growing: the lowered copy is longer (31 = byte length of
			// the marker line), so an offset from it starts on the next line.
			name:   "fail-open grow: marker names another family, Alpha on the next line",
			body:   strings.Repeat("Ⱥ", 31) + "\n" + marker + " Beta\nAlpha is mentioned here\n",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := dismissalReason(tc.body, marker, "FAM-1", "Alpha")
			if ok != tc.wantOK {
				t.Fatalf("dismissalReason ok = %v, want %v (reason %q)", ok, tc.wantOK, reason)
			}
			if tc.wantOK && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}
