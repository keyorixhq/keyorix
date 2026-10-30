package main

import "testing"

// TestDismissalReason_NonASCIIBeforeMarker pins the index mismatch: the marker
// was located in strings.ToLower(body) but the line was sliced from the
// original body. "İ" (U+0130) is 2 bytes and strings.ToLower makes it "i"
// (1 byte), so every such letter before the marker moved the slice start one
// byte earlier, back into the text before the marker.
func TestDismissalReason_NonASCIIBeforeMarker(t *testing.T) {
	const marker = "family-check: intentional"
	cases := []struct {
		name       string
		body       string
		wantOK     bool
		wantReason string
	}{
		{"ASCII only", "intro\n" + marker + " — Alpha: only A1 has the bug\n", true, "Alpha: only A1 has the bug"},
		{"non-ASCII before marker", "İİİİ title\n" + marker + " — Alpha: only A1 has the bug\n", true, "Alpha: only A1 has the bug"},
		{"non-ASCII before marker, other family", "İİİİ title\n" + marker + " — Beta: x\n", false, ""},
		{"marker in another case keeps no marker text in the reason", "İİ\nFamily-Check: Intentional - Alpha: ok\n", true, "Alpha: ok"},
	}
	for _, tc := range cases {
		ok, reason := dismissalReason(tc.body, marker, "alpha", "Alpha")
		if ok != tc.wantOK || reason != tc.wantReason {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", tc.name, ok, reason, tc.wantOK, tc.wantReason)
		}
		if got := hasMarker(tc.body, marker, "alpha", "Alpha"); got != tc.wantOK {
			t.Errorf("%s: hasMarker = %v, want %v", tc.name, got, tc.wantOK)
		}
	}
}

// TestDismissalReason_OnlyFirstMarkerLineIsRead pins the documented
// first-marker-line behaviour (README.md, "Marker lines"): a later line that
// names the family does not rescue an earlier line that names another.
func TestDismissalReason_OnlyFirstMarkerLineIsRead(t *testing.T) {
	const marker = "family-check: intentional"
	body := marker + " — Beta: x\n" + marker + " — Alpha: y\n"
	if ok, _ := dismissalReason(body, marker, "alpha", "Alpha"); ok {
		t.Error("second marker line must not be read")
	}
	if ok, _ := dismissalReason(body, marker, "beta", "Beta"); !ok {
		t.Error("first marker line names Beta and must dismiss it")
	}
}
