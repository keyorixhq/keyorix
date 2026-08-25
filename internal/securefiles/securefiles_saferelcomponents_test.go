package securefiles

import "testing"

// TestSafeRelComponents exercises safeRelComponents directly rather than only
// through an outcome like Save/SecureWriteFileSync rejecting an escaping path.
//
// Phase 1 of this coverage audit mutated safeRelComponents' ".."-rejection
// alone (dropping it from the component-rejection loop) and found
// TestSaveRejectsPathEscapingBaseDir stayed green: resolveInside/
// isPathInsideBase — a second, independent lexical guard checked earlier in
// SecureWriteFileSync — still caught the same "../escape.yaml" input. That is
// correct defense-in-depth, not a weak test: the invariant Save promises
// ("must not write outside its base directory") held throughout. But it also
// means a regression in THIS function alone, with the other layer intact,
// would currently be invisible to any test in this package. This file closes
// that gap by asserting on safeRelComponents' own return value, independent
// of which (if any) other layer would also catch the same input.
func TestSafeRelComponents(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		want    []string // checked only when wantErr is false
	}{
		{name: "absolute path is rejected", in: "/etc/passwd", wantErr: true},
		{name: "empty path is rejected", in: "", wantErr: true},
		{name: "dot (cleans to empty) is rejected", in: ".", wantErr: true},
		{name: "leading .. escapes and is rejected", in: "../escape.yaml", wantErr: true},
		{name: "deep .. that still escapes is rejected", in: "a/../../escape.yaml", wantErr: true},
		{name: "a trailing .. that Clean absorbs before it can escape is allowed", in: "a/b/..", wantErr: false, want: []string{"a"}},
		{name: "a .. that Clean absorbs before it can escape is allowed", in: "a/../b", wantErr: false, want: []string{"b"}},
		{name: "plain relative path is allowed", in: "a/b/c", wantErr: false, want: []string{"a", "b", "c"}},
		{name: "single-component relative path is allowed", in: "keyorix.yaml", wantErr: false, want: []string{"keyorix.yaml"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeRelComponents(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("safeRelComponents(%q): expected an error, got parts %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeRelComponents(%q): unexpected error: %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("safeRelComponents(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("safeRelComponents(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
