package a

import "testing"

// FuzzThing checks INV-A-01: the parser never panics.
func FuzzThing(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {})
}

// helperOracle is shared by the fuzz target. INV-A-07 is only named here.
func helperOracle() {}

func TestWriteChecksAuthz(t *testing.T) {
	// INV-A-02
}

func TestWipeKeys(t *testing.T) {
	// INV-A-06
}

// A typo for an undefined rule: INV-A-91 (closest defined ID is INV-A-01).
func TestTypo(t *testing.T) {}
