package toy

import "testing"

// FuzzWeak is the deliberately weak oracle: it only asserts that Max returns
// one of its two inputs. That property holds for min as well as max, so a
// mutant that turns Max into min SURVIVES this oracle. This is the oracle hole
// oraclehealth is designed to surface.
func FuzzWeak(f *testing.F) {
	f.Add(1, 2)
	f.Add(-3, 7)
	f.Fuzz(func(t *testing.T, a, b int) {
		got := Max(a, b)
		if got != a && got != b {
			t.Fatalf("Max(%d,%d)=%d is neither input", a, b, got)
		}
	})
}

// FuzzStrong is the strong oracle: it recomputes the maximum with an
// independent reference expression (untouched by the mutator, which only
// rewrites non-test .go files) and demands exact agreement. The min mutant
// fails this on the very first seed, so it is KILLED.
func FuzzStrong(f *testing.F) {
	f.Add(1, 2)
	f.Add(-3, 7)
	f.Fuzz(func(t *testing.T, a, b int) {
		got := Max(a, b)
		want := a
		if b > want {
			want = b
		}
		if got != want {
			t.Fatalf("Max(%d,%d)=%d want %d", a, b, got, want)
		}
	})
}
