//go:build race

package resguard

// coldStartSlack under the race detector: its runtime makes two identical no-op
// Guard calls differ by up to ~1.6 KiB, as much as a missing Prime costs, so a
// -race run only proves the ~10 KiB metric-table part, not the Prime part.
const coldStartSlack = 2048
