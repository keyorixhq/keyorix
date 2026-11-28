//go:build !race

package resguard

// coldStartSlack: two warm no-op Guard calls differ by ~150 bytes natively, and a
// missing Prime costs the first call >= ~1.4 KiB (stall monitor start plus a
// runner and timer), so this also fails when Prime is not called.
const coldStartSlack = 768
