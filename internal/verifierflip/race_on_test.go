//go:build race

package verifierflip_test

// raceEnabled: the race detector distorts reject timing and multiplies its
// cost, so TestVerifierBitFlip leaves the timing rules to non-race runs.
const raceEnabled = true
