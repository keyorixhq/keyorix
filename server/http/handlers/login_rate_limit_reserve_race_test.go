//go:build race

package handlers

// raceDetectorActive mirrors internal/fuzzutil's guard_race.go/guard_norace.go
// pattern: -race instruments every memory access, slowing execution enough to
// change the relative timing between the DB-backed reserve and the bcrypt
// credential check that TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks
// depends on — confirmed empirically to flake under -race even against the
// fixed code (aggregate too_many_requests dropped well below the threshold
// tuned for an uninstrumented build).
const raceDetectorActive = true
