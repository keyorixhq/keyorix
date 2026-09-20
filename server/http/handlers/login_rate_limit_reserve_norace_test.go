//go:build !race

package handlers

// raceDetectorActive — see login_rate_limit_reserve_race_test.go.
const raceDetectorActive = false
