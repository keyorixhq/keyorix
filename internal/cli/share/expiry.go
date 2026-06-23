package share

import (
	"fmt"
	"time"
)

// resolveShareExpiry turns the --expires (absolute RFC3339) and --ttl (relative Go
// duration) flags into an absolute expiry instant for a share.
//
//   - The two flags are mutually exclusive.
//   - Both empty → (nil, nil): a permanent share (or, on update, "leave expiry as-is").
//   - --ttl is resolved against the current wall clock.
//
// A past expiry is left for the core layer to reject (it owns the authoritative
// "must be in the future" check against its own clock); this helper only parses and
// enforces that --ttl is positive, so the two flags can't silently disagree.
func resolveShareExpiry(expires, ttl string) (*time.Time, error) {
	if expires != "" && ttl != "" {
		return nil, fmt.Errorf("use only one of --expires or --ttl")
	}
	switch {
	case expires != "":
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return nil, fmt.Errorf("invalid --expires (want RFC3339, e.g. 2026-07-01T15:00:00Z): %w", err)
		}
		return &t, nil
	case ttl != "":
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid --ttl (want a Go duration, e.g. 24h, 30m): %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("--ttl must be a positive duration")
		}
		t := time.Now().Add(d)
		return &t, nil
	default:
		return nil, nil
	}
}

// formatShareExpiry renders a share's expiry for CLI output: a local timestamp, or
// "never" for a permanent share.
func formatShareExpiry(expiresAt *time.Time) string {
	if expiresAt == nil {
		return "never"
	}
	return expiresAt.Format("2006-01-02 15:04:05")
}
