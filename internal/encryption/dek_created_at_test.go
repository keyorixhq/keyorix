package encryption

import (
	"testing"
	"time"
)

func TestDEKCreatedAt_OnlyForTheEpochsDEK(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 8, time.UTC)
	rec := "abc123 " + at.Format(time.RFC3339Nano)
	if got, ok := DEKCreatedAt("abc123", rec); !ok || !got.Equal(at) {
		t.Fatalf("matching epoch: got %v, %v; want %v, true", got, ok, at)
	}
	for name, c := range map[string]struct{ epoch, rec string }{
		"another DEK":       {"def456", rec},
		"rotation fence":    {dekEpochRotatingPrefix + "abc123", rec},
		"fence as recorded": {dekEpochRotatingPrefix + "abc123", dekEpochRotatingPrefix + "abc123 " + at.Format(time.RFC3339Nano)},
		"no time":           {"abc123", "abc123"},
		"bad time":          {"abc123", "abc123 yesterday"},
		"empty":             {"", ""},
	} {
		if _, ok := DEKCreatedAt(c.epoch, c.rec); ok {
			t.Errorf("%s: DEKCreatedAt(%q, %q) reported a recorded time", name, c.epoch, c.rec)
		}
	}
}
