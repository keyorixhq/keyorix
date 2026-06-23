package share

import (
	"testing"
	"time"
)

func TestResolveShareExpiry(t *testing.T) {
	t.Run("both empty is a permanent share", func(t *testing.T) {
		got, err := resolveShareExpiry("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("got %v, want nil (permanent)", got)
		}
	})

	t.Run("absolute RFC3339 expiry", func(t *testing.T) {
		got, err := resolveShareExpiry("2026-07-01T15:00:00Z", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, 7, 1, 15, 0, 0, 0, time.UTC)
		if got == nil || !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("relative ttl resolves from now", func(t *testing.T) {
		before := time.Now()
		got, err := resolveShareExpiry("", "2h")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("got nil, want a time ~2h out")
		}
		// Allow a wide window so the test never clock-bombs.
		delta := got.Sub(before)
		if delta < 119*time.Minute || delta > 121*time.Minute {
			t.Errorf("ttl resolved to %v from now, want ~2h", delta)
		}
	})

	t.Run("both set is rejected", func(t *testing.T) {
		if _, err := resolveShareExpiry("2026-07-01T15:00:00Z", "2h"); err == nil {
			t.Error("expected an error when both --expires and --ttl are set")
		}
	})

	t.Run("malformed expires is rejected", func(t *testing.T) {
		if _, err := resolveShareExpiry("not-a-timestamp", ""); err == nil {
			t.Error("expected an error for a non-RFC3339 --expires")
		}
	})

	t.Run("malformed ttl is rejected", func(t *testing.T) {
		if _, err := resolveShareExpiry("", "soon"); err == nil {
			t.Error("expected an error for a non-duration --ttl")
		}
	})

	t.Run("non-positive ttl is rejected", func(t *testing.T) {
		if _, err := resolveShareExpiry("", "0s"); err == nil {
			t.Error("expected an error for a zero --ttl")
		}
		if _, err := resolveShareExpiry("", "-1h"); err == nil {
			t.Error("expected an error for a negative --ttl")
		}
	})
}

func TestFormatShareExpiry(t *testing.T) {
	if got := formatShareExpiry(nil); got != "never" {
		t.Errorf("nil expiry = %q, want %q", got, "never")
	}
	at := time.Date(2026, 7, 1, 15, 4, 5, 0, time.UTC)
	if got := formatShareExpiry(&at); got != "2026-07-01 15:04:05" {
		t.Errorf("formatted expiry = %q, want %q", got, "2026-07-01 15:04:05")
	}
}

func TestCreateAndUpdateExpiryFlagsExist(t *testing.T) {
	for _, name := range []string{"expires", "ttl"} {
		if createCmd.Flags().Lookup(name) == nil {
			t.Errorf("create command missing --%s flag", name)
		}
	}
	for _, name := range []string{"expires", "ttl", "clear-expiry"} {
		if updateCmd.Flags().Lookup(name) == nil {
			t.Errorf("update command missing --%s flag", name)
		}
	}
}
