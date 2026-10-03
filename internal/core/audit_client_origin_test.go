package core

import (
	"context"
	"strings"
	"testing"
)

// TestDetachedAuditContext_PreservesClientOrigin: an origin tagged before detaching must
// survive DetachedAuditContext, like the impersonation/actor tags do (#2545). The HTTP
// handlers tag after detaching, so this path is only exercised here.
func TestDetachedAuditContext_PreservesClientOrigin(t *testing.T) {
	parent := WithClientOrigin(context.Background(), "keyorix-migrate/dev source=vault:secret/a")
	got := withClientOriginNote(DetachedAuditContext(parent), "User u created secret s")
	if want := "User u created secret s [client-asserted origin: keyorix-migrate/dev source=vault:secret/a]"; got != want {
		t.Errorf("description = %q, want %q", got, want)
	}
}

func TestWithClientOrigin_EmptyAndCapped(t *testing.T) {
	if _, ok := clientOriginFromContext(WithClientOrigin(context.Background(), " \x00\n ")); ok {
		t.Error("a whitespace/control-only origin was recorded; want none")
	}
	if got := withClientOriginNote(context.Background(), "d"); got != "d" {
		t.Errorf("no origin: description = %q, want unchanged", got)
	}
	origin, _ := clientOriginFromContext(WithClientOrigin(context.Background(), strings.Repeat("é", 1000)))
	if n := len([]rune(origin)); n != maxClientOriginRunes+1 {
		t.Errorf("capped origin has %d runes, want %d (+ ellipsis)", n, maxClientOriginRunes+1)
	}
}
