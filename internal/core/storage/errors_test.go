package storage_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// TestIsXNotFound_SentinelAndWrapped proves each IsXNotFound helper still
// recognizes its own local sentinel error, recognizes it wrapped (errors.Is
// through fmt.Errorf's %w), and returns false for nil, a different sentinel,
// and a generic error. Originally these also proved a RemoteStorage
// *remote.HTTPError branch (errors.As); that branch was deleted along with
// RemoteStorage itself in ADR-108 Phase 6 step 14b-2.
func TestIsXNotFound_SentinelAndWrapped(t *testing.T) {
	cases := []struct {
		name     string
		fn       func(error) bool
		sentinel error
	}{
		{"IsUserNotFound", storage.IsUserNotFound, storage.ErrUserNotFound},
		{"IsSessionNotFound", storage.IsSessionNotFound, storage.ErrSessionNotFound},
		{"IsSecretNotFound", storage.IsSecretNotFound, storage.ErrSecretNotFound},
		{"IsSecretVersionNotFound", storage.IsSecretVersionNotFound, storage.ErrSecretVersionNotFound},
	}
	otherErr := errors.New("some other error")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fn(nil) {
				t.Errorf("%s(nil) = true, want false", c.name)
			}
			if !c.fn(c.sentinel) {
				t.Errorf("%s(sentinel) = false, want true", c.name)
			}
			if !c.fn(fmt.Errorf("wrapped: %w", c.sentinel)) {
				t.Errorf("%s(wrapped sentinel) = false, want true", c.name)
			}
			if c.fn(storage.ErrRoleNotAssigned) && c.sentinel != storage.ErrRoleNotAssigned {
				t.Errorf("%s(a different sentinel) = true, want false", c.name)
			}
			if c.fn(otherErr) {
				t.Errorf("%s(generic error) = true, want false", c.name)
			}
		})
	}
}

func TestSentinelErrors_distinct(t *testing.T) {
	sentinels := []error{
		storage.ErrUserNotFound,
		storage.ErrRoleNotAssigned,
		storage.ErrWouldStrandLastAdmin,
		storage.ErrBreakGlassNotActive,
		storage.ErrDuplicateActiveMembership,
		storage.ErrDuplicateEmail,
		storage.ErrDuplicateProjectName,
		storage.ErrDuplicateSecretVersion,
		storage.ErrUnsupportedByBackend,
		storage.ErrBreakGlassAlreadyActive,
		storage.ErrDuplicateDynamicSecretConfig,
		storage.ErrDuplicateReminderNotification,
		storage.ErrDuplicateSecretDependency,
		storage.ErrSecretDependencyCycle,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %d (%v) matches sentinel %d (%v) — they must be distinct", i, a, j, b)
			}
		}
	}
}
