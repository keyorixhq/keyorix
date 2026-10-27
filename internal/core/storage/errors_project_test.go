package storage_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// TestIsProjectNotFound_SentinelOnly: the helpers match the sentinel (bare or
// wrapped) and nothing else — in particular not an unrelated error whose text
// says "project not found" (ERRLOSS-MFA-1: the MFA gate used to match text).
func TestIsProjectNotFound_SentinelOnly(t *testing.T) {
	cases := []struct {
		name      string
		fn        func(error) bool
		sentinel  error
		lookalike error
	}{
		{"IsProjectNotFound", storage.IsProjectNotFound, storage.ErrProjectNotFound, errors.New("project not found")},
		{"IsEnvironmentNotFound", storage.IsEnvironmentNotFound, storage.ErrEnvironmentNotFound, errors.New("environment not found")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fn(nil) {
				t.Errorf("%s(nil) = true, want false", c.name)
			}
			if !c.fn(c.sentinel) || !c.fn(fmt.Errorf("wrapped: %w", c.sentinel)) {
				t.Errorf("%s(sentinel / wrapped sentinel) = false, want true", c.name)
			}
			if c.fn(c.lookalike) {
				t.Errorf("%s(same text, not the sentinel) = true, want false", c.name)
			}
			if c.fn(storage.ErrUserNotFound) {
				t.Errorf("%s(a different sentinel) = true, want false", c.name)
			}
		})
	}
	if storage.ErrProjectNotFound.Error() != "project not found" || storage.ErrEnvironmentNotFound.Error() != "environment not found" {
		t.Error("sentinel text changed: existing text matchers depend on it until ERRLOSS-SENTINELS-1")
	}
}
