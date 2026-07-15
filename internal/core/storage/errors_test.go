package storage_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

func TestIsUserNotFound_nil(t *testing.T) {
	if storage.IsUserNotFound(nil) {
		t.Error("IsUserNotFound(nil) = true, want false")
	}
}

func TestIsUserNotFound_sentinel(t *testing.T) {
	if !storage.IsUserNotFound(storage.ErrUserNotFound) {
		t.Error("IsUserNotFound(ErrUserNotFound) = false, want true")
	}
	// wrapped form
	if !storage.IsUserNotFound(fmt.Errorf("wrapped: %w", storage.ErrUserNotFound)) {
		t.Error("IsUserNotFound(wrapped ErrUserNotFound) = false, want true")
	}
}

func TestIsUserNotFound_otherSentinel(t *testing.T) {
	if storage.IsUserNotFound(storage.ErrRoleNotAssigned) {
		t.Error("IsUserNotFound(ErrRoleNotAssigned) = true, want false")
	}
	if storage.IsUserNotFound(errors.New("some other error")) {
		t.Error("IsUserNotFound(generic error) = true, want false")
	}
}

func TestIsUserNotFound_httpNotFound(t *testing.T) {
	err := &remote.HTTPError{StatusCode: http.StatusNotFound}
	if !storage.IsUserNotFound(err) {
		t.Error("IsUserNotFound(HTTPError 404) = false, want true")
	}
	// wrapped
	if !storage.IsUserNotFound(fmt.Errorf("wrap: %w", err)) {
		t.Error("IsUserNotFound(wrapped HTTPError 404) = false, want true")
	}
}

func TestIsUserNotFound_httpOtherStatus(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError} {
		err := &remote.HTTPError{StatusCode: code}
		if storage.IsUserNotFound(err) {
			t.Errorf("IsUserNotFound(HTTPError %d) = true, want false", code)
		}
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
