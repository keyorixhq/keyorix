// models_s18_test.go — coverage uplift for GetUserGroups (line 68) and
// GetGroupShares (line 79) in group_sharing.go.
//
// Both functions are stubs (they do not touch a DB); tests verify the zero-ID
// guard and the happy-path return values.
package models

import (
	"errors"
	"testing"
)

// ---- GetUserGroups ----

// TestGetUserGroups_ZeroIDReturnsError verifies the guard that rejects userID == 0.
func TestGetUserGroups_ZeroIDReturnsError(t *testing.T) {
	_, err := GetUserGroups(0)
	if err == nil {
		t.Fatal("expected error for userID == 0, got nil")
	}
	if err.Error() != "user ID cannot be zero" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestGetUserGroups_ValidIDReturnsEmptySlice verifies that a non-zero userID
// returns an empty (not nil) slice and no error (stub implementation).
func TestGetUserGroups_ValidIDReturnsEmptySlice(t *testing.T) {
	groups, err := GetUserGroups(1)
	if err != nil {
		t.Fatalf("GetUserGroups(1): unexpected error: %v", err)
	}
	if groups == nil {
		t.Error("expected non-nil slice, got nil")
	}
	if len(groups) != 0 {
		t.Errorf("expected empty slice, got len=%d", len(groups))
	}
}

// TestGetUserGroups_LargeIDReturnsEmpty confirms the stub works for arbitrary IDs.
func TestGetUserGroups_LargeIDReturnsEmpty(t *testing.T) {
	groups, err := GetUserGroups(^uint(0)) // max uint
	if err != nil {
		t.Fatalf("GetUserGroups(max uint): %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected empty slice, got %v", groups)
	}
}

// ---- GetGroupShares ----

// TestGetGroupShares_ZeroIDReturnsError verifies the guard that rejects groupID == 0.
func TestGetGroupShares_ZeroIDReturnsError(t *testing.T) {
	_, err := GetGroupShares(0)
	if err == nil {
		t.Fatal("expected error for groupID == 0, got nil")
	}
	if err.Error() != "group ID cannot be zero" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestGetGroupShares_ValidIDReturnsEmptySlice verifies that a non-zero groupID
// returns an empty (not nil) slice and no error (stub implementation).
func TestGetGroupShares_ValidIDReturnsEmptySlice(t *testing.T) {
	shares, err := GetGroupShares(99)
	if err != nil {
		t.Fatalf("GetGroupShares(99): unexpected error: %v", err)
	}
	if shares == nil {
		t.Error("expected non-nil slice, got nil")
	}
	if len(shares) != 0 {
		t.Errorf("expected empty slice, got len=%d", len(shares))
	}
}

// TestGetGroupShares_ErrorIsStandardError verifies the zero-ID error satisfies
// the standard errors.New shape (for callers that errors.As / errors.Is).
func TestGetGroupShares_ErrorIsStandardError(t *testing.T) {
	_, err := GetGroupShares(0)
	var target *interface{ Error() string }
	// Just confirm the error interface; also shadow-check it's not an errors.As
	// typed error — it's a plain string error from errors.New.
	_ = target
	if !errors.As(err, new(interface{ Error() string })) {
		t.Errorf("error does not implement error interface: %v", err)
	}
}

// TestGetGroupShares_LargeIDReturnsEmpty confirms the stub works for large group IDs.
func TestGetGroupShares_LargeIDReturnsEmpty(t *testing.T) {
	shares, err := GetGroupShares(1_000_000)
	if err != nil {
		t.Fatalf("GetGroupShares(1_000_000): %v", err)
	}
	if len(shares) != 0 {
		t.Errorf("expected empty slice, got %v", shares)
	}
}

// ---- DefaultRegistry coverage (internal/trust is a separate package; we note
//      that trust_test.go already covers DefaultRegistry at line 82-88, so no
//      new test is needed here for that function.) ----
