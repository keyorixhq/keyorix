// remote_mfa_wire_test.go — unit tests for verifyMFAWireResponse.toModel(),
// specifically that the password-age fields (PasswordChangedAt, CreatedAt)
// survive the wire→model conversion so enforcePasswordExpiryGate (ADR-025)
// evaluates correctly on storage.type: remote spoke deployments.
package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyMFAWireResponse_ToModel_PreservesPasswordAgeFields confirms that
// toModel() populates PasswordChangedAt and CreatedAt from the wire response.
// Before the fix these fields were absent from verifyMFAWireResponse, so
// toModel() always returned a sparse User{ID, Username} — causing
// core.PasswordExpired() to return false regardless of the actual password age,
// silently bypassing enforcePasswordExpiryGate on remote spoke deployments.
func TestVerifyMFAWireResponse_ToModel_PreservesPasswordAgeFields(t *testing.T) {
	changedAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	createdAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	wire := verifyMFAWireResponse{
		ID:                42,
		Username:          "alice",
		UsedRecovery:      false,
		PasswordChangedAt: &changedAt,
		CreatedAt:         createdAt,
	}
	u := wire.toModel()
	require.NotNil(t, u)
	assert.Equal(t, uint(42), u.ID)
	assert.Equal(t, "alice", u.Username)
	require.NotNil(t, u.PasswordChangedAt,
		"PasswordChangedAt must be propagated from the wire response so "+
			"enforcePasswordExpiryGate can evaluate the password age on remote storage")
	assert.Equal(t, changedAt, *u.PasswordChangedAt)
	assert.Equal(t, createdAt, u.CreatedAt,
		"CreatedAt must be propagated so the fallback expiry path (nil PasswordChangedAt) works correctly")
}

// TestVerifyMFAWireResponse_ToModel_NilPasswordChangedAt confirms that a nil
// PasswordChangedAt (legacy user, never explicitly set) is preserved as nil
// rather than replaced with a zero value — core.PasswordExpired's fallback
// path uses user.CreatedAt in that case, so both fields must round-trip cleanly.
func TestVerifyMFAWireResponse_ToModel_NilPasswordChangedAt(t *testing.T) {
	createdAt := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	wire := verifyMFAWireResponse{
		ID:                7,
		Username:          "bob",
		UsedRecovery:      true,
		PasswordChangedAt: nil,
		CreatedAt:         createdAt,
	}
	u := wire.toModel()
	require.NotNil(t, u)
	assert.Nil(t, u.PasswordChangedAt,
		"nil PasswordChangedAt must remain nil so the CreatedAt fallback in PasswordExpired is reached")
	assert.Equal(t, createdAt, u.CreatedAt)
}
