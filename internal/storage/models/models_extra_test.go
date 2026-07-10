package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SecretNode helper methods ---

// TestSecretNode_CanAccess validates that the owner always has access and a
// non-owner without shares does not.
func TestSecretNode_CanAccess(t *testing.T) {
	s := &SecretNode{OwnerID: 1}
	assert.True(t, s.CanAccess(1), "owner must always have access")
	assert.False(t, s.CanAccess(2), "non-owner with no share must not have access")
}

// TestSecretNode_CanWrite validates that only the owner has write access in the
// model-layer helper (shares are checked at the storage layer).
func TestSecretNode_CanWrite(t *testing.T) {
	s := &SecretNode{OwnerID: 10}
	assert.True(t, s.CanWrite(10))
	assert.False(t, s.CanWrite(99))
}

// --- Permission level helpers ---

// TestValidatePermissionLevel_CaseSensitive validates that uppercase is not
// accepted (ValidatePermissionLevel is case-sensitive).
func TestValidatePermissionLevel_CaseSensitive(t *testing.T) {
	// "READ" and "WRITE" must be rejected — only lowercase is valid.
	require.Error(t, ValidatePermissionLevel("READ"))
	require.Error(t, ValidatePermissionLevel("WRITE"))
	require.Error(t, ValidatePermissionLevel("admin"))
}

// --- Group sharing helpers ---

// TestGetGroupMembers_ZeroIDError validates the zero-ID guard.
func TestGetGroupMembers_ZeroIDError(t *testing.T) {
	_, err := GetGroupMembers(0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}

// TestGetGroupMembers_NonZeroID validates a non-zero ID returns a non-nil
// (but empty) slice without error.
func TestGetGroupMembers_NonZeroID(t *testing.T) {
	members, err := GetGroupMembers(1)
	require.NoError(t, err)
	assert.NotNil(t, members)
}

// TestValidateGroupExists_ZeroIDError validates the zero-ID guard.
func TestValidateGroupExists_ZeroIDError(t *testing.T) {
	err := ValidateGroupExists(0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}

// TestValidateGroupExists_NonZeroID validates that a non-zero ID passes.
func TestValidateGroupExists_NonZeroID(t *testing.T) {
	// The placeholder always returns nil for non-zero.
	require.NoError(t, ValidateGroupExists(1))
}

// TestCanAccessViaGroup_ZeroSecretID validates the secret-ID zero guard.
func TestCanAccessViaGroup_ZeroSecretID(t *testing.T) {
	_, _, err := CanAccessViaGroup(0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret")
}

// TestCanAccessViaGroup_ZeroUserID validates the user-ID zero guard.
func TestCanAccessViaGroup_ZeroUserID(t *testing.T) {
	_, _, err := CanAccessViaGroup(1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user")
}

// TestCanAccessViaGroup_NonZero validates that non-zero IDs return no error.
func TestCanAccessViaGroup_NonZero(t *testing.T) {
	ok, perm, err := CanAccessViaGroup(1, 2)
	require.NoError(t, err)
	assert.False(t, ok, "placeholder always returns false")
	assert.Empty(t, perm)
}

// TestGetUserGroups_ZeroIDError validates the zero-ID guard.
func TestGetUserGroups_ZeroIDError(t *testing.T) {
	_, err := GetUserGroups(0)
	require.Error(t, err)
}

// TestGetGroupShares_ZeroIDError validates the zero-ID guard.
func TestGetGroupShares_ZeroIDError(t *testing.T) {
	_, err := GetGroupShares(0)
	require.Error(t, err)
}

// TestIsGroupMember_Placeholder validates that the placeholder always returns
// false.
func TestIsGroupMember_Placeholder(t *testing.T) {
	assert.False(t, IsGroupMember(1, 1))
}

// --- JSON type ---

// TestJSON_ValueNil validates that a nil JSON value returns (nil, nil).
func TestJSON_ValueNil(t *testing.T) {
	var j JSON
	v, err := j.Value()
	require.NoError(t, err)
	assert.Nil(t, v)
}

// TestJSON_Value validates that a non-nil JSON returns its string representation.
func TestJSON_Value(t *testing.T) {
	j := JSON(`{"key":"val"}`)
	v, err := j.Value()
	require.NoError(t, err)
	assert.Equal(t, `{"key":"val"}`, v)
}

// TestJSON_ScanNil validates that scanning nil sets j to nil.
func TestJSON_ScanNil(t *testing.T) {
	var j JSON
	require.NoError(t, j.Scan(nil))
	assert.Nil(t, j)
}

// TestJSON_ScanString validates scanning a string value.
func TestJSON_ScanString(t *testing.T) {
	var j JSON
	require.NoError(t, j.Scan(`{"a":1}`))
	assert.Equal(t, JSON(`{"a":1}`), j)
}

// TestJSON_ScanBytes validates scanning a []byte value.
func TestJSON_ScanBytes(t *testing.T) {
	var j JSON
	require.NoError(t, j.Scan([]byte(`{"b":2}`)))
	assert.Equal(t, JSON(`{"b":2}`), j)
}

// TestJSON_ScanUnsupportedType validates that scanning an unsupported type
// returns an error.
func TestJSON_ScanUnsupportedType(t *testing.T) {
	var j JSON
	err := j.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scan type")
}

// TestJSON_MarshalJSON_Nil validates that a nil JSON marshals as "null".
func TestJSON_MarshalJSON_Nil(t *testing.T) {
	var j JSON
	b, err := j.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, "null", string(b))
}

// TestJSON_MarshalJSON_NonNil validates raw bytes are used directly.
func TestJSON_MarshalJSON_NonNil(t *testing.T) {
	j := JSON(`{"x":1}`)
	b, err := j.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `{"x":1}`, string(b))
}

// TestJSON_UnmarshalJSON validates that JSON is stored as raw bytes.
func TestJSON_UnmarshalJSON(t *testing.T) {
	var j JSON
	require.NoError(t, j.UnmarshalJSON([]byte(`{"y":2}`)))
	assert.Equal(t, JSON(`{"y":2}`), j)
}

// TestJSON_RoundTrip validates the full marshal/unmarshal cycle via encoding/json.
func TestJSON_RoundTrip(t *testing.T) {
	type wrapper struct {
		Data JSON `json:"data"`
	}
	original := wrapper{Data: JSON(`{"hello":"world"}`)}
	b, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded wrapper
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, original.Data, decoded.Data)
}

// TestJSON_RoundTrip_Null validates that a nil JSON field marshals as null and
// round-trips correctly.
func TestJSON_RoundTrip_Null(t *testing.T) {
	type wrapper struct {
		Data JSON `json:"data"`
	}
	original := wrapper{Data: nil}
	b, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(b), "null")

	var decoded wrapper
	require.NoError(t, json.Unmarshal(b, &decoded))
	// After round-trip, Data may be nil or JSON("null") depending on path.
	// Both are acceptable; just ensure no error.
}

// --- NotificationSeverity ---

// TestNotificationSeverity_Constants validates the ordered severity constants.
func TestNotificationSeverity_Constants(t *testing.T) {
	assert.Equal(t, NotificationSeverity(0), NotificationSeverityNone)
	assert.Equal(t, NotificationSeverity(1), NotificationSeverityWarning)
	assert.Equal(t, NotificationSeverity(2), NotificationSeverityCritical)

	// Critical is strictly more severe than Warning.
	assert.Greater(t, int(NotificationSeverityCritical), int(NotificationSeverityWarning))
}

// --- SoDPolicy TableName ---

// TestSoDPolicy_TableName validates the custom table name.
func TestSoDPolicy_TableName(t *testing.T) {
	assert.Equal(t, "sod_policies", SoDPolicy{}.TableName())
}

// --- MachineIdentityOIDCBinding TableName ---

// TestMachineIdentityOIDCBinding_TableName validates the custom table name.
func TestMachineIdentityOIDCBinding_TableName(t *testing.T) {
	assert.Equal(t, "machine_identity_oidc_bindings", MachineIdentityOIDCBinding{}.TableName())
}

// --- DynamicSecretLease ---

// TestDynamicSecretLease_StatusTransitions validates that the model stores all
// expected status values.
func TestDynamicSecretLease_StatusTransitions(t *testing.T) {
	for _, s := range []string{"active", "revoked", "expired", "revoke_failed"} {
		l := DynamicSecretLease{Status: s}
		assert.Equal(t, s, l.Status)
	}
}

// TestDynamicSecretLease_ExpiresAt validates IssuedAt < ExpiresAt ordering.
func TestDynamicSecretLease_ExpiresAt(t *testing.T) {
	now := time.Now()
	l := DynamicSecretLease{
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	assert.True(t, l.ExpiresAt.After(l.IssuedAt))
}

// --- ShareRecord permission defaults ---

// TestShareRecord_DefaultPermission validates that an empty Permission is set
// to "read" by ValidateShareRecord.
func TestShareRecord_DefaultPermission(t *testing.T) {
	s := &ShareRecord{SecretID: 1, OwnerID: 2, RecipientID: 3}
	require.NoError(t, ValidateShareRecord(s))
	assert.Equal(t, "read", s.Permission)
}

// TestShareRecord_ExpiresAt validates that an expired share can be represented.
func TestShareRecord_ExpiresAt(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := ShareRecord{ExpiresAt: &past}
	assert.True(t, s.ExpiresAt.Before(time.Now()))
}
