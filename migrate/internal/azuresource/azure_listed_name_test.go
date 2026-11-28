package azuresource

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// TestListedSecretName_MalformedServerIDs pins the fix for a nil-pointer panic: the
// SDK's ID.Name() panics for any listed ID that does not carry a name segment, and
// the ID comes from the vault's list response (server-controlled). Every malformed
// shape must come back as "" (the caller skips the entry) and must never panic.
//
// It does NOT verify the SDK itself (its Name() is still unsafe for these inputs),
// the get-by-name path, or IDs with a name but an unusable version segment.
func TestListedSecretName_MalformedServerIDs(t *testing.T) {
	for _, tc := range []struct{ id, want string }{
		{"", ""},
		{"https://v.vault.azure.net", ""},
		{"https://v.vault.azure.net/", ""},
		{"https://v.vault.azure.net/secrets", ""},
		{"%zz", ""},
		{"::::", ""},
		{"https://v.vault.azure.net/secrets/db-password", "db-password"},
		{"https://v.vault.azure.net/secrets/db-password/0123abcd", "db-password"},
	} {
		id := azsecrets.ID(tc.id)
		if got := listedSecretName(&id); got != tc.want {
			t.Errorf("listedSecretName(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}
