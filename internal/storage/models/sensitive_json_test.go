package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// Sensitive at-rest fields (password hashes, secret ciphertext, encrypted
// credentials, token hashes) must never appear when a model is JSON-marshalled, so
// an accidental raw-model serialization in any handler/export cannot leak them.
// Each field carries `json:"-"`; this regression guards against that being dropped.
func TestSensitiveFieldsAreNotJSONSerialized(t *testing.T) {
	cases := []struct {
		name    string
		v       interface{}
		secrets []string
	}{
		{
			name:    "User.PasswordHash",
			v:       &User{Username: "alice", PasswordHash: "BCRYPT$leaked"},
			secrets: []string{"BCRYPT$leaked", "PasswordHash"},
		},
		{
			name:    "SecretVersion.EncryptedValue",
			v:       &SecretVersion{SecretNodeID: 1, EncryptedValue: []byte("ciphertext-here"), EncryptionMetadata: JSON(`{"k":"v1"}`)},
			secrets: []string{"EncryptedValue", "EncryptionMetadata"},
		},
		{
			name:    "MFASecret.SecretEnc",
			v:       &MFASecret{UserID: 1, SecretEnc: []byte("totp-seed"), SecretMeta: []byte("meta")},
			secrets: []string{"SecretEnc", "SecretMeta"},
		},
		{
			name:    "DynamicSecretConfig.AdminDSNEnc",
			v:       &DynamicSecretConfig{Name: "pg", AdminDSNEnc: []byte("postgres://secret"), AdminDSNMeta: []byte("m")},
			secrets: []string{"AdminDSNEnc"},
		},
		{
			name:    "DynamicSecretLease.CredentialEnc",
			v:       &DynamicSecretLease{LeaseID: "l1", CredentialEnc: []byte("cred-json")},
			secrets: []string{"CredentialEnc"},
		},
		{
			name:    "APIClient.ClientSecret",
			v:       &APIClient{ClientID: "kx-client-1", ClientSecret: "sha256hash", EncryptedClientSecret: []byte("x")},
			secrets: []string{"ClientSecret", "EncryptedClientSecret"},
		},
		{
			name:    "APIToken.Token",
			v:       &APIToken{Token: "sha256hash", EncryptedToken: []byte("x")},
			secrets: []string{"\"Token\"", "EncryptedToken"},
		},
		{
			name:    "Session.SessionToken",
			v:       &Session{SessionToken: "sha256hash", EncryptedSessionToken: []byte("x")},
			secrets: []string{"SessionToken", "EncryptedSessionToken"},
		},
		{
			name:    "PasswordReset.Token",
			v:       &PasswordReset{Token: "reset-tok", EncryptedToken: []byte("x")},
			secrets: []string{"reset-tok", "EncryptedToken"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			out := string(b)
			for _, s := range tc.secrets {
				if strings.Contains(out, s) {
					t.Errorf("marshalled JSON must not contain %q, got: %s", s, out)
				}
			}
		})
	}
}
