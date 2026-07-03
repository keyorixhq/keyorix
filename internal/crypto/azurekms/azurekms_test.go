package azurekms

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// fakeKeys models Azure Key Vault's WrapKey/UnwrapKey semantics closely enough
// to exercise rotation: each version has distinct key material, so a blob
// wrapped under version A can only be unwrapped by requesting version A
// specifically — requesting "" (current) or a different version fails once
// "current" no longer points at A. currentVersion mutates to simulate rotation.
type fakeKeys struct {
	currentVersion string
}

type fakeWrapped struct {
	Version   string `json:"version"`
	Plaintext []byte `json:"plaintext"`
}

func (f *fakeKeys) resolve(version string) string {
	if version == "" {
		return f.currentVersion
	}
	return version
}

func (f *fakeKeys) WrapKey(_ context.Context, name string, version string, params azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	v := f.resolve(version)
	body, err := json.Marshal(fakeWrapped{Version: v, Plaintext: params.Value})
	if err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	kid := azkeys.ID(fmt.Sprintf("https://vault.vault.azure.net/keys/%s/%s", name, v))
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: &kid, Result: body}}, nil
}

func (f *fakeKeys) UnwrapKey(_ context.Context, _ string, version string, params azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	v := f.resolve(version)
	var w fakeWrapped
	if err := json.Unmarshal(params.Value, &w); err != nil {
		return azkeys.UnwrapKeyResponse{}, err
	}
	if w.Version != v {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("fake unwrap: blob wrapped under version %q, request targeted %q (key rotated?)", w.Version, v)
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: w.Plaintext}}, nil
}

func newTestClient(keys *fakeKeys, keyVersion string) *client {
	return &client{keys: keys, keyName: "kek", keyVersion: keyVersion}
}

func TestAzureKMS_EncryptPinsVersionAndSurvivesRotation(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "") // unversioned kms_key_id — the documented default usage

	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Simulate Azure's own recommended auto-rotation policy advancing "current"
	// to a new version between the Encrypt call and the next server restart.
	fk.currentVersion = "v2"

	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt must target the pinned version (v1), survived rotation to v2: %v", err)
	}
	if string(pt) != "kek-material" {
		t.Fatalf("round-trip got %q", pt)
	}
}

func TestAzureKMS_WithoutPinningWouldFailAfterRotation(t *testing.T) {
	// Sanity check that the fake actually models rotation breakage — i.e. that
	// the previous (unpinned) behavior really would have broken, so the pinning
	// fix in the test above is meaningfully exercised.
	fk := &fakeKeys{currentVersion: "v1"}
	res, err := fk.WrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("kek-material"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	fk.currentVersion = "v2"
	if _, err := fk.UnwrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     res.Result,
	}, nil); err == nil {
		t.Fatal("expected unwrap targeting \"current\" after rotation to fail against a pre-rotation blob")
	}
}

func TestAzureKMS_LegacyUnpinnedBlobStillDecrypts(t *testing.T) {
	// Legacy data: wrapped by the pre-fix Encrypt, which returned the raw wrap
	// result with no version-pinning envelope. As long as the key has not been
	// rotated since, it must still decrypt via the old "current"/configured-
	// version resolution.
	fk := &fakeKeys{currentVersion: "v1"}
	legacy, err := fk.WrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("legacy-kek"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	c := newTestClient(fk, "") // unversioned config, matching the legacy deployment
	pt, err := c.Decrypt(context.Background(), legacy.Result)
	if err != nil {
		t.Fatalf("legacy unpinned blob must still decrypt: %v", err)
	}
	if string(pt) != "legacy-kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAzureKMS_LegacyExplicitlyVersionedBlobStillDecrypts(t *testing.T) {
	// A pre-fix deployment that had already worked around this class of issue by
	// pinning kms_key_id itself to an explicit version must be unaffected.
	fk := &fakeKeys{currentVersion: "v3"}
	legacy, err := fk.WrapKey(context.Background(), "kek", "v3", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("legacy-kek"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	c := newTestClient(fk, "v3")
	pt, err := c.Decrypt(context.Background(), legacy.Result)
	if err != nil {
		t.Fatalf("legacy explicitly-versioned blob must still decrypt: %v", err)
	}
	if string(pt) != "legacy-kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAzureKMS_EncryptDecryptRoundTrip(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "")
	ct, err := c.Encrypt(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("got %q", pt)
	}
}

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		name                             string
		keyID                            string
		wantVault, wantName, wantVersion string
		wantErr                          bool
	}{
		{
			name:        "versioned",
			keyID:       "https://myvault.vault.azure.net/keys/kek/abc123",
			wantVault:   "https://myvault.vault.azure.net",
			wantName:    "kek",
			wantVersion: "abc123",
		},
		{
			name:      "unversioned uses latest",
			keyID:     "https://myvault.vault.azure.net/keys/kek",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{
			name:      "trailing slash",
			keyID:     "https://myvault.vault.azure.net/keys/kek/",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{name: "missing scheme/host", keyID: "/keys/kek/v1", wantErr: true},
		{name: "not a keys path", keyID: "https://myvault.vault.azure.net/secrets/foo", wantErr: true},
		{name: "missing key name", keyID: "https://myvault.vault.azure.net/keys", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, name, version, err := parseKeyID(tt.keyID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got vault=%q name=%q version=%q", vault, name, version)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if vault != tt.wantVault || name != tt.wantName || version != tt.wantVersion {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", vault, name, version, tt.wantVault, tt.wantName, tt.wantVersion)
			}
		})
	}
}
