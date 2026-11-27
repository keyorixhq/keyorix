package azurekms

// KEYCOMMIT-2 item 3: which key a version-pinned envelope is unwrapped under. The
// envelope carries a key VERSION (authenticated by the MAC against the unwrapped
// KEK, see envelope) but no key NAME: UnwrapKey is always called with the configured
// name, whatever the blob says. This pins that with the stub client. It does NOT
// verify the MAC (TestAzureKMS_DecryptRefusesTamperedVersion), the legacy
// no-MAC envelope (TestDecrypt_PinnedEnvelopeWithoutMACStillDecrypts: by design the
// version is unauthenticated there), or anything about what Key Vault embeds.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type nameRecordingKeys struct {
	inner      *fakeKeys
	unwrapName string
	unwrapVer  string
}

func (r *nameRecordingKeys) WrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, o *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	return r.inner.WrapKey(ctx, name, version, p, o)
}

func (r *nameRecordingKeys) UnwrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, o *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	r.unwrapName, r.unwrapVer = name, version
	return r.inner.UnwrapKey(ctx, name, version, p, o)
}

func TestAzureKMS_DecryptUsesConfiguredKeyNameWhateverTheEnvelopeSays(t *testing.T) {
	rec := &nameRecordingKeys{inner: &fakeKeys{currentVersion: "v1"}}
	c := &client{keys: rec, keyName: "kek", keyVersion: ""}
	ct, err := c.Encrypt(context.Background(), []byte(testKEK32))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Control: the honest envelope unwraps under the configured name and its version.
	if _, err := c.Decrypt(context.Background(), ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if rec.unwrapName != "kek" || rec.unwrapVer != "v1" {
		t.Fatalf("UnwrapKey(%q, %q), want (kek, v1)", rec.unwrapName, rec.unwrapVer)
	}

	// An envelope with extra key-naming fields: they are not part of the format and
	// must not reach the request.
	env, pinned, err := decodeEnvelope(ct)
	if err != nil || !pinned {
		t.Fatalf("decodeEnvelope: pinned=%v err=%v", pinned, err)
	}
	var m map[string]any
	body, _ := json.Marshal(env)
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["name"] = "attacker-key"
	m["kid"] = "https://vault.vault.azure.net/keys/attacker-key/v9"
	forgedBody, _ := json.Marshal(m)
	forged := append([]byte(envelopeMagic), forgedBody...)

	rec.unwrapName, rec.unwrapVer = "", ""
	_, _ = c.Decrypt(context.Background(), forged)
	if rec.unwrapName != "kek" {
		t.Fatalf("an envelope carrying a key name redirected UnwrapKey to %q", rec.unwrapName)
	}
}
