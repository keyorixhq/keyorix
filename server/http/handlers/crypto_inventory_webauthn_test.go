package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func coseBlob(t *testing.T, v any) []byte {
	t.Helper()
	pk, err := webauthncbor.Marshal(v)
	require.NoError(t, err)
	blob, err := json.Marshal(map[string]any{"publicKey": pk})
	require.NoError(t, err)
	return blob
}

func TestCryptoInventoryHandler_WebAuthnCredentialsByAlgorithm(t *testing.T) {
	f := newCryptoInvFixture(t)
	require.NoError(t, f.db.AutoMigrate(&models.WebAuthnCredential{}))
	f.cfg.WebAuthn.Enabled, f.cfg.WebAuthn.RPID = true, "keyorix.example"

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	blobs := [][]byte{
		coseBlob(t, webauthncose.EC2PublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
			Curve: int64(webauthncose.P256), XCoord: pad(ec.X.Bytes()), YCoord: pad(ec.Y.Bytes())}),
		coseBlob(t, webauthncose.RSAPublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.RSAKey), Algorithm: int64(webauthncose.AlgRS256)},
			Modulus: rk.N.Bytes(), Exponent: big.NewInt(int64(rk.E)).Bytes()}),
		coseBlob(t, webauthncose.OKPPublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.OctetKey), Algorithm: int64(webauthncose.AlgEdDSA)},
			Curve: int64(webauthncose.Ed25519), XCoord: edPub}),
		[]byte(`not json`),
	}
	// Three users, one of them with two credentials: the walk is per user.
	for i, b := range blobs {
		u := &models.User{Username: fmt.Sprintf("u%d", i/2), Email: fmt.Sprintf("u%d@example.test", i/2)}
		if i%2 == 0 {
			require.NoError(t, f.db.Create(u).Error)
		} else {
			require.NoError(t, f.db.Where("username = ?", u.Username).First(u).Error)
		}
		require.NoError(t, f.db.Create(&models.WebAuthnCredential{UserID: u.ID, CredentialID: []byte{byte(i + 1)}, Name: "k",
			CredentialBlob: b, CreatedAt: time.Now().Add(-time.Duration(i+1) * 24 * time.Hour)}).Error)
	}

	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	byID := map[string]cryptoinventory.Asset{}
	for _, a := range env.Data.Assets {
		byID[a.ID] = a
	}
	assert.Equal(t, "ECDSA-P256 (COSE ES256)", byID["webauthn-passkeys.ecdsa-p256-cose-es256"].Algorithm)
	assert.Equal(t, "RSA-2048 (COSE RS256)", byID["webauthn-passkeys.rsa-2048-cose-rs256"].Algorithm)
	assert.Equal(t, "Ed25519 (COSE EdDSA)", byID["webauthn-passkeys.ed25519-cose-eddsa"].Algorithm)
	assert.Contains(t, byID, "webauthn-passkeys.unknown", "an undecodable blob is recorded, not dropped")
	assert.NotContains(t, byID, "webauthn-passkeys", "the generic asset is replaced")
	assert.Contains(t, w.Body.String(), "1 WebAuthn credential(s) have a public key that could not be classified")
	assert.NotContains(t, w.Body.String(), string(blobs[0]), "no credential bytes in the response")
}

func TestCryptoInventoryHandler_WebAuthnListingFailureKeepsGenericAsset(t *testing.T) {
	f := newCryptoInvFixture(t) // no webauthn_credentials table: the per-user query fails
	f.cfg.WebAuthn.Enabled, f.cfg.WebAuthn.RPID = true, "keyorix.example"
	require.NoError(t, f.db.Create(&models.User{Username: "a", Email: "a@example.test"}).Error)

	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "webauthn-passkeys")
	assert.Contains(t, w.Body.String(), "WebAuthn credentials could not be listed")
}
