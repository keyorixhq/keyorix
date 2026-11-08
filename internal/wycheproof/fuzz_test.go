package wycheproof

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

// The fuzz targets are differential: the Keyorix wrapper (or the library path
// Keyorix uses) must agree with the standard library primitive called directly.
// They are seeded from the Wycheproof vectors when those are downloaded, and
// always with the generated valid inputs below, so that without the vectors
// (CI and the fuzz rig do not fetch them) every target still has a key and an
// input that the accept branch handles.

// fallbackMsg is signed by the fixed keys the JWT target uses when the
// vectors are absent. Only the public keys and one signature each are kept;
// the private keys were discarded after signing.
var fallbackMsg = []byte("keyorix wycheproof fuzz seed")

var (
	fallbackECJWK = rules.JWK{Kty: "EC", Crv: "P-256",
		X: "VU9ido9aLa-s_RTBL3oXQaF3zTpcbXGs6A5WVZ8znyI",
		Y: "uxKGmlvKktgQ9TAt7ySW_MMhmQzKtm7U6vIBM5q3csI"}
	fallbackES256Sig = mustHex("03aca2f7ca7ffcca61f6a09298b6dfd665b31d0e628a0a738a06dab04ce7d6ec" +
		"75d04890525133e42f47d03f46d3d85ee3c27f795682afa2fddcc5ad2798aa80")
	fallbackRSJWK = rules.JWK{Kty: "RSA", E: "AQAB",
		N: "-3T9fz9cWIkZye9VjhuawSQJLYCXLHek0rVja5kqAgApjySje9sHJZPmRnYuw78oubgWHieDUUnP7CCWUQHSRMP2gQnGN5Vt0_RWWp4Wm0XnQ27LsIwOPWUoFvyQNYiEZVmdWLK8BYqySZsni7uvHapIi0mFVFyOGcZEMfxmwvysI0BfhBtBruPUWoYPlyk__d1onCOiINOt20I8FiRcH0ZZ6bh3MEwdNfLuKCFoI-aoitEeRfR7CneG4KGziWgHCWE0_pQ86_4-xDO5Yj-whXtVQ96ma7i3TUBgmdFyV29Zv1Rj1ARcQXhzR4jaC4hh9wH1SFpbabXAdu81N032QQ"}
	fallbackRS256Sig = mustHex("b8786d23791813e6b74d0694739930c307eb5f8b24963b4de4da567f57122bb6" +
		"07891370ac417b517d5f6c7173cff7f65e9c3bf185c57dd28c044c4127706869" +
		"b11ffc5c1c7fa54876e622a9cb55b9e5f5637de3afd857dce8b8d2d57ac0f2d6" +
		"f7eefc7206fc2c7173bf922ab7a421c1339b3984bf5e2c86c58e62d1718185e8" +
		"446e71890ebeb66771d8b2d3f3bc38ca4f1a5fcefe390f56a43bb030f3ab243d" +
		"581ff2da4f922004334baae7bed1b3321c6ff874a045e7c4652347d0b53c2915" +
		"c04717afb16ffbf90971125e744e869603ac6284e5d3494b9bfa2224a5887706" +
		"f8c0536a5d6673001fbc7cce5148e239a1801df26ed366e48999a448e5eb4dc0")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// fixedBytes returns n bytes starting at start and counting up.
func fixedBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// aeadFuzzInput encodes one input of FuzzWycheproofAEADOpen.
func aeadFuzzInput(key, nonce, aad, ct, tag []byte) []byte {
	b := append(clone(key), nonce...)
	b = append(b, byte(len(aad)))
	b = append(b, aad...)
	return append(append(b, ct...), tag...)
}

// sealedAEADSeed is a valid AES-256-GCM input sealed with crypto/cipher.
func sealedAEADSeed() []byte {
	key, nonce, aad := fixedBytes(32, 1), fixedBytes(12, 0x40), []byte("aad")
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	sealed := g.Seal(nil, nonce, []byte("hello"), aad)
	n := len(sealed) - g.Overhead()
	return aeadFuzzInput(key, nonce, aad, sealed[:n], sealed[n:])
}

// signedEd25519Seed is a valid pub||sig||msg input for FuzzWycheproofEd25519Verify.
func signedEd25519Seed() []byte {
	priv := ed25519.NewKeyFromSeed(fixedBytes(ed25519.SeedSize, 7))
	pub, _ := priv.Public().(ed25519.PublicKey)
	return append(append(clone(pub), ed25519.Sign(priv, fallbackMsg)...), fallbackMsg...)
}

func FuzzWycheproofAEADOpen(f *testing.F) {
	enc := aeadFuzzInput
	f.Add(enc(make([]byte, 32), make([]byte, 12), nil, []byte("hello"), make([]byte, 16)))
	f.Add(sealedAEADSeed())
	var v aesGCMFile
	if wvec.Load("aes_gcm_test.json", &v) == nil {
		n := 0
		for _, g := range v.TestGroups {
			if g.KeySize != 256 || g.IvSize != 96 || g.TagSize != 128 {
				continue
			}
			for _, tc := range g.Tests {
				if len(tc.Aad) < 256 && n < 120 {
					f.Add(enc(tc.Key, tc.Iv, tc.Aad, tc.Ct, tc.Tag))
					n++
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 45 {
			return
		}
		key, nonce := data[:32], data[32:44]
		al := int(data[44])
		if len(data) < 45+al {
			return
		}
		aad, rest := data[45:45+al], data[45+al:]
		ct, tag := rest, []byte(nil)
		if len(rest) >= 16 {
			ct, tag = rest[:len(rest)-16], rest[len(rest)-16:]
		}
		want, werr := stdlibOpen(key, nonce, aad, ct, tag)
		for _, open := range []aeadOpen{keyorixOpen(false), keyorixOpen(true)} {
			got, gerr := open(key, nonce, aad, ct, tag)
			if (gerr == nil) != (werr == nil) {
				t.Fatalf("accept mismatch: wrapper err=%v stdlib err=%v", gerr, werr)
			}
			if gerr == nil && !eq(got, want) {
				t.Fatalf("plaintext mismatch")
			}
		}
	})
}

func FuzzWycheproofEd25519Verify(f *testing.F) {
	var v ed25519File
	if wvec.Load("ed25519_test.json", &v) == nil {
		n := 0
		for _, g := range v.TestGroups {
			for _, tc := range g.Tests {
				if len(g.PublicKey.Pk) == 32 && len(tc.Sig) == 64 && n < 150 {
					f.Add(append(append(clone(g.PublicKey.Pk), tc.Sig...), tc.Msg...))
					n++
				}
			}
		}
	}
	f.Add(make([]byte, 96))
	f.Add(signedEd25519Seed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 96 {
			return
		}
		pub, sig, msg := data[:32], data[32:96], data[96:]
		if keyorixEdVerify(pub, msg, sig) != stdlibEdVerify(pub, msg, sig) {
			t.Fatalf("pkg/trust and crypto/ed25519 disagree")
		}
	})
}

func FuzzWycheproofJWTVerify(f *testing.F) {
	var es sigFile
	var rs sigFile
	var ecJWK, rsJWK rules.JWK
	haveEC := wvec.Load("ecdsa_secp256r1_sha256_p1363_test.json", &es) == nil && len(es.TestGroups) > 0
	haveRS := wvec.Load("rsa_signature_2048_sha256_test.json", &rs) == nil && len(rs.TestGroups) > 0
	if haveEC {
		g := es.TestGroups[0]
		ecJWK = jwkOf(g)
		for i, tc := range g.Tests {
			if i < 100 {
				f.Add(byte(0), []byte(tc.Msg), []byte(tc.Sig))
			}
		}
	}
	if haveRS {
		g := rs.TestGroups[0]
		rsJWK = jwkOf(g)
		for i, tc := range g.Tests {
			if i < 60 {
				f.Add(byte(1), []byte(tc.Msg), []byte(tc.Sig))
			}
		}
	}
	if !haveEC {
		ecJWK = fallbackECJWK
		f.Add(byte(0), fallbackMsg, fallbackES256Sig)
	}
	if !haveRS {
		rsJWK = fallbackRSJWK
		f.Add(byte(1), fallbackMsg, fallbackRS256Sig)
	}
	var ecPub *ecdsa.PublicKey
	var rsPub *rsa.PublicKey
	if k, err := rules.ParseJWK(ecJWK); err == nil {
		ecPub, _ = k.(*ecdsa.PublicKey)
	}
	if k, err := rules.ParseJWK(rsJWK); err == nil {
		rsPub, _ = k.(*rsa.PublicKey)
	}
	if ecPub == nil || rsPub == nil {
		// Without both keys a branch of the target would compare nothing.
		f.Fatalf("FuzzWycheproofJWTVerify: no usable key (ES256 %v, RS256 %v)", ecPub != nil, rsPub != nil)
	}
	f.Fuzz(func(t *testing.T, which byte, msg, sig []byte) {
		h := sha256.Sum256(msg)
		if which%2 == 0 {
			got := keyorixJWTVerify("ES256")(ecJWK, msg, sig)
			want := false
			if len(sig) == 64 {
				want = ecdsa.VerifyASN1(ecPub, h[:], derSig(new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])))
			}
			if got != want {
				t.Fatalf("ES256: jwt=%v ecdsa=%v", got, want)
			}
		} else {
			got := keyorixJWTVerify("RS256")(rsJWK, msg, sig)
			want := rsa.VerifyPKCS1v15(rsPub, crypto.SHA256, h[:], sig) == nil
			if got != want {
				t.Fatalf("RS256: jwt=%v rsa=%v", got, want)
			}
		}
	})
}

// TestFuzzFallbackSeedsAreAccepted: the generated seeds are valid inputs, so
// the fuzz targets reach their accept branch even without the vectors.
func TestFuzzFallbackSeedsAreAccepted(t *testing.T) {
	if !keyorixJWTVerify("ES256")(fallbackECJWK, fallbackMsg, fallbackES256Sig) {
		t.Error("ES256 fallback signature is rejected by the JWT path")
	}
	if !keyorixJWTVerify("RS256")(fallbackRSJWK, fallbackMsg, fallbackRS256Sig) {
		t.Error("RS256 fallback signature is rejected by the JWT path")
	}
	d := sealedAEADSeed()
	al := int(d[44])
	aad, rest := d[45:45+al], d[45+al:]
	for _, open := range []aeadOpen{keyorixOpen(false), keyorixOpen(true)} {
		pt, err := open(d[:32], d[32:44], aad, rest[:len(rest)-16], rest[len(rest)-16:])
		if err != nil || string(pt) != "hello" {
			t.Errorf("AEAD sealed seed: plaintext %q, err %v", pt, err)
		}
	}
	e := signedEd25519Seed()
	if !keyorixEdVerify(e[:32], e[96:], e[32:96]) {
		t.Error("Ed25519 seed is rejected by pkg/trust")
	}
}
