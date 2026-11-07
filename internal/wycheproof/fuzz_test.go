package wycheproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

// The fuzz targets are differential: the Keyorix wrapper (or the library path
// Keyorix uses) must agree with the standard library primitive called directly.
// They are seeded from the Wycheproof vectors when those are downloaded.

func FuzzWycheproofAEADOpen(f *testing.F) {
	enc := func(key, nonce, aad, ct, tag []byte) []byte {
		b := append(clone(key), nonce...)
		b = append(b, byte(len(aad)))
		b = append(b, aad...)
		return append(append(b, ct...), tag...)
	}
	f.Add(enc(make([]byte, 32), make([]byte, 12), nil, []byte("hello"), make([]byte, 16)))
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
	if !haveEC && !haveRS {
		f.Add(byte(0), []byte("m"), make([]byte, 64))
	}
	var ecPub *ecdsa.PublicKey
	var rsPub *rsa.PublicKey
	if haveEC {
		if k, err := rules.ParseJWK(ecJWK); err == nil {
			ecPub, _ = k.(*ecdsa.PublicKey)
		}
	}
	if haveRS {
		if k, err := rules.ParseJWK(rsJWK); err == nil {
			rsPub, _ = k.(*rsa.PublicKey)
		}
	}
	f.Fuzz(func(t *testing.T, which byte, msg, sig []byte) {
		h := sha256.Sum256(msg)
		if which%2 == 0 && ecPub != nil {
			got := keyorixJWTVerify("ES256")(ecJWK, msg, sig)
			want := false
			if len(sig) == 64 {
				want = ecdsa.VerifyASN1(ecPub, h[:], derSig(new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])))
			}
			if got != want {
				t.Fatalf("ES256: jwt=%v ecdsa=%v", got, want)
			}
		} else if rsPub != nil {
			got := keyorixJWTVerify("RS256")(rsJWK, msg, sig)
			want := rsa.VerifyPKCS1v15(rsPub, crypto.SHA256, h[:], sig) == nil
			if got != want {
				t.Fatalf("RS256: jwt=%v rsa=%v", got, want)
			}
		}
	})
}
