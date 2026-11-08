package wycheproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

type sigGroup struct {
	PublicKey struct {
		Curve  string
		Wx, Wy wvec.Hex
	}
	PublicKeyJwk rules.JWK
	KeyJwk       rules.JWK
	Tests        []struct {
		TcID     int
		Flags    []string
		Msg, Sig wvec.Hex
		Result   string
	}
}

type sigFile struct{ TestGroups []sigGroup }

// jwtVerify is the operation under test: parse the key the way Keyorix does
// (rules.ParseJWK), then verify with the golang-jwt method for alg.
type jwtVerify func(jwk rules.JWK, msg, sig []byte) bool

func keyorixJWTVerify(alg string) jwtVerify {
	m := jwt.GetSigningMethod(alg)
	return func(jwk rules.JWK, msg, sig []byte) bool {
		key, err := rules.ParseJWK(jwk)
		if err != nil {
			return false
		}
		return m.Verify(string(msg), clone(sig), key) == nil
	}
}

// jwkOf returns the group's key as a JWK. Wycheproof omits publicKeyJwk for
// some edge-case keys; those are rebuilt from the affine coordinates.
func jwkOf(g sigGroup) rules.JWK {
	if g.PublicKeyJwk.Kty != "" {
		return g.PublicKeyJwk
	}
	if g.KeyJwk.Kty != "" {
		return g.KeyJwk
	}
	size, crv := 32, "P-256"
	if g.PublicKey.Curve == "secp384r1" {
		size, crv = 48, "P-384"
	}
	b64 := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(new(big.Int).SetBytes(b).FillBytes(make([]byte, size)))
	}
	return rules.JWK{Kty: "EC", Crv: crv, X: b64(g.PublicKey.Wx), Y: b64(g.PublicKey.Wy)}
}

// sigSuite runs the vectors and the signature mutations. ecN is the group
// order for ECDSA (nil for RSA); rsaN is the modulus (nil for ECDSA).
func sigSuite(r *Report, verify, ref jwtVerify, f *sigFile, ecBytes int, malleableOK bool) {
	for _, g := range f.TestGroups {
		jwk := jwkOf(g)
		var n *big.Int
		if ecBytes == 0 {
			n = new(big.Int).SetBytes(mustB64(jwk.N))
		}
		for _, tc := range g.Tests {
			id := "tc" + itoa(tc.TcID)
			tc := tc
			r.Judge(id, tc.Result, tc.Flags, true, func() bool { return verify(jwk, tc.Msg, tc.Sig) })
			if tc.Result != resValid {
				continue
			}
			rej := func(label string, m, s []byte) {
				if eq(m, tc.Msg) && eq(s, tc.Sig) {
					return
				}
				r.RejectRef(id+" "+label, func() bool { return verify(jwk, m, s) }, func() bool { return ref(jwk, m, s) })
			}
			for i := 0; i < len(tc.Sig)*8; i++ {
				if ecBytes == 48 && i >= 64 && i < len(tc.Sig)*8-64 && i%8 != 0 {
					continue // P-384: all bits of the first and last 8 bytes, then one bit per byte
				}
				rej("sigbit"+itoa(i), tc.Msg, flipBit(tc.Sig, i))
			}
			for i := 0; i < len(tc.Msg)*8 && i < 128; i++ {
				rej("msgbit"+itoa(i), flipBit(tc.Msg, i), tc.Sig)
			}
			rej("msg-ext", append(clone(tc.Msg), 'x'), tc.Sig)
			if len(tc.Msg) > 0 {
				rej("msg-trunc", tc.Msg[:len(tc.Msg)-1], tc.Sig)
				rej("msg-empty", nil, tc.Sig)
			}
			rej("sig-empty", tc.Msg, nil)
			rej("sig-trunc1", tc.Msg, tc.Sig[:len(tc.Sig)-1])
			rej("sig-trunc-half", tc.Msg, tc.Sig[:len(tc.Sig)/2])
			rej("sig-ext1", tc.Msg, append(clone(tc.Sig), 0))
			rej("sig-ext-ff", tc.Msg, append(clone(tc.Sig), 0xff))
			rej("sig-prepend0", tc.Msg, append([]byte{0}, tc.Sig...))
			rej("sig-zero", tc.Msg, make([]byte, len(tc.Sig)))
			rej("sig-ff", tc.Msg, repeat(0xff, len(tc.Sig)))
			if ecBytes > 0 && len(tc.Sig) == 2*ecBytes {
				ecMutations(r, id, jwk, verify, tc.Msg, tc.Sig, ecBytes, rej, malleableOK)
			}
			if ecBytes == 0 {
				s := new(big.Int).SetBytes(tc.Sig)
				if s2 := new(big.Int).Add(s, n); s2.BitLen() <= len(tc.Sig)*8 {
					rej("sig+N", tc.Msg, s2.FillBytes(make([]byte, len(tc.Sig))))
				}
				rej("sig=1", tc.Msg, new(big.Int).SetInt64(1).FillBytes(make([]byte, len(tc.Sig))))
			}
		}
	}
}

var curveOrders = map[int]*big.Int{
	32: mustBig("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	48: mustBig("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
}

func mustBig(h string) *big.Int { v, _ := new(big.Int).SetString(h, 16); return v }

func ecMutations(r *Report, id string, jwk rules.JWK, verify jwtVerify, msg, sig []byte, nb int, rej func(string, []byte, []byte), malleableOK bool) {
	n := curveOrders[nb]
	rr, ss := sig[:nb], sig[nb:]
	enc := func(a, b *big.Int) []byte {
		return append(a.FillBytes(make([]byte, nb)), b.FillBytes(make([]byte, nb))...)
	}
	ri, si := new(big.Int).SetBytes(rr), new(big.Int).SetBytes(ss)
	zero := new(big.Int)
	rej("r=0", msg, enc(zero, si))
	rej("s=0", msg, enc(ri, zero))
	rej("r=n", msg, enc(n, si))
	rej("s=n", msg, enc(ri, n))
	rej("r=s=0", msg, enc(zero, zero))
	if rn := new(big.Int).Add(ri, n); rn.BitLen() <= nb*8 {
		rej("r+n", msg, enc(rn, si))
	}
	if sn := new(big.Int).Add(si, n); sn.BitLen() <= nb*8 {
		rej("s+n", msg, enc(ri, sn))
	}
	rej("rs-swapped", msg, enc(si, ri))
	// DER form of the same signature must not be accepted by the P1363 path
	rej("der-form", msg, derSig(ri, si))
	// (r, n-s) is a mathematically valid ECDSA signature; JWT does not enforce
	// low-S, so it is recorded and not asserted (RULES.md section 1).
	hi := new(big.Int).Sub(n, si)
	if hi.Sign() > 0 {
		if acc, pan := try(func() bool { return verify(jwk, msg, enc(ri, hi)) }); pan != nil {
			r.Failf("%s %s: PANIC on (r,n-s): %v", r.Name, id, pan)
		} else {
			r.Count("ecdsa_n_minus_s_accepted", b2i(acc))
			r.Count("ecdsa_n_minus_s_rejected", b2i(!acc))
		}
	}
	_ = malleableOK
}

func derSig(r, s *big.Int) []byte {
	enc := func(x *big.Int) []byte {
		b := x.Bytes()
		if len(b) == 0 || b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(enc(r), enc(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func TestJWTES256(t *testing.T) { runSig(t, "ecdsa_secp256r1_sha256_p1363_test.json", "ES256", 32) }
func TestJWTES384(t *testing.T) { runSig(t, "ecdsa_secp384r1_sha384_p1363_test.json", "ES384", 48) }
func TestJWTRS256(t *testing.T) { runSig(t, "rsa_signature_2048_sha256_test.json", "RS256", 0) }
func TestJWTPS256(t *testing.T) { runSig(t, "rsa_pss_2048_sha256_mgf1_32_test.json", "PS256", 0) }

func runSig(t *testing.T, file, alg string, ecBytes int) {
	var f sigFile
	loadVectors(t, file, &f)
	r := newReport("jwt/"+alg, true)
	if alg == "PS256" {
		// golang-jwt verifies PSS with an automatic salt length; the s_len
		// vectors (tc67-tc72) are therefore accepted. Tracked privately.
		r.Known = map[string]bool{"tc67": true, "tc68": true, "tc69": true, "tc70": true, "tc71": true, "tc72": true}
	}
	sigSuite(r, keyorixJWTVerify(alg), refVerify(alg), &f, ecBytes, true)
	t.Logf("%s: %s", r.Name, r.Summary())
	r.Err(t)
}

// refVerify is the reference: the standard library primitive called directly.
func refVerify(alg string) jwtVerify {
	return func(jwk rules.JWK, msg, sig []byte) bool {
		k, err := rules.ParseJWK(jwk)
		if err != nil {
			return false
		}
		switch pub := k.(type) {
		case *ecdsa.PublicKey:
			nb := (pub.Curve.Params().BitSize + 7) / 8
			if len(sig) != 2*nb {
				return false
			}
			var h []byte
			if nb == 32 {
				s := sha256.Sum256(msg)
				h = s[:]
			} else {
				s := sha512.Sum384(msg)
				h = s[:]
			}
			return ecdsa.VerifyASN1(pub, h, derSig(new(big.Int).SetBytes(sig[:nb]), new(big.Int).SetBytes(sig[nb:])))
		case *rsa.PublicKey:
			s := sha256.Sum256(msg)
			if alg == "PS256" {
				return rsa.VerifyPSS(pub, crypto.SHA256, s[:], sig, &rsa.PSSOptions{SaltLength: 32}) == nil
			}
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, s[:], sig) == nil
		}
		return false
	}
}
