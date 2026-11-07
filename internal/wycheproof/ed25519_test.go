package wycheproof

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

type ed25519File struct {
	TestGroups []struct {
		PublicKey struct{ Pk wvec.Hex }
		Tests     []struct {
			TcID     int
			Flags    []string
			Msg, Sig wvec.Hex
			Result   string
		}
	}
}

// edVerify is the operation under test: true means the signature was accepted.
type edVerify func(pub, msg, sig []byte) bool

// keyorixEdVerify goes through pkg/trust's registry exactly as the update and
// license checks do.
func keyorixEdVerify(pub, msg, sig []byte) bool {
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeUpdate, "k1", ed25519.PublicKey(clone(pub))); err != nil {
		return false
	}
	return reg.Verify(trust.PurposeUpdate, "k1", clone(msg), clone(sig)) == nil
}

func stdlibEdVerify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

var edL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func leToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func intToLE(x *big.Int, n int) []byte {
	be := x.FillBytes(make([]byte, n))
	out := make([]byte, n)
	for i := range be {
		out[n-1-i] = be[i]
	}
	return out
}

func edSuite(r *Report, verify edVerify, f *ed25519File, extra func(r *Report, id string, pub, msg, sig []byte)) {
	var validSigs [][3][]byte
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if tc.Result == resValid && len(g.PublicKey.Pk) == 32 && len(tc.Sig) == 64 {
				validSigs = append(validSigs, [3][]byte{g.PublicKey.Pk, tc.Msg, tc.Sig})
			}
		}
	}
	for _, g := range f.TestGroups {
		pub := g.PublicKey.Pk
		for _, tc := range g.Tests {
			id := "tc" + itoa(tc.TcID)
			tc := tc
			r.Judge(id, tc.Result, tc.Flags, true, func() bool { return verify(pub, tc.Msg, tc.Sig) })
			if tc.Result != resValid || len(tc.Sig) != 64 {
				continue
			}
			edMutations(r, verify, id, pub, tc.Msg, tc.Sig, validSigs)
			if extra != nil {
				extra(r, id, pub, tc.Msg, tc.Sig)
			}
		}
	}
}

func edMutations(r *Report, verify edVerify, id string, pub, msg, sig []byte, others [][3][]byte) {
	rej := func(label string, p, m, s []byte) {
		if eq(p, pub) && eq(m, msg) && eq(s, sig) {
			return
		}
		r.RejectRef(id+" "+label, func() bool { return verify(p, m, s) }, func() bool { return stdlibEdVerify(p, m, s) })
	}
	for i := 0; i < 512; i++ {
		rej("sigbit"+itoa(i), pub, msg, flipBit(sig, i))
	}
	for i := 0; i < 256; i++ {
		rej("pubbit"+itoa(i), flipBit(pub, i), msg, sig)
	}
	for i := 0; i < len(msg)*8 && i < 256; i++ {
		rej("msgbit"+itoa(i), pub, flipBit(msg, i), sig)
	}
	rej("msg-ext", pub, append(clone(msg), 0), sig)
	if len(msg) > 0 {
		rej("msg-trunc", pub, msg[:len(msg)-1], sig)
		rej("msg-empty", pub, nil, sig)
	}
	for _, n := range []int{63, 32, 1, 0} {
		rej("sig-trunc"+itoa(n), pub, msg, sig[:n])
	}
	for _, n := range []int{1, 32, 64} {
		rej("sig-ext"+itoa(n), pub, msg, append(clone(sig), make([]byte, n)...))
		rej("sig-ext-ff"+itoa(n), pub, msg, append(clone(sig), repeat(0xff, n)...))
	}
	// malleable S forms: S+L, S+2L
	s := leToInt(sig[32:])
	for k := int64(1); k <= 2; k++ {
		s2 := new(big.Int).Add(s, new(big.Int).Mul(edL, big.NewInt(k)))
		if s2.BitLen() <= 256 {
			rej("S+"+itoa(int(k))+"L", pub, msg, append(clone(sig[:32]), intToLE(s2, 32)...))
		}
	}
	rej("RS-swapped", pub, msg, append(clone(sig[32:]), sig[:32]...))
	rej("zero-sig", pub, msg, make([]byte, 64))
	for _, o := range others {
		if !eq(o[0], pub) || !eq(o[1], msg) {
			rej("foreign-sig", pub, msg, o[2])
			break
		}
	}
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestEd25519TrustRegistry(t *testing.T) {
	var f ed25519File
	loadVectors(t, "ed25519_test.json", &f)
	r := newReport("trust/Ed25519", true)
	edSuite(r, keyorixEdVerify, &f, nil)
	t.Logf("%s: %s", r.Name, r.Summary())
	r.Err(t)
}

// Registry-level confusion: the right signature under the wrong key id,
// purpose or an unconfigured purpose must be refused.
func TestEd25519TrustRegistryScoping(t *testing.T) {
	var f ed25519File
	loadVectors(t, "ed25519_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if tc.Result != resValid || len(g.PublicKey.Pk) != 32 {
				continue
			}
			reg := trust.NewRegistry()
			if err := reg.Add(trust.PurposeUpdate, "k1", ed25519.PublicKey(clone(g.PublicKey.Pk))); err != nil {
				t.Fatal(err)
			}
			if err := reg.Verify(trust.PurposeUpdate, "k1", tc.Msg, tc.Sig); err != nil {
				t.Fatalf("tc%d: valid signature rejected: %v", tc.TcID, err)
			}
			if reg.Verify(trust.PurposeUpdate, "k2", tc.Msg, tc.Sig) == nil {
				t.Fatalf("tc%d: unknown key id accepted", tc.TcID)
			}
			if reg.Verify(trust.PurposeLicense, "k1", tc.Msg, tc.Sig) == nil {
				t.Fatalf("tc%d: wrong purpose accepted", tc.TcID)
			}
			if err := reg.Add(trust.PurposeLicense, "k1", ed25519.PublicKey(clone(g.PublicKey.Pk))); err == nil {
				t.Fatalf("tc%d: same key registered under two purposes", tc.TcID)
			}
			n++
		}
	}
	t.Logf("scoping checks: %d valid vectors", n)
}
