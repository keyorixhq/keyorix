package wycheproof

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption/aead"
	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

type aesGCMFile struct {
	TestGroups []struct {
		IvSize, KeySize, TagSize int
		Tests                    []struct {
			TcID                       int
			Flags                      []string
			Key, Iv, Aad, Msg, Ct, Tag wvec.Hex
			Result                     string
		}
	}
}

// aeadOpen is the operation under test: authenticated decryption. A nil error
// means the input was accepted.
type aeadOpen func(key, nonce, aad, ct, tag []byte) ([]byte, error)

// keyorixOpen drives internal/encryption/aead through its stored layout:
// ciphertext||tag in Data, the nonce base64 in the metadata.
func keyorixOpen(alwaysAAD bool) aeadOpen {
	return func(key, nonce, aad, ct, tag []byte) ([]byte, error) {
		es, err := aead.NewEncryptionService(clone(key))
		if err != nil {
			return nil, err
		}
		ed := &aead.EncryptedData{
			Data: append(clone(ct), tag...),
			Metadata: aead.EncryptionMetadata{
				Algorithm: aead.AESCipherSuite,
				Nonce:     base64.StdEncoding.EncodeToString(nonce),
			},
		}
		if len(aad) == 0 && !alwaysAAD {
			return es.Decrypt(ed)
		}
		return es.DecryptWithAAD(ed, aad)
	}
}

// stdlibOpen is the control: crypto/cipher AES-GCM with the same scope as
// Keyorix (256-bit key, 96-bit nonce, 128-bit tag).
func stdlibOpen(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 || len(tag) != 16 {
		return nil, errors.New("out of scope")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, append(clone(ct), tag...), aad)
}

func aeadSuite(r *Report, open aeadOpen, f *aesGCMFile) {
	call := func(key, nonce, aad, ct, tag []byte) bool {
		_, err := open(clone(key), clone(nonce), clone(aad), clone(ct), clone(tag))
		return err == nil
	}
	for _, g := range f.TestGroups {
		inScope := g.KeySize == 256 && g.IvSize == 96 && g.TagSize == 128
		for _, tc := range g.Tests {
			id := "tc" + itoa(tc.TcID)
			tc := tc
			scope := inScope
			if hasFlag(tc.Flags, "ZeroLengthIv") || hasFlag(tc.Flags, "SmallIv") || hasFlag(tc.Flags, "LongIv") {
				scope = false // by design: only 96-bit nonces
			}
			r.Judge(id, tc.Result, tc.Flags, scope, func() bool {
				pt, err := open(clone(tc.Key), clone(tc.Iv), clone(tc.Aad), clone(tc.Ct), clone(tc.Tag))
				if err != nil {
					return false
				}
				if tc.Result == resValid && !eq(pt, tc.Msg) {
					r.Failf("%s %s: accepted with wrong plaintext", r.Name, id)
					return false
				}
				return true
			})
			if scope && tc.Result == resValid {
				aeadMutations(r, call, id, tc.Key, tc.Iv, tc.Aad, tc.Ct, tc.Tag)
			}
		}
	}
}

func aeadMutations(r *Report, call func(key, nonce, aad, ct, tag []byte) bool, id string, key, nonce, aad, ct, tag []byte) {
	rej := func(label string, k, n, a, c, t []byte) {
		if eq(k, key) && eq(n, nonce) && eq(a, aad) && eq(c, ct) && eq(t, tag) {
			return
		}
		r.RejectRef(id+" "+label, func() bool { return call(k, n, a, c, t) }, func() bool { _, err := stdlibOpen(clone(k), clone(n), clone(a), clone(c), clone(t)); return err == nil })
	}
	for i := 0; i < len(tag)*8; i++ {
		rej("tagbit"+itoa(i), key, nonce, aad, ct, flipBit(tag, i))
	}
	for i := 0; i < len(nonce)*8; i++ {
		rej("noncebit"+itoa(i), key, flipBit(nonce, i), aad, ct, tag)
	}
	for i := 0; i < len(key)*8; i++ {
		rej("keybit"+itoa(i), flipBit(key, i), nonce, aad, ct, tag)
	}
	for i := 0; i < len(ct)*8 && i < 256*8; i++ {
		if i >= 16*8 && i%8 != 0 {
			continue // all bits of the first 16 bytes, then one bit per byte
		}
		rej("ctbit"+itoa(i), key, nonce, aad, flipBit(ct, i), tag)
	}
	for i := 0; i < len(aad)*8 && i < 256*8; i++ {
		if i >= 16*8 && i%8 != 0 {
			continue
		}
		rej("aadbit"+itoa(i), key, nonce, flipBit(aad, i), ct, tag)
	}
	// truncation of the tag (and then into the ciphertext), taken from the end
	whole := append(clone(ct), tag...)
	for k := 1; k <= 16 && k <= len(whole); k++ {
		short := whole[:len(whole)-k]
		rej("trunc-end"+itoa(k), key, nonce, aad, short, nil)
		if len(short) >= 16 {
			rej("trunc-end-asplit"+itoa(k), key, nonce, aad, short[:len(short)-16], short[len(short)-16:])
		}
	}
	rej("tag-short-only", key, nonce, aad, ct, tag[:12])
	rej("tag-empty", key, nonce, aad, ct, nil)
	if len(ct) > 0 {
		rej("drop-first-ct-byte", key, nonce, aad, ct[1:], tag)
	}
	rej("empty-data", key, nonce, aad, nil, nil)
	rej("zero-tag", key, nonce, aad, ct, make([]byte, 16))
	// extension
	for _, n := range []int{1, 16, 1024} {
		rej("ext-ct"+itoa(n), key, nonce, aad, append(clone(ct), make([]byte, n)...), tag)
		rej("ext-tag"+itoa(n), key, nonce, aad, ct, append(clone(tag), make([]byte, n)...))
	}
	// nonce lengths
	for _, bad := range [][]byte{nil, nonce[:1], nonce[:11], append(clone(nonce), 0), append(clone(nonce), nonce[:4]...), append(clone(nonce), nonce...)} {
		rej("nonce-len"+itoa(len(bad)), key, bad, aad, ct, tag)
	}
	rej("nonce-pad-16", key, append(clone(nonce), 0, 0, 0, 0), aad, ct, tag)
	// swaps
	rej("tag=padded-nonce", key, nonce, aad, ct, append(clone(nonce), 0, 0, 0, 0))
	rej("nonce=tag-prefix", key, tag[:12], aad, ct, tag)
	rej("tag-halves-swapped", key, nonce, aad, ct, append(clone(tag[8:]), tag[:8]...))
	if len(ct) >= 16 {
		rej("ct-tag-exchanged", key, nonce, aad, tag, ct[len(ct)-16:])
		rej("ct-tail-tag-exchanged", key, nonce, aad, append(clone(ct[:len(ct)-16]), tag...), ct[len(ct)-16:])
	}
	// aad
	if len(aad) == 0 {
		rej("add-aad", key, nonce, []byte{0}, ct, tag)
		rej("add-aad-nonce", key, nonce, nonce, ct, tag)
	} else {
		rej("drop-aad", key, nonce, nil, ct, tag)
		rej("ext-aad", key, nonce, append(clone(aad), 0), ct, tag)
		rej("trunc-aad", key, nonce, aad[:len(aad)-1], ct, tag)
		rej("aad=nonce", key, nonce, nonce, ct, tag)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestAEADKeyorixWrapper(t *testing.T) {
	var f aesGCMFile
	loadVectors(t, "aes_gcm_test.json", &f)
	for _, variant := range []struct {
		name string
		open aeadOpen
	}{{"aead/Decrypt", keyorixOpen(false)}, {"aead/DecryptWithAAD", keyorixOpen(true)}} {
		r := newReport(variant.name, variant.name == "aead/Decrypt")
		aeadSuite(r, variant.open, &f)
		t.Logf("%s: %s", r.Name, r.Summary())
		r.Err(t)
	}
}

// Encrypt side: what the wrapper seals must open under the standard library
// with the nonce it recorded, for every key/plaintext/AAD in the vectors.
func TestAEADKeyorixEncryptOpensUnderStdlib(t *testing.T) {
	var f aesGCMFile
	loadVectors(t, "aes_gcm_test.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		if g.KeySize != 256 {
			continue
		}
		for _, tc := range g.Tests {
			if tc.Result != resValid {
				continue
			}
			es, err := aead.NewEncryptionService(clone(tc.Key))
			if err != nil {
				t.Fatal(err)
			}
			var ed *aead.EncryptedData
			if len(tc.Aad) == 0 {
				ed, err = es.Encrypt(tc.Msg, "v1")
			} else {
				ed, err = es.EncryptWithAAD(tc.Msg, "v1", tc.Aad)
			}
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := base64.StdEncoding.DecodeString(ed.Metadata.Nonce)
			if err != nil || len(nonce) != 12 {
				t.Fatalf("tc%d: nonce %q: %v", tc.TcID, ed.Metadata.Nonce, err)
			}
			pt, err := stdlibOpen(tc.Key, nonce, tc.Aad, ed.Data[:len(ed.Data)-16], ed.Data[len(ed.Data)-16:])
			if err != nil || !eq(pt, tc.Msg) {
				t.Fatalf("tc%d: stdlib cannot open Keyorix ciphertext: %v", tc.TcID, err)
			}
			n++
		}
	}
	t.Logf("encrypt-side round trips: %d", n)
}

func TestAEADKeyorixRejectsOtherKeySizes(t *testing.T) {
	var f aesGCMFile
	loadVectors(t, "aes_gcm_test.json", &f)
	seen := map[int]bool{}
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if len(tc.Key) != 32 && !seen[len(tc.Key)] {
				seen[len(tc.Key)] = true
				if _, err := aead.NewEncryptionService(clone(tc.Key)); err == nil {
					t.Errorf("NewEncryptionService accepted a %d-byte key", len(tc.Key))
				}
			}
		}
	}
}
