package crypto

// LIB-FUZZ-2 target 1b: google/go-tpm structure decoding behind
// TPMKeyProvider (internal/crypto/tpm_provider.go).
//
// Inventory. The sealed KEK blob is a local file under baseDir (the
// wrapped_key_path of the tpm provider), read by KEK() at every start. Whoever can
// write that file already controls the key directory, so the realistic hostile
// producers are a restored backup or a copied key directory from another host:
// KEK() runs encoding/json over it, then go-tpm's tpm2.Unmarshal over the
// TPM2B_PUBLIC and TPM2B_PRIVATE inside, all before it talks to the TPM. The
// risks that are keyorix's own are (1) a corrupt blob must never be mistaken for
// "no blob yet" (generateAndSeal would persist a fresh KEK over the real one,
// orphaning every DEK wrapped under it), (2) the decode must precede the TPM
// open and never panic or balloon, and (3) nothing may be written beside the
// blob.
//
// There is no TPM in the harness: the opener always fails, which is what makes
// "KEK() returned a key" an unconditional bug.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

var errNoTPM = errors.New("harness: no TPM")

func sealedBlobSeed(tb testing.TB) []byte {
	tb.Helper()
	pub := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true,
		},
	})
	priv := tpm2.TPM2BPrivate{Buffer: bytes.Repeat([]byte{0xA5}, 80)}
	b, err := json.Marshal(tpmSealedBlob{Public: tpm2.Marshal(pub), Private: tpm2.Marshal(priv)})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func dirState(tb testing.TB, dir string) map[string]string {
	tb.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			tb.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// checkSealedBlobRun is the oracle for one KEK() call over a stored blob. opens
// is how many times the TPM was opened.
func checkSealedBlobRun(stored []byte, kek []byte, err error, opens int, before, after map[string]string) error {
	var blob tpmSealedBlob
	jsonOK := json.Unmarshal(stored, &blob) == nil
	decodeOK := false
	if jsonOK {
		_, e1 := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
		_, e2 := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob.Private)
		decodeOK = e1 == nil && e2 == nil
	}
	switch {
	case err == nil || kek != nil:
		return errors.New("KEK() produced a key from a blob with no TPM behind it")
	case opens > 1:
		return errors.New("TPM opened more than once for one KEK() call")
	case decodeOK != (opens == 1):
		return errors.New("TPM opened for a blob that does not decode, or not opened for one that does")
	case !reflect.DeepEqual(before, after):
		return errors.New("KEK() changed the key directory (a corrupt blob must never be regenerated over)")
	}
	return nil
}

func FuzzTPMSealedBlob(f *testing.F) {
	seed := sealedBlobSeed(f)
	f.Add(seed)
	f.Add([]byte(`{"public":"","private":""}`))
	f.Add([]byte(`{"public":"AAA=","private":"AAA="}`))
	f.Add([]byte(`null`))
	f.Add([]byte{})
	f.Add(seed[:len(seed)/2])
	f.Fuzz(func(t *testing.T, stored []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "kek.tpm"), stored, 0o600); err != nil {
			t.Fatal(err)
		}
		before := dirState(t, dir)
		opens := 0
		p := NewTPMKeyProvider("", dir, "kek.tpm")
		p.open = func() (transport.TPMCloser, error) { opens++; return nil, errNoTPM }
		var (
			kek []byte
			err error
		)
		fuzzutil.Guard(t.Fatalf, "TPMKeyProvider.KEK", func() { kek, err = p.KEK() })
		if oerr := checkSealedBlobRun(stored, kek, err, opens, before, dirState(t, dir)); oerr != nil {
			t.Fatal(oerr)
		}
	})
}

// TestTPMSealedBlobOracle_RedProof: the oracle names each planted fault.
func TestTPMSealedBlobOracle_RedProof(t *testing.T) {
	seed := sealedBlobSeed(t)
	same := map[string]string{"kek.tpm": string(seed)}
	changed := map[string]string{"kek.tpm": "regenerated"}
	extra := map[string]string{"kek.tpm": string(seed), "kek.tpm.tmp": "x"}
	good := func(kek []byte, err error, opens int, b, a map[string]string) error {
		return checkSealedBlobRun(seed, kek, err, opens, b, a)
	}
	// The unplanted run: seed decodes, TPM opened once, error returned, dir untouched.
	if err := good(nil, errNoTPM, 1, same, same); err != nil {
		t.Fatalf("oracle rejects a correct run: %v", err)
	}
	for name, run := range map[string]func() error{
		"key produced without a TPM":       func() error { return good(make([]byte, 32), nil, 1, same, same) },
		"corrupt blob regenerated":         func() error { return good(nil, errNoTPM, 1, same, changed) },
		"stray file left beside the blob":  func() error { return good(nil, errNoTPM, 1, same, extra) },
		"TPM opened before decode":         func() error { return checkSealedBlobRun([]byte(`{"public":"AAUB"}`), nil, errNoTPM, 1, same, same) },
		"decodable blob never reached TPM": func() error { return good(nil, errNoTPM, 0, same, same) },
		"TPM opened twice":                 func() error { return good(nil, errNoTPM, 2, same, same) },
	} {
		if run() == nil {
			t.Errorf("oracle missed planted fault %q", name)
		}
	}
}

// FuzzGoTPMStructures: tpm2.Unmarshal of every structure keyorix or go-webauthn
// feeds untrusted bytes to must not panic or balloon, and a structure that
// decoded must re-marshal to a fixpoint (Marshal(Unmarshal(Marshal(v))) ==
// Marshal(v)): a decoder that accepts what the encoder cannot reproduce hands
// downstream code a value that no TPM could have produced.
func FuzzGoTPMStructures(f *testing.F) {
	seed := sealedBlobSeed(f)
	var blob tpmSealedBlob
	if err := json.Unmarshal(seed, &blob); err != nil {
		f.Fatal(err)
	}
	for k := range 5 {
		f.Add(uint8(k), blob.Public)
		f.Add(uint8(k), blob.Private)
	}
	fixpoint := func(name string, b []byte, dec func([]byte) (any, error)) error {
		v, err := dec(b)
		if err != nil {
			return nil
		}
		m1 := marshalAny(v)
		v2, err := dec(m1)
		if err != nil {
			return errors.New(name + ": decoded value does not decode again after Marshal: " + err.Error())
		}
		if m2 := marshalAny(v2); !bytes.Equal(m1, m2) {
			return errors.New(name + ": Marshal is not a fixpoint of Unmarshal")
		}
		return nil
	}
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		decs := []struct {
			name string
			dec  func([]byte) (any, error)
		}{
			{"TPMTPublic", func(b []byte) (any, error) { return tpm2.Unmarshal[tpm2.TPMTPublic](b) }},
			{"TPMSAttest", func(b []byte) (any, error) { return tpm2.Unmarshal[tpm2.TPMSAttest](b) }},
			{"TPM2BPublic", func(b []byte) (any, error) { return tpm2.Unmarshal[tpm2.TPM2BPublic](b) }},
			{"TPM2BPrivate", func(b []byte) (any, error) { return tpm2.Unmarshal[tpm2.TPM2BPrivate](b) }},
			{"TPMTSignature", func(b []byte) (any, error) { return tpm2.Unmarshal[tpm2.TPMTSignature](b) }},
		}
		d := decs[int(which)%len(decs)]
		var err error
		fuzzutil.Guard(t.Fatalf, "tpm2.Unmarshal "+d.name, func() { err = fixpoint(d.name, b, d.dec) })
		if err != nil {
			t.Fatal(err)
		}
	})
}

// marshalAny marshals a value returned by tpm2.Unmarshal (a pointer to a TPM type).
func marshalAny(v any) []byte {
	switch x := v.(type) {
	case *tpm2.TPMTPublic:
		return tpm2.Marshal(x)
	case *tpm2.TPMSAttest:
		return tpm2.Marshal(x)
	case *tpm2.TPM2BPublic:
		return tpm2.Marshal(x)
	case *tpm2.TPM2BPrivate:
		return tpm2.Marshal(x)
	case *tpm2.TPMTSignature:
		return tpm2.Marshal(x)
	}
	panic("marshalAny: unhandled type")
}
