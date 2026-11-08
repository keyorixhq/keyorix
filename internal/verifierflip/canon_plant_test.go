package verifierflip_test

import (
	"bytes"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption/aead"
	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

// Planted defects for the Target.Canon contract: a verifier that ignores part
// of the credential or tag must surface as ACCEPT-DIFFERENT. A Canon that
// reports only the user ID or the plaintext passes these defects silently.

func TestCanonContract_TokenIgnoringLastCharIsDifferent(t *testing.T) {
	for _, tg := range tokenTargets(t) {
		t.Run(tg.Name, func(t *testing.T) {
			verify, art := tg.Verify, tg.Artifact
			tg.Verify = func(b []byte) bool {
				if len(b) != len(art) {
					return verify(b)
				}
				return verify(append(bytes.Clone(b[:len(b)-1]), art[len(art)-1]))
			}
			rep, err := verifierflip.Run(tg, verifierflip.Options{Seed: 1, SkipTiming: true})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Different == 0 || rep.Panics != 0 {
				t.Fatalf("planted defect not reported as ACCEPT-DIFFERENT: different=%d equiv=%d panics=%d", rep.Different, rep.Equivalent, rep.Panics)
			}
		})
	}
}

func TestCanonContract_AEADIgnoringLastTagByteIsDifferent(t *testing.T) {
	svc, err := aead.NewEncryptionService(fixedKey("kek"))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("secret:42:v3")
	ed, err := svc.EncryptWithAAD([]byte("hunter2-plaintext-value"), "kek-1", aad)
	if err != nil {
		t.Fatal(err)
	}
	art, err := aead.SerializeEncryptedData(ed)
	if err != nil {
		t.Fatal(err)
	}
	open := func(d *aead.EncryptedData) ([]byte, error) {
		forged := *d
		forged.Data = bytes.Clone(d.Data)
		if len(forged.Data) == len(ed.Data) {
			forged.Data[len(forged.Data)-1] = ed.Data[len(ed.Data)-1]
		}
		return svc.DecryptWithAAD(&forged, aad)
	}
	tg := verifierflip.Target{
		Name: "aead-planted-ignores-last-tag-byte", Artifact: art,
		Verify: func(b []byte) bool {
			d, err := aead.DeserializeEncryptedData(b)
			if err != nil {
				return false
			}
			_, err = open(d)
			return err == nil
		},
		Canon: aeadCanon(open),
	}
	rep, err := verifierflip.Run(tg, verifierflip.Options{Seed: 1, SkipTiming: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Different == 0 {
		t.Fatalf("planted defect not reported as ACCEPT-DIFFERENT: equiv=%d", rep.Equivalent)
	}
}
