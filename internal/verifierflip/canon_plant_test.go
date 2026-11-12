package verifierflip_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption/aead"
	"github.com/keyorixhq/keyorix/internal/verifierflip"
	"github.com/keyorixhq/keyorix/pkg/bundleverify"
	"github.com/keyorixhq/keyorix/pkg/trust"
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

// TestCanonContract_BundleIgnoringComponentDigestIsDifferent: a bundle verifier
// that still walks the tar and enforces the entry set but no longer compares
// component digests returns the same manifest for changed components, so a
// Canon of manifest and signature alone reports those accepts as equivalent.
func TestCanonContract_BundleIgnoringComponentDigestIsDifferent(t *testing.T) {
	rep, err := verifierflip.Run(bundleTargetWith(t, verifyBundleWithoutDigests), verifierflip.Options{Seed: 1, SkipTiming: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Different == 0 || rep.Panics != 0 {
		t.Fatalf("planted defect not reported as ACCEPT-DIFFERENT: different=%d equiv=%d panics=%d", rep.Different, rep.Equivalent, rep.Panics)
	}
}

// verifyBundleWithoutDigests is bundleverify.Verify with the component sha256
// compare removed: signature, entry order, entry set and sizes are still checked.
func verifyBundleWithoutDigests(r io.Reader, reg *trust.KeyRegistry) (*bundleverify.Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	readEntry := func(want string) ([]byte, error) {
		h, err := tr.Next()
		if err != nil {
			return nil, err
		}
		if h.Name != want {
			return nil, fmt.Errorf("entry %q, want %q", h.Name, want)
		}
		return io.ReadAll(tr)
	}
	mb, err := readEntry("manifest.json")
	if err != nil {
		return nil, err
	}
	sig, err := readEntry("manifest.sig")
	if err != nil {
		return nil, err
	}
	var m bundleverify.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, err
	}
	if err := reg.Verify(trust.PurposeUpdate, m.KeyID, mb, sig); err != nil {
		return nil, err
	}
	sizes := make(map[string]int64, len(m.Components))
	for _, c := range m.Components {
		sizes[c.Path] = c.Size
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if want, ok := sizes[h.Name]; !ok || h.Size != want {
			return nil, fmt.Errorf("unlisted, duplicate or resized entry %q", h.Name)
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return nil, err
		}
		delete(sizes, h.Name)
	}
	if len(sizes) != 0 {
		return nil, fmt.Errorf("%d components missing", len(sizes))
	}
	return &m, nil
}
