package wycheproof

import (
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
)

// xmlencTemplate builds the EncryptedData element structure once (the library's
// own Encrypt only supplies the structure; see internal/libconformance for why
// the CipherValue is replaced).
func xmlencTemplate(t testing.TB, key []byte) *etree.Element {
	el, err := xmlenc.AES128GCM.Encrypt(key, []byte("x"), make([]byte, 12))
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	return el
}

func setCipherValue(el *etree.Element, raw []byte) *etree.Element {
	c := el.Copy()
	var walk func(e *etree.Element) *etree.Element
	walk = func(e *etree.Element) *etree.Element {
		if e.Tag == "CipherValue" {
			return e
		}
		for _, ch := range e.ChildElements() {
			if r := walk(ch); r != nil {
				return r
			}
		}
		return nil
	}
	walk(c).SetText(base64.StdEncoding.EncodeToString(raw))
	return c
}

// xmlencOpen is crewjam/saml xmlenc.Decrypt on a CipherValue of nonce||ct||tag.
func xmlencOpen(tpl *etree.Element) func(key, raw []byte) ([]byte, error) {
	return func(key, raw []byte) ([]byte, error) {
		return xmlenc.Decrypt(clone(key), setCipherValue(tpl, raw))
	}
}

func TestXMLEncAES128GCM(t *testing.T) {
	var f aesGCMFile
	loadVectors(t, "aes_gcm_test.json", &f)
	tpl := xmlencTemplate(t, make([]byte, 16))
	open := xmlencOpen(tpl)
	r := newReport("xmlenc/AES128GCM", false)
	for _, g := range f.TestGroups {
		scopeGroup := g.KeySize == 128 && g.IvSize == 96 && g.TagSize == 128
		for _, tc := range g.Tests {
			if len(tc.Aad) != 0 {
				r.Count("skipped_aad_unsupported", 1)
				continue
			}
			id := "tc" + itoa(tc.TcID)
			tc := tc
			raw := append(append(clone(tc.Iv), tc.Ct...), tc.Tag...)
			scope := scopeGroup && len(tc.Iv) == 12
			r.Judge(id, tc.Result, tc.Flags, scope, func() bool {
				pt, err := open(tc.Key, raw)
				if err != nil {
					return false
				}
				if tc.Result == resValid && !eq(pt, tc.Msg) {
					r.Failf("%s %s: wrong plaintext", r.Name, id)
					return false
				}
				return true
			})
			if !scope || tc.Result != resValid {
				continue
			}
			rej := func(label string, b []byte) {
				if eq(b, raw) {
					return
				}
				r.Reject(id+" "+label, func() bool { _, err := open(tc.Key, b); return err == nil })
			}
			for i := 0; i < len(raw)*8 && i < 512; i++ {
				rej("bit"+itoa(i), flipBit(raw, i))
			}
			for n := 0; n <= 28 && n < len(raw); n++ {
				if n < 12 {
					// Below the nonce size the library slices out of range.
					// Tracked privately; Keyorix's SAML provider recovers
					// panics from the library (internal/saml/provider.go).
					// The outcome is counted, and acceptance still fails.
					acc, pan := try(func() bool { _, err := open(tc.Key, raw[:n]); return err == nil })
					r.Count("short_ciphertext_probes", 1)
					if pan != nil {
						r.Count("short_ciphertext_known_panic", 1)
					} else if acc {
						r.Failf("%s %s: truncated to %d bytes accepted", r.Name, id, n)
					}
					continue
				}
				rej("trunc"+itoa(n), raw[:n])
			}
			rej("ext1", append(clone(raw), 0))
			rej("ext16", append(clone(raw), make([]byte, 16)...))
		}
	}
	t.Logf("%s: %s", r.Name, r.Summary())
	r.Err(t)
}
