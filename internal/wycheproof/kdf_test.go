package wycheproof

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	xhkdf "golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/wycheproof/wvec"
)

func mustB64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

// ---- HKDF-SHA256 (library level, both call shapes Keyorix uses) ----

type hkdfFile struct {
	TestGroups []struct {
		KeySize int
		Tests   []struct {
			TcID            int
			Flags           []string
			Ikm, Salt, Info wvec.Hex
			Size            int
			Okm             wvec.Hex
			Result          string
		}
	}
}

func hkdfKey(ikm, salt, info []byte, size int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, string(info), size)
}

func hkdfReader(ikm, salt, info []byte, size int) ([]byte, error) {
	out := make([]byte, size)
	_, err := io.ReadFull(xhkdf.New(sha256.New, ikm, salt, info), out)
	return out, err
}

func TestHKDFSHA256(t *testing.T) {
	var f hkdfFile
	loadVectors(t, "hkdf_sha256_test.json", &f)
	for _, shape := range []struct {
		name string
		fn   func(ikm, salt, info []byte, size int) ([]byte, error)
	}{{"hkdf/Key", hkdfKey}, {"hkdf/New", hkdfReader}} {
		r := newReport(shape.name, false)
		for _, g := range f.TestGroups {
			for _, tc := range g.Tests {
				id := "tc" + itoa(tc.TcID)
				tc := tc
				r.Judge(id, tc.Result, tc.Flags, true, func() bool {
					out, err := shape.fn(clone(tc.Ikm), clone(tc.Salt), clone(tc.Info), tc.Size)
					if err != nil {
						return false
					}
					if tc.Result == resValid && !eq(out, tc.Okm) {
						r.Failf("%s %s: wrong output", r.Name, id)
						return false
					}
					return true
				})
				if tc.Result != resValid {
					continue
				}
				differs := func(label string, ikm, salt, info []byte) {
					r.Count("mutations", 1)
					out, err := shape.fn(ikm, salt, info, tc.Size)
					if err == nil && eq(out, tc.Okm) {
						r.Failf("%s %s: %s did not change the output", r.Name, id, label)
					}
				}
				for i := 0; i < len(tc.Ikm)*8 && i < 64; i++ {
					differs("ikm-bit"+itoa(i), flipBit(tc.Ikm, i), tc.Salt, tc.Info)
				}
				for i := 0; i < len(tc.Salt)*8 && i < 64; i++ {
					differs("salt-bit"+itoa(i), tc.Ikm, flipBit(tc.Salt, i), tc.Info)
				}
				if len(tc.Salt) == 0 {
					differs("salt-1byte", tc.Ikm, []byte{1}, tc.Info)
				}
				for i := 0; i < len(tc.Info)*8 && i < 64; i++ {
					differs("info-bit"+itoa(i), tc.Ikm, tc.Salt, flipBit(tc.Info, i))
				}
				differs("info-ext", tc.Ikm, tc.Salt, append(clone(tc.Info), 0))
				// output length: shorter output is a prefix of the longer one
				if tc.Size > 1 {
					short, err := shape.fn(tc.Ikm, tc.Salt, tc.Info, tc.Size-1)
					r.Count("mutations", 1)
					if err != nil || !eq(short, tc.Okm[:tc.Size-1]) {
						r.Failf("%s %s: prefix property broken", r.Name, id)
					}
				}
			}
		}
		t.Logf("%s: %s", r.Name, r.Summary())
		r.Err(t)
	}
}

// ---- PBKDF2-HMAC-SHA256 ----

type pbkdf2File struct {
	TestGroups []struct {
		Tests []struct {
			TcID           int
			Flags          []string
			Password, Salt wvec.Hex
			IterationCount int
			DkLen          int
			Dk             wvec.Hex
			Result         string
		}
	}
}

const pbkdf2IterCap = 100000

func TestPBKDF2SHA256(t *testing.T) {
	var f pbkdf2File
	loadVectors(t, "pbkdf2_hmacsha256_test.json", &f)
	r := newReport("pbkdf2", false)
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			id := "tc" + itoa(tc.TcID)
			tc := tc
			if tc.IterationCount > pbkdf2IterCap {
				r.Count("skipped_iterations_over_cap", 1)
				continue
			}
			r.Judge(id, tc.Result, tc.Flags, true, func() bool {
				out := pbkdf2.Key(clone(tc.Password), clone(tc.Salt), tc.IterationCount, tc.DkLen, sha256.New)
				if !eq(out, tc.Dk) {
					r.Failf("%s %s: library output differs", r.Name, id)
					return false
				}
				if tc.DkLen == 32 {
					// Keyorix's own wrapper for its 32-byte KEK derivation.
					if got := encryption.GenerateKEK(string(tc.Password), clone(tc.Salt), tc.IterationCount); !eq(got, tc.Dk) {
						r.Failf("%s %s: encryption.GenerateKEK differs", r.Name, id)
						return false
					}
					r.Count("generatekek", 1)
				}
				return true
			})
			if tc.Result != resValid || tc.IterationCount > 2000 {
				continue
			}
			differs := func(label string, pw, salt []byte, it int) {
				r.Count("mutations", 1)
				if eq(pbkdf2.Key(pw, salt, it, tc.DkLen, sha256.New), tc.Dk) {
					r.Failf("%s %s: %s did not change the output", r.Name, id, label)
				}
			}
			for i := 0; i < len(tc.Password)*8 && i < 64; i++ {
				differs("pw-bit"+itoa(i), flipBit(tc.Password, i), tc.Salt, tc.IterationCount)
			}
			for i := 0; i < len(tc.Salt)*8 && i < 64; i++ {
				differs("salt-bit"+itoa(i), tc.Password, flipBit(tc.Salt, i), tc.IterationCount)
			}
			differs("iter+1", tc.Password, tc.Salt, tc.IterationCount+1)
			if tc.IterationCount > 1 {
				differs("iter-1", tc.Password, tc.Salt, tc.IterationCount-1)
			}
		}
	}
	t.Logf("%s: %s", r.Name, r.Summary())
	r.Err(t)
}

// ---- HMAC-SHA256 with the comparison Keyorix uses (hmac.Equal) ----

type hmacFile struct {
	TestGroups []struct {
		KeySize, TagSize int
		Tests            []struct {
			TcID          int
			Flags         []string
			Key, Msg, Tag wvec.Hex
			Result        string
		}
	}
}

func hmacCheck(key, msg, tag []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	sum := m.Sum(nil)
	if len(tag) == 0 || len(tag) > len(sum) {
		return false
	}
	return hmac.Equal(sum[:len(tag)], tag)
}

func TestHMACSHA256(t *testing.T) {
	var f hmacFile
	loadVectors(t, "hmac_sha256_test.json", &f)
	r := newReport("hmac", false)
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			id := "tc" + itoa(tc.TcID)
			tc := tc
			full := g.TagSize == 256
			r.Judge(id, tc.Result, tc.Flags, true, func() bool { return hmacCheck(tc.Key, tc.Msg, tc.Tag) })
			if tc.Result != resValid || !full {
				continue
			}
			for i := 0; i < len(tc.Tag)*8; i++ {
				bad := flipBit(tc.Tag, i)
				r.Reject(id+" tagbit"+itoa(i), func() bool { return hmacCheck(tc.Key, tc.Msg, bad) })
			}
			r.Reject(id+" tag-ext", func() bool { return hmacCheck(tc.Key, tc.Msg, append(clone(tc.Tag), 0)) })
			r.Reject(id+" tag-empty", func() bool { return hmacCheck(tc.Key, tc.Msg, nil) })
			for i := 0; i < len(tc.Msg)*8 && i < 64; i++ {
				bad := flipBit(tc.Msg, i)
				r.Reject(id+" msgbit"+itoa(i), func() bool { return hmacCheck(tc.Key, bad, tc.Tag) })
			}
			for i := 0; i < len(tc.Key)*8 && i < 64; i++ {
				bad := flipBit(tc.Key, i)
				r.Reject(id+" keybit"+itoa(i), func() bool { return hmacCheck(bad, tc.Msg, tc.Tag) })
			}
		}
	}
	t.Logf("%s: %s", r.Name, r.Summary())
	r.Err(t)
}
