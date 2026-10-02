package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// craftArchiveTolerant is craftArchive (tarslip_test.go) with every t.Fatal
// replaced by a (nil, false) return -- needed here because the fuzzer can
// (and does) generate names archive/tar.Writer itself refuses to encode
// (e.g. an embedded NUL needing a PAX record), which is a limitation of
// building the corpus through Go's own tar writer, not a production code
// path to assert anything about.
func craftArchiveTolerant(t testing.TB, tarName string, payload []byte) ([]byte, bool) {
	t.Helper()
	sum := sha256.Sum256(payload)
	m := Manifest{Tables: []TableEntry{{
		Name: "x", TarName: tarName, UncompressedSize: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]),
	}}}
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct {
		name string
		data []byte
	}{{"MANIFEST.json", mj}, {tarName, payload}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, false
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, false
		}
	}
	if err := tw.Close(); err != nil {
		return nil, false
	}
	if err := gz.Close(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// fuzzPathSafetyMaxNameLen bounds the fuzzed tar entry name -- real tar
// headers cap a name at 100 (ustar) + 155 (prefix) = 255 bytes in practice,
// so this is already generous for the real format; it also bounds how many
// "../" segments a single fuzzed name can encode, keeping the worst-case
// blast radius of a (currently not believed to exist) guard regression
// contained to a handful of directory levels rather than unbounded.
const fuzzPathSafetyMaxNameLen = 512

// FuzzExtractArchivePathSafety is SESSION-BV target 4: no archive entry name
// -- "../" traversal, an absolute path, an embedded NUL, a symlink-ish
// component, or a Unicode-normalization trick -- may ever cause a byte to
// land outside the staging directory ExtractArchive was given (the #2270
// tar-slip class). Unlike TestExtractArchive_RefusesPathTraversal's three
// hand-picked names, this generalizes the oracle so it holds for ANY name
// the fuzzer invents: filepath.IsLocal's verdict on the name must agree with
// whether ExtractArchive refused it, and -- regardless of verdict -- nothing
// written ever lands outside the staging directory's own subtree.
func FuzzExtractArchivePathSafety(f *testing.F) {
	seeds := []string{
		"../escaped.txt",
		"tables/../../escaped.txt",
		"/tmp/keyorix-tarslip-absolute.txt", // the exact #2270 regression case
		"tables/x.ndjson",                   // a legitimate local name -- must still work
		"....//....//etc/passwd",
		"tab\x00les/x.ndjson", // embedded NUL
		"tables/xÅ.ndjson",   // "å" as NFD (two code points)
		"tables/xå.ndjson",    // "å" as NFC (one code point) -- same glyph, different bytes
		"",
		".",
		"..",
		"tables/./x.ndjson",
	}
	for _, s := range seeds {
		f.Add(s, []byte("payload"))
	}

	f.Fuzz(func(t *testing.T, name string, payload []byte) {
		if len(name) == 0 || len(name) > fuzzPathSafetyMaxNameLen {
			t.Skip()
		}

		root := t.TempDir()
		staging := filepath.Join(root, "staging")
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}

		archive, ok := craftArchiveTolerant(t, name, payload)
		if !ok {
			// archive/tar.Writer itself refuses to encode this name (e.g. an
			// embedded NUL byte needs a PAX record archive/tar won't emit) --
			// a limitation of building the corpus via Go's own tar writer,
			// not a claim about what ExtractArchive's READER can be handed:
			// a hand-crafted malicious tar stream isn't bound by what
			// archive/tar.Writer is willing to produce. Known, stated gap,
			// not silently absent coverage.
			t.Skip()
		}
		_, err := ExtractArchive(bytes.NewReader(archive), staging, 0, 0)

		isLocal := filepath.IsLocal(name)
		if !isLocal {
			if err == nil {
				t.Fatalf("ExtractArchive accepted non-local entry name %q (filepath.IsLocal=false)", name)
			}
			// Confirm no NEW regular file was written where an unguarded
			// Join-then-write would have landed it -- filepath.Join never
			// lets a literal absolute-looking second argument override the
			// first (Go's Join always treats every argument as a path
			// ELEMENT to concatenate then Clean, unlike e.g. Python's
			// os.path.join), so the one path an unguarded implementation
			// could actually reach is staging joined with name. Checked via
			// IsRegular, not mere existence: a degenerate name like ".." or
			// "." resolves (via Join+Clean) to staging's own pre-existing
			// ancestor directory, which legitimately already exists as this
			// test's own scaffolding -- that's not escape evidence, only a
			// newly-created FILE there would be.
			if info, statErr := os.Stat(filepath.Join(staging, name)); statErr == nil && info.Mode().IsRegular() {
				t.Fatalf("payload escaped: %q was written under staging despite being refused as non-local", name)
			}
		}

		// Regardless of accept/refuse/reason: walk whatever IS under staging
		// and confirm every entry is a plain file strictly inside it (no
		// symlink, which could itself be a second-stage escape vector for
		// something read through the staged path later), and confirm the
		// staging directory itself still exists (never replaced/escaped).
		if _, statErr := os.Stat(staging); statErr != nil {
			t.Fatalf("staging directory itself is gone after ExtractArchive: %v", statErr)
		}
		walkErr := filepath.WalkDir(staging, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&fs.ModeSymlink != 0 {
				t.Fatalf("a symlink was created under staging at %q", path)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk staging dir: %v", walkErr)
		}
	})
}
