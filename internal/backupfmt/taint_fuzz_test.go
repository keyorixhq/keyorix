//go:build taintoverlay

package backupfmt

// Input-to-sink taint harness for backup restore extraction (see
// internal/fuzzutil/taint). Every name the archive's manifest controls (table
// name, tar name, key-file original path and tar name) carries the marker, with
// "../" and absolute forms. Contract: extraction may create files only inside
// the staging directory; a path flow outside it, or any command/host/query
// flow, is unexpected.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintExtractArchive ./internal/backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

func FuzzTaintExtractArchive(f *testing.F) {
	f.Add("a", "b", "c", "d")
	f.Fuzz(func(t *testing.T, tableName, tarName, keyOrig, keyTar string) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		defer taint.Check(t.Fatalf)
		staging := t.TempDir()
		taint.Allow(taint.Rule{Class: taint.Path, Root: staging, Why: "extraction confined to the staging dir"})

		payload := []byte("x")
		sum := sha256.Sum256(payload)
		h := hex.EncodeToString(sum[:])
		tn, kt := taint.PathStr(tarName), taint.PathStr(keyTar)
		m := Manifest{
			Tables:   []TableEntry{{Name: taint.Str(tableName), TarName: tn, UncompressedSize: 1, SHA256: h}},
			KeyFiles: []KeyFileEntry{{OriginalPath: taint.PathStr(keyOrig), TarName: kt, Size: 1, SHA256: h}},
		}
		mj, err := json.Marshal(m)
		if err != nil {
			t.Skip(err)
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, e := range []struct {
			name string
			data []byte
		}{{"MANIFEST.json", mj}, {tn, payload}, {kt, payload}} {
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
				t.Skip(err)
			}
			_, _ = tw.Write(e.data)
		}
		_ = tw.Close()
		_ = gz.Close()
		_, _ = ExtractArchive(bytes.NewReader(buf.Bytes()), staging, 1<<12, 1<<14)
	})
}
