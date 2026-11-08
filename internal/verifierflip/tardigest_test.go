package verifierflip_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

func TestGzipTarDigest(t *testing.T) {
	archive := func(entries ...[2]string) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, e := range entries {
			if err := tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o600, Size: int64(len(e[1]))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(e[1])); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	base := archive([2]string{"m", "1"}, [2]string{"a", "content"})
	want := verifierflip.GzipTarDigest(base)
	if strings.HasPrefix(want, "unreadable") {
		t.Fatalf("baseline unreadable: %s", want)
	}
	if got := verifierflip.GzipTarDigest(append(bytes.Clone(base), "trailing"...)); got != want {
		t.Errorf("bytes after the gzip stream changed the digest")
	}
	for name, other := range map[string][]byte{
		"content":  archive([2]string{"m", "1"}, [2]string{"a", "CONTENT"}),
		"name":     archive([2]string{"m", "1"}, [2]string{"b", "content"}),
		"dropped":  archive([2]string{"m", "1"}),
		"boundary": archive([2]string{"m", "1a"}, [2]string{"", "content"}),
	} {
		if verifierflip.GzipTarDigest(other) == want {
			t.Errorf("%s: digest did not change", name)
		}
	}
	if got := verifierflip.GzipTarDigest(base[:len(base)/2]); !strings.HasPrefix(got, "unreadable") {
		t.Errorf("truncated archive digest = %q, want unreadable", got)
	}
	skipped := verifierflip.GzipTarDigest(archive([2]string{"m", "2"}, [2]string{"a", "content"}), "m")
	if skipped != verifierflip.GzipTarDigest(base, "m") {
		t.Errorf("a skipped entry changed the digest")
	}
}
