package canary

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func testCanary(hostile bool) Canary {
	return New("value", Secret, []byte("seed-1"), hostile)
}

func TestNewIsReplayableAndUnique(t *testing.T) {
	a, b := testCanary(false), testCanary(false)
	if a != b {
		t.Fatalf("same input gave different canaries: %q %q", a.Raw, b.Raw)
	}
	if c := New("value", Secret, []byte("seed-2"), false); c.Core == a.Core {
		t.Fatal("different seed gave the same core")
	}
	if c := New("other", Secret, []byte("seed-1"), false); c.Core == a.Core {
		t.Fatal("different label gave the same core")
	}
	if len(a.Core) != coreLen {
		t.Fatalf("core length %d", len(a.Core))
	}
}

func TestScanFindsEveryEncoding(t *testing.T) {
	for _, hostile := range []bool{false, true} {
		c := testCanary(hostile)
		s := NewScanner(c)
		for _, v := range c.Variants() {
			hay := append(append([]byte("prefix "), v.Bytes...), " suffix"...)
			if len(s.Scan("x", hay)) == 0 {
				t.Errorf("hostile=%v: variant %s not detected", hostile, v.Name)
			}
		}
	}
}

func TestScanFindsAnyFragmentOfEightBytes(t *testing.T) {
	c := testCanary(true)
	s := NewScanner(c)
	for n := MinWindow; n <= len(c.Core); n++ {
		for k := 0; k+n <= len(c.Core); k++ {
			frag := c.Core[k : k+n]
			if len(s.Scan("x", []byte("<<"+frag+">>"))) == 0 {
				t.Fatalf("fragment [%d:%d] not detected", k, k+n)
			}
			if len(s.Scan("x", []byte("<<"+hex.EncodeToString([]byte(frag))+">>"))) == 0 {
				t.Fatalf("hex of fragment [%d:%d] not detected", k, k+n)
			}
		}
	}
}

// The window claim in the Scanner doc comment: base64 of a fragment is found once
// the fragment spans three aligned groups, wherever it sits in the stream.
func TestScanFindsBase64Fragments(t *testing.T) {
	c := testCanary(false)
	s := NewScanner(c)
	const span = 9 + 2 // nine bytes plus the worst-case misalignment
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		for lead := range 3 {
			for k := 0; k+span <= len(c.Core); k++ {
				stream := append([]byte(strings.Repeat("-", lead)), c.Core[k:k+span]...)
				if len(s.Scan("x", []byte(e.EncodeToString(stream)))) == 0 {
					t.Fatalf("lead=%d k=%d: base64 fragment not detected", lead, k)
				}
			}
		}
	}
}

func TestScanRejectsShortFragmentsAndCleanData(t *testing.T) {
	c := testCanary(false)
	s := NewScanner(c)
	if hits := s.Scan("x", []byte("<<"+c.Core[:MinWindow-1]+">>")); len(hits) != 0 {
		t.Fatalf("a %d-byte fragment was reported: %v", MinWindow-1, hits)
	}
	// The fixed prefix is shared by every canary, so it must not count.
	if hits := s.Scan("x", []byte("kxfS-kxfS-kxfS-")); len(hits) != 0 {
		t.Fatalf("the shared prefix was reported: %v", hits)
	}
	other := New("other", Secret, []byte("seed-2"), false)
	if hits := s.Scan("x", []byte(other.Raw)); len(hits) != 0 {
		t.Fatalf("another canary was reported: %v", hits)
	}
}

func TestScanReportsTheFragmentOnlyWithoutAWholeHit(t *testing.T) {
	c := testCanary(false)
	s := NewScanner(c)
	if hits := s.Scan("x", []byte(c.Raw)); len(hits) == 0 || hits[len(hits)-1].Variant == "core-window" {
		t.Fatalf("whole value reported as fragment: %v", hits)
	}
	hits := s.Scan("x", []byte(c.Core[3:15]))
	if len(hits) != 1 || hits[0].Variant != "core-window" {
		t.Fatalf("truncated value: %v", hits)
	}
}

func TestSnippetMasksTheMatch(t *testing.T) {
	c := testCanary(false)
	hits := NewScanner(c).Scan("x", []byte("before "+c.Raw+" after"))
	if len(hits) == 0 {
		t.Fatal("no hit")
	}
	for _, h := range hits {
		if strings.Contains(h.Snippet, c.Core) {
			t.Fatalf("snippet shows the core: %s", h.Snippet)
		}
	}
}

func TestAllowlistMatchesExactlyAndTracksUse(t *testing.T) {
	a := NewAllowlist(Rule{ID: "reveal", Channel: "body", Origin: "GET /value", Label: "v", Why: "reveal"}, Rule{ID: "unused", Channel: "log", Why: "x"})
	if id := a.Permit(Hit{Channel: "body", Label: "v"}, "GET /value"); id != "reveal" {
		t.Fatalf("permit: %q", id)
	}
	for _, h := range []struct {
		h      Hit
		origin string
	}{
		{Hit{Channel: "body", Label: "v"}, "GET /other"},
		{Hit{Channel: "body", Label: "w"}, "GET /value"},
		{Hit{Channel: "header", Label: "v"}, "GET /value"},
	} {
		if id := a.Permit(h.h, h.origin); id != "" {
			t.Fatalf("%v at %s permitted by %s", h.h, h.origin, id)
		}
	}
	if un := a.Unused(); len(un) != 1 || un[0] != "unused" {
		t.Fatalf("unused: %v", un)
	}
}

func TestCaptureDrainsAndScans(t *testing.T) {
	c := NewCapture()
	fmt.Fprint(c.Writer("a"), "one")
	c.Record("b", []byte("two"))
	got := c.Drain()
	if len(got) != 2 || got[0].Channel != "a" || string(got[0].Data) != "one" || got[1].Channel != "b" {
		t.Fatalf("drain: %+v", got)
	}
	if again := c.Drain(); len(again) != 0 {
		t.Fatalf("second drain kept data: %+v", again)
	}
}

func TestInstallLogsCapturesBothLoggers(t *testing.T) {
	c := NewCapture()
	restore := c.InstallLogs()
	log.Print("via-log")
	slog.Info("via-slog")
	restore()
	got := map[string]string{}
	for _, o := range c.Drain() {
		got[o.Channel] = string(o.Data)
	}
	if !strings.Contains(got[ChannelLog], "via-log") || !strings.Contains(got[ChannelSlog], "via-slog") {
		t.Fatalf("captured: %v", got)
	}
}

func TestInstallStdioSeesEveryWriteWithoutWaiting(t *testing.T) {
	c := NewCapture()
	restore, err := c.InstallStdio(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	fmt.Fprint(os.Stdout, "out-1")
	fmt.Fprint(os.Stderr, "err-1")
	first := c.Drain()
	fmt.Fprint(os.Stdout, "out-2")
	second := c.Drain()
	if len(first) != 2 || string(first[0].Data) != "err-1" || string(first[1].Data) != "out-1" {
		t.Fatalf("first drain: %+v", first)
	}
	if len(second) != 1 || string(second[0].Data) != "out-2" {
		t.Fatalf("second drain: %+v", second)
	}
}
