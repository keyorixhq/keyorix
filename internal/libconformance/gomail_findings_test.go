package libconformance

import (
	"bytes"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
)

// TestGoMailFindingLongHeaderWord pins finding LF1-GOMAIL-long-header-word in
// wneessen/go-mail v0.8.1: header values are folded only at spaces, so a subject holding
// one ASCII token longer than the 998-octet line limit (RFC 5322 §2.1.1) is written as a
// single over-long line. A relay may reject or re-wrap such a message. This test goes red
// when go-mail starts breaking such words (for example by RFC 2047-encoding them); then
// delete unbreakableHeaderLine's exception together with this test.
//
// What this does NOT verify: keyorix reachability. Notification titles and the
// setup-link subject interpolate names whose lengths keyorix bounds well below 990
// octets (see the LF1 report's trace); this only shows the library behaviour.
func TestGoMailFindingLongHeaderWord(t *testing.T) {
	m, err := newGoMailMsg("a@example.com", strings.Repeat("x", 1200), "b")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	longest := 0
	for line := range bytes.SplitSeq(buf.Bytes(), []byte("\r\n")) {
		longest = max(longest, len(line))
	}
	if longest <= 998 {
		t.Fatalf("longest line is now %d octets: finding fixed, remove the exception", longest)
	}
}

// TestQPFindingStaleCR pins finding LF1-QP-stale-cr in the Go standard library's
// mime/quotedprintable.Writer (go1.27.3): after a '\r', a byte the writer escapes as =XX
// does not clear its pending-CR flag, so the next '\n' is swallowed and two lines become
// one. go-mail's default text/plain encoding is this writer, so keyorix notification
// bodies pass through it. This test goes red when the standard library is fixed; then
// delete qpStaleCRLineBreaks together with this test.
func TestQPFindingStaleCR(t *testing.T) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write([]byte("a\r=\nb")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(quotedprintable.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "a\r\n=\r\nb" {
		t.Fatalf("quotedprintable now keeps the line break: finding fixed, remove qpStaleCRLineBreaks")
	}
	if string(got) != "a\r\n=b" || qpStaleCRLineBreaks("a\r=\nb") != "a\r\n=b" {
		t.Fatalf("decoded %q; model says %q", got, qpStaleCRLineBreaks("a\r=\nb"))
	}
}
