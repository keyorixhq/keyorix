package netutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// feedAll runs the scanner over the stream split at the given chunk sizes.
func feedChunks(l RESPLimits, stream []byte, chunks []int) error {
	s := newRESPScanner(l)
	for _, c := range chunks {
		if c > len(stream) {
			c = len(stream)
		}
		if err := s.feed(stream[:c]); err != nil {
			return err
		}
		stream = stream[c:]
	}
	return s.feed(stream)
}

func TestRESPScannerVerdicts(t *testing.T) {
	big := strconv.Itoa(1 << 30)
	for _, tc := range []struct {
		name string
		in   string
		bad  bool
	}{
		{"simple string", "+OK\r\n", false},
		{"error", "-ERR nope\r\n", false},
		{"integer", ":123\r\n", false},
		{"bulk", "$5\r\nhello\r\n", false},
		{"bulk body containing a header-looking line", "$13\r\n$999999999999\r\n", false},
		{"bulk over-declared but within budget", "$4096\r\nshort\r\n", false},
		{"null bulk", "$-1\r\n", false},
		{"null array", "*-1\r\n", false},
		{"array", "*2\r\n:1\r\n:2\r\n", false},
		{"nested arrays", "*2\r\n*1\r\n:1\r\n*1\r\n:2\r\n", false},
		{"resp3 map", "%1\r\n+k\r\n+v\r\n", false},
		{"attribute then value", "|1\r\n+a\r\n+b\r\n+OK\r\n", false},
		{"push", ">3\r\n+pubsub\r\n+ch\r\n+hi\r\n", false},
		{"verbatim", "=15\r\ntxt:Some string\r\n", false},
		{"blob error", "!21\r\nSYNTAX invalid syntax\r\n", false},
		{"double bool null bignum", ",3.14\r\n#t\r\n_\r\n(12345678901234567890\r\n", false},
		{"two replies back to back", "+OK\r\n$5\r\nhello\r\n", false},

		{"huge bulk", "$" + big + "\r\nshort\r\n", true},
		{"huge array", "*100000000\r\n:1\r\n", true},
		{"huge map", "%50000000\r\n+k\r\n+v\r\n", true},
		{"huge set", "~100000000\r\n", true},
		{"huge push", ">100000000\r\n", true},
		{"huge attribute", "|50000000\r\n", true},
		{"huge verbatim", "=" + big + "\r\n", true},
		{"huge blob error", "!" + big + "\r\n", true},
		{"max int64", "$9223372036854775807\r\n", true},
		{"overflows int64", "$99999999999999999999999\r\n", true},
		{"huge header after a normal reply", "+OK\r\n*100000000\r\n", true},
		{"huge header nested in an array", "*2\r\n:1\r\n$" + big + "\r\n", true},
		{"signed plus", "$+" + big + "\r\n", true},
		{"unknown type byte", "?5\r\n", true},
		{"malformed number", "$5x\r\n", true},
		{"empty number", "$\r\n", true},
		{"CR without LF", "$5\rX", true},
		{"negative below -1", "$-2\r\n", true},
		{"line over the cap", "+" + strings.Repeat("a", 100) + "\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := RESPLimits{MaxDeclaredBytes: 1 << 20, MaxLineBytes: 64}
			err := feedChunks(l, []byte(tc.in), nil)
			if (err != nil) != tc.bad {
				t.Fatalf("verdict for %q: err=%v, want violation=%v", tc.in, err, tc.bad)
			}
			if err != nil && !errors.Is(err, ErrRESPLimit) {
				t.Fatalf("error %v does not match ErrRESPLimit", err)
			}
			// Same verdict one byte at a time: header and body boundaries can fall
			// anywhere across reads.
			ones := make([]int, len(tc.in))
			for i := range ones {
				ones[i] = 1
			}
			if err2 := feedChunks(l, []byte(tc.in), ones); (err2 != nil) != tc.bad {
				t.Fatalf("byte-at-a-time verdict differs: err=%v, want violation=%v", err2, tc.bad)
			}
		})
	}
}

// The budget is per window: several moderate announcements add up, and a write
// (a new command) starts a fresh window.
func TestRESPScannerWindowBudget(t *testing.T) {
	l := RESPLimits{MaxDeclaredBytes: 1000}
	s := newRESPScanner(l)
	if err := s.feed([]byte("*40\r\n")); err != nil { // 40*16 = 640
		t.Fatalf("first announcement: %v", err)
	}
	if err := s.feed([]byte(strings.Repeat(":1\r\n", 40))); err != nil {
		t.Fatalf("elements: %v", err)
	}
	if err := s.feed([]byte("*40\r\n")); err == nil { // 640 + 640 > 1000
		t.Fatal("second announcement in the same window should exceed the budget")
	}
	s = newRESPScanner(l)
	_ = s.feed([]byte("*40\r\n" + strings.Repeat(":1\r\n", 40)))
	s.resetWindow()
	if err := s.feed([]byte("*40\r\n")); err != nil {
		t.Fatalf("after resetWindow the same announcement must pass: %v", err)
	}
}

// refViolation is an independent, whole-buffer reference for the scanner's verdict:
// it reads line by line the way a RESP client does instead of byte by byte.
func refViolation(l RESPLimits, buf []byte) bool {
	l = l.withDefaults()
	var declared int64
	for len(buf) > 0 {
		typ := buf[0]
		nl := bytes.IndexByte(buf, '\n')
		switch typ {
		case '+', '-', ':', ',', '_', '#', '(':
			if nl < 0 {
				return len(buf) > l.MaxLineBytes
			}
			if nl > l.MaxLineBytes {
				return true
			}
			buf = buf[nl+1:]
		case '$', '=', '!', '*', '~', '>', '%', '|':
			if nl < 0 {
				// incomplete header: only malformed or oversized content is a verdict
				return refPartialBad(buf[1:])
			}
			line := buf[1:nl]
			if len(line) < 2 || line[len(line)-1] != '\r' {
				return true
			}
			num := string(line[:len(line)-1])
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange && !strings.HasPrefix(num, "-") {
					return true
				}
				return true
			}
			if n < -1 {
				return true
			}
			buf = buf[nl+1:]
			if n < 0 {
				continue
			}
			var w int64 = 64
			switch typ {
			case '$', '=', '!':
				w = 1
			case '*', '~', '>':
				w = 16
			}
			if n > l.MaxDeclaredBytes/w || declared > l.MaxDeclaredBytes-n*w {
				return true
			}
			declared += n * w
			if w == 1 {
				if int64(len(buf)) <= n+2 {
					return false
				}
				buf = buf[n+2:]
			}
		default:
			return true
		}
	}
	return false
}

// refPartialBad reports whether an incomplete header (no LF yet) is already a
// violation under the scanner's character-by-character rules.
func refPartialBad(rest []byte) bool {
	nd := 0
	sign := false
	for i, b := range rest {
		switch {
		case b >= '0' && b <= '9':
			nd++
		case (b == '-' || b == '+') && !sign && nd == 0:
			sign = true
		case b == '\r' && nd > 0:
			return i != len(rest)-1 // anything after CR must be LF, and LF would have ended the line
		default:
			return true
		}
	}
	return false
}

func TestRESPScannerMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	l := RESPLimits{MaxDeclaredBytes: 4096, MaxLineBytes: 32}
	frags := []string{"+OK\r\n", "-ERR x\r\n", ":1\r\n", "$3\r\nabc\r\n", "$0\r\n\r\n", "$-1\r\n", "*2\r\n", "*0\r\n", "%1\r\n",
		"~1\r\n", ">1\r\n", "|1\r\n", "=7\r\ntxt:abc\r\n", "!3\r\nERR\r\n", "$100\r\n", "*300\r\n", "$99999\r\n", "%99\r\n", "_\r\n",
		",1.5\r\n", "#t\r\n", "$5\r\n$9\r\n", "?\r\n", "$x\r\n", "$-2\r\n", "$\r\n"}
	for iter := 0; iter < 20000; iter++ {
		var b bytes.Buffer
		for i, n := 0, 1+rng.Intn(6); i < n; i++ {
			b.WriteString(frags[rng.Intn(len(frags))])
		}
		stream := b.Bytes()
		got := feedChunks(l, stream, nil) != nil
		want := refViolation(l, stream)
		if got != want {
			t.Fatalf("scanner=%v reference=%v for %q", got, want, stream)
		}
	}
}

// FuzzRESPScannerChunking: the verdict must not depend on how the stream is split
// across reads, and must agree with the whole-buffer reference.
func FuzzRESPScannerChunking(f *testing.F) {
	f.Add([]byte("$5\r\nhello\r\n"), uint8(3))
	f.Add([]byte("*2\r\n:1\r\n:2\r\n"), uint8(1))
	f.Add([]byte("$99999999\r\nshort\r\n"), uint8(2))
	f.Add([]byte("+OK\r\n$-1\r\n%1\r\n+k\r\n+v\r\n"), uint8(5))
	f.Fuzz(func(t *testing.T, stream []byte, step uint8) {
		l := RESPLimits{MaxDeclaredBytes: 1 << 16, MaxLineBytes: 64}
		whole := feedChunks(l, stream, nil) != nil
		var chunks []int
		st := int(step)%7 + 1
		for rem := len(stream); rem > 0; rem -= st {
			chunks = append(chunks, st)
		}
		if split := feedChunks(l, stream, chunks) != nil; split != whole {
			t.Fatalf("verdict depends on chunking (step %d): whole=%v split=%v for %q", st, whole, split, stream)
		}
		if ref := refViolation(l, stream); ref != whole {
			t.Fatalf("scanner=%v reference=%v for %q", whole, ref, stream)
		}
	})
}

// --- connection wrapper --------------------------------------------------------

func guardedPipe(t *testing.T, lim RESPLimits) (client net.Conn, server net.Conn) {
	t.Helper()
	cs, ss := net.Pipe()
	next := func(context.Context, string, string) (net.Conn, error) { return cs, nil }
	c, err := RESPGuardDialer(next, lim)(context.Background(), "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = ss.Close() })
	return c, ss
}

func TestRESPGuardConnPassesBenignStreamUnchanged(t *testing.T) {
	c, srv := guardedPipe(t, RESPLimits{})
	want := []byte("+OK\r\n$5\r\nhello\r\n*2\r\n:1\r\n:2\r\n")
	go func() { _, _ = srv.Write(want); _ = srv.Close() }()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("guard altered a benign stream: got %q want %q", got, want)
	}
}

func TestRESPGuardConnRejectsOversizedHeaderAndWithholdsIt(t *testing.T) {
	c, srv := guardedPipe(t, RESPLimits{})
	go func() { _, _ = srv.Write([]byte("*100000000\r\n:1\r\n")) }()
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n != 0 || !errors.Is(err, ErrRESPLimit) {
		t.Fatalf("Read = (%d, %v), want (0, ErrRESPLimit): the violating header must not reach the client", n, err)
	}
	if _, err := c.Read(buf); !errors.Is(err, ErrRESPLimit) {
		t.Fatalf("a later Read must keep returning the error, got %v", err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := srv.Write([]byte("x")); err == nil {
		t.Fatal("the guard must close the underlying connection on a violation")
	}
}

func TestRESPGuardConnHeaderSplitAcrossReads(t *testing.T) {
	c, srv := guardedPipe(t, RESPLimits{})
	go func() {
		_, _ = srv.Write([]byte("$99999"))
		time.Sleep(20 * time.Millisecond)
		_, _ = srv.Write([]byte("99999\r\nshort\r\n"))
	}()
	buf := make([]byte, 64)
	var err error
	for i := 0; i < 3 && err == nil; i++ {
		_, err = c.Read(buf)
	}
	if !errors.Is(err, ErrRESPLimit) {
		t.Fatalf("split header must still be rejected, got %v", err)
	}
}

func TestRESPGuardConnWriteStartsNewWindow(t *testing.T) {
	c, srv := guardedPipe(t, RESPLimits{MaxDeclaredBytes: 1000})
	readN := func(want int) error {
		buf := make([]byte, 256)
		got := 0
		for got < want {
			n, err := c.Read(buf)
			got += n
			if err != nil {
				return err
			}
		}
		return nil
	}
	reply := []byte("*40\r\n" + strings.Repeat(":1\r\n", 40)) // announces 640 of 1000
	go func() { _, _ = srv.Write(reply) }()
	if err := readN(len(reply)); err != nil {
		t.Fatalf("first reply: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, srv) }()
	if _, err := c.Write([]byte("PING\r\n")); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = srv.Write(reply) }()
	if err := readN(len(reply)); err != nil {
		t.Fatalf("a second reply after a write must get a fresh budget: %v", err)
	}
}
