package netutil

// respguard.go — bounds what a Redis (RESP) server may make a client allocate.
//
// RESP replies announce their size up front ("$<bytes>", "*<elements>", "%<pairs>"),
// and go-redis sizes its buffers from that announced number before a single body
// byte has arrived (make([]byte, n+2), make([]interface{}, n), make(map, n)) with no
// option to cap it. A hostile or man-in-the-middled server can therefore make the
// client allocate gigabytes, or panic on an out-of-range length, with a reply of a
// few bytes, and the read timeout does not help because it only fires after the
// allocation has succeeded. RESPGuardDialer wraps the connection a client dials and
// checks the announced numbers in the byte stream, closing the connection with an
// error before the client's parser ever sees an oversized header.
//
// The guard is a flat scanner, not a RESP parser: it needs no nesting stack,
// because the only things that matter are (1) every header's announced number and
// (2) where each bulk body ends, so the next header is found. It fails closed on
// anything it does not recognise (unknown type byte, malformed number, missing CRLF):
// a conforming server never sends those, and go-redis would reject them itself.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

const (
	// DefaultRESPMaxDeclaredBytes bounds the allocation weight a server may announce
	// within one reply window (see RESPLimits). 64 MiB is far above any reply keyorix
	// reads from Redis (ACL, AUTH, PING) and far below what exhausts a small host.
	DefaultRESPMaxDeclaredBytes int64 = 64 << 20

	// DefaultRESPMaxLineBytes bounds a single non-length reply line (simple string,
	// error, integer, double, ...), which go-redis buffers without limit.
	DefaultRESPMaxLineBytes = 1 << 20

	// respNumSaturate stops the header-number accumulator from overflowing int64;
	// anything past it is over every limit anyway.
	respNumSaturate int64 = 1 << 50

	// Allocation weight per announced unit: a bulk byte costs one byte, an array
	// element is a 16-byte interface value, a map/attribute pair is budgeted at 64
	// bytes (two interface values plus map overhead).
	respWeightBulk  int64 = 1
	respWeightElem  int64 = 16
	respWeightPair  int64 = 64
	respBodyTrailer       = 2 // CRLF after a bulk body
)

// RESPLimits configures RESPGuardDialer. Zero values select the defaults.
//
// MaxDeclaredBytes is a budget per "reply window": the window resets every time the
// client writes to the connection (a new command), so the sum of everything the
// server announces in answer to one command, or one pipeline, must stay under it.
type RESPLimits struct {
	MaxDeclaredBytes int64
	MaxLineBytes     int
}

func (l RESPLimits) withDefaults() RESPLimits {
	if l.MaxDeclaredBytes <= 0 {
		l.MaxDeclaredBytes = DefaultRESPMaxDeclaredBytes
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = DefaultRESPMaxLineBytes
	}
	return l
}

// ErrRESPLimit is matched (errors.Is) by every error the guard returns.
var ErrRESPLimit = errors.New("netutil: RESP reply rejected")

type respLimitError struct{ reason string }

func (e *respLimitError) Error() string   { return "netutil: RESP reply rejected: " + e.reason }
func (e *respLimitError) Is(t error) bool { return t == ErrRESPLimit }

type respState uint8

const (
	rsType  respState = iota // expecting a type byte
	rsLine                   // skipping a non-length line up to LF
	rsNum                    // reading a length header's number
	rsNumLF                  // saw CR after the number, expecting LF
	rsBody                   // skipping a bulk body and its CRLF
)

// respScanner is the streaming state machine. It is not safe for concurrent use.
type respScanner struct {
	lim       RESPLimits
	st        respState
	typ       byte
	neg       bool
	sign      bool
	nd        int
	n         int64
	saturated bool
	skip      int64
	line      int
	declared  int64
}

func newRESPScanner(l RESPLimits) *respScanner { return &respScanner{lim: l.withDefaults()} }

// resetWindow starts a new reply window (the client wrote a command).
func (s *respScanner) resetWindow() { s.declared = 0 }

// feed scans p, which holds the next bytes of the server stream, and returns an
// error at the first violation. After an error the scanner must not be reused.
func (s *respScanner) feed(p []byte) error {
	for i := 0; i < len(p); i++ {
		b := p[i]
		switch s.st {
		case rsType:
			switch b {
			case '$', '=', '!', '*', '~', '>', '%', '|':
				s.typ, s.st = b, rsNum
				s.neg, s.sign, s.nd, s.n, s.saturated = false, false, 0, 0, false
			case '+', '-', ':', ',', '_', '#', '(':
				s.st, s.line = rsLine, 1
			default:
				return &respLimitError{"unknown type byte"}
			}
		case rsLine:
			if b == '\n' {
				s.st = rsType
				continue
			}
			s.line++
			if s.line > s.lim.MaxLineBytes {
				return &respLimitError{fmt.Sprintf("line longer than %d bytes", s.lim.MaxLineBytes)}
			}
		case rsNum:
			switch {
			case b >= '0' && b <= '9':
				s.nd++
				if !s.saturated {
					s.n = s.n*10 + int64(b-'0')
					if s.n > respNumSaturate {
						s.saturated = true
					}
				}
			case (b == '-' || b == '+') && !s.sign && s.nd == 0:
				s.sign, s.neg = true, b == '-'
			case b == '\r' && s.nd > 0:
				s.st = rsNumLF
			default:
				return &respLimitError{"malformed length header"}
			}
		case rsNumLF:
			if b != '\n' {
				return &respLimitError{"malformed length header (CR without LF)"}
			}
			body, err := s.finishHeader()
			if err != nil {
				return err
			}
			if body > 0 {
				s.skip, s.st = body, rsBody
			} else {
				s.st = rsType
			}
		case rsBody:
			rem := int64(len(p) - i)
			if rem >= s.skip {
				i += int(s.skip) - 1
				s.skip, s.st = 0, rsType
			} else {
				s.skip -= rem
				i = len(p) - 1
			}
		}
	}
	return nil
}

// finishHeader applies the limits to a completed length header and returns how many
// body bytes follow it (bulk-like types only).
func (s *respScanner) finishHeader() (int64, error) {
	n := s.n
	if s.neg {
		n = -n
	}
	if n < -1 {
		return 0, &respLimitError{"negative length below -1"}
	}
	if n < 0 { // -1: RESP2 null; no body, no elements
		return 0, nil
	}
	var w int64
	switch s.typ {
	case '$', '=', '!':
		w = respWeightBulk
	case '*', '~', '>':
		w = respWeightElem
	default: // '%', '|'
		w = respWeightPair
	}
	max := s.lim.MaxDeclaredBytes
	if s.saturated || n > max/w || s.declared > max-n*w {
		return 0, &respLimitError{fmt.Sprintf("announced length %d (type %q) exceeds the %d-byte reply budget", n, s.typ, max)}
	}
	s.declared += n * w
	switch s.typ {
	case '$', '=', '!':
		return n + respBodyTrailer, nil
	}
	return 0, nil
}

// respGuardConn applies a respScanner to everything read from the server and resets
// the window on every write. After a violation it is closed and every later Read
// returns the same error.
type respGuardConn struct {
	net.Conn
	mu  sync.Mutex
	sc  *respScanner
	err error
}

func (c *respGuardConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	c.mu.Unlock()

	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		verr := c.sc.feed(p[:n])
		if verr != nil {
			c.err = verr
		}
		c.mu.Unlock()
		if verr != nil {
			// Withhold the whole chunk: the client has not seen the violating header
			// and, because it only acts on a complete header line, never will.
			_ = c.Conn.Close()
			return 0, verr
		}
	}
	return n, err
}

func (c *respGuardConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.sc.resetWindow()
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// RESPGuardDialer wraps next so every connection it returns enforces lim on the RESP
// stream read from the server. Wrap the OUTERMOST dialer, after any TLS layer, so
// the guard sees plaintext RESP. Typical use with go-redis:
//
//	if opts.Dialer == nil {
//		opts.Dialer = redis.NewDialer(opts) // the library's default (TLS-aware) dialer
//	}
//	opts.Dialer = netutil.RESPGuardDialer(opts.Dialer, netutil.RESPLimits{})
func RESPGuardDialer(next func(ctx context.Context, network, addr string) (net.Conn, error), lim RESPLimits) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := next(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &respGuardConn{Conn: conn, sc: newRESPScanner(lim)}, nil
	}
}
