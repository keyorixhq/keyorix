package netutil

// mysqlguard.go — bounds the column count a MySQL server may announce.
//
// A text or binary result set starts with a header packet whose payload is a
// length-encoded integer: the number of column definition packets that follow.
// go-sql-driver/mysql (up to v1.10.1) sizes its column slice from that number
// before it reads a single column packet, so a hostile or man-in-the-middled
// server can make the client allocate far more than it ever sends. MySQLGuardDialer
// wraps the connection and checks that number in the byte stream, closing the
// connection with an error before the driver sees an oversized header.
//
// Coverage is deliberately narrow and stated here, not implied:
//   - Only the first packet of the response to each command is inspected (the
//     result set header of COM_QUERY / COM_STMT_EXECUTE). Further result sets of
//     a multi-statement reply are not.
//   - Once the client asks for TLS (an SSLRequest packet with CLIENT_SSL set) the
//     stream is ciphertext and the guard steps aside: a TLS connection is NOT
//     covered, because the driver wraps the connection it dials in its own TLS
//     layer, which a dial-time wrapper cannot sit above.
//   - The compressed protocol changes the framing; a client that asks for
//     CLIENT_COMPRESS is refused rather than left unguarded.
//
// The framing tracker follows exactly the bytes the driver reads and writes
// (4-byte header: 3-byte little-endian length, 1-byte sequence id), so the guard
// and the driver cannot disagree about where a packet starts.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
)

// DefaultMySQLMaxColumns is the largest column count accepted in a result set header.
// A table holds at most 4096 columns and a prepared statement announces its column
// count in a uint16, so 65536 is above anything a conforming server sends and keeps
// the allocation an unpatched driver makes for it in the single-digit megabytes.
const DefaultMySQLMaxColumns uint64 = 1 << 16

const (
	mysqlCapCompress uint32 = 0x00000020
	mysqlCapSSL      uint32 = 0x00000800
	mysqlSSLReqLen          = 32 // SSLRequest payload: caps(4) max packet(4) charset(1) filler(23)
	mysqlHeadCap            = 9  // bytes of a packet payload the scanner keeps: 0xfe + uint64
)

// MySQLLimits configures MySQLGuardDialer. The zero value selects the defaults.
type MySQLLimits struct {
	MaxColumns uint64
}

func (l MySQLLimits) withDefaults() MySQLLimits {
	if l.MaxColumns == 0 {
		l.MaxColumns = DefaultMySQLMaxColumns
	}
	return l
}

// ErrMySQLLimit is matched (errors.Is) by every error the guard returns.
var ErrMySQLLimit = errors.New("netutil: MySQL packet rejected")

type mysqlLimitError struct{ reason string }

func (e *mysqlLimitError) Error() string   { return "netutil: MySQL packet rejected: " + e.reason }
func (e *mysqlLimitError) Is(t error) bool { return t == ErrMySQLLimit }

// mysqlFrame tracks one direction of the stream across arbitrary read/write chunking.
type mysqlFrame struct {
	hdr   [4]byte
	hdrN  int
	inPkt bool
	plen  int
	seq   byte
	pos   int // payload bytes consumed in the current packet
	want  int // payload bytes to capture into head (0: none)
	head  [mysqlHeadCap]byte
}

// mysqlScanner is the two-direction state machine. Not safe for concurrent use.
type mysqlScanner struct {
	lim    MySQLLimits
	armed  bool // the client started a command; the next server packet answers it
	sealed bool // TLS requested: ciphertext from here on, nothing more to inspect
	c, s   mysqlFrame
}

func newMySQLScanner(l MySQLLimits) *mysqlScanner { return &mysqlScanner{lim: l.withDefaults()} }

// feed scans p, the next bytes of the server stream (server=true) or of the client
// stream (server=false). After an error the scanner must not be reused.
func (m *mysqlScanner) feed(server bool, p []byte) error {
	f := &m.c
	if server {
		f = &m.s
	}
	for len(p) > 0 {
		if m.sealed {
			return nil
		}
		if !f.inPkt {
			// Collect the 4-byte packet header.
			n := copy(f.hdr[f.hdrN:], p)
			f.hdrN += n
			p = p[n:]
			if f.hdrN < 4 {
				return nil
			}
			f.hdrN = 0
			f.plen = int(f.hdr[0]) | int(f.hdr[1])<<8 | int(f.hdr[2])<<16
			f.seq = f.hdr[3]
			f.pos = 0
			f.want = 0
			if server {
				if m.armed {
					m.armed = false
					f.want = min(f.plen, mysqlHeadCap)
				}
			} else {
				if f.seq == 0 {
					m.armed = true
				}
				if f.seq == 1 && f.plen >= 4 {
					f.want = 4 // capability flags of the handshake response / SSLRequest
				}
			}
			f.inPkt = f.plen > 0
			continue
		}
		// Inside a payload: take what we still need for the head, then skip the rest.
		take := min(len(p), f.plen-f.pos)
		if f.pos < f.want {
			c := min(take, f.want-f.pos)
			copy(f.head[f.pos:], p[:c])
		}
		before := f.pos
		f.pos += take
		p = p[take:]
		if f.want > 0 && before < f.want && f.pos >= f.want {
			if err := m.headComplete(server, f); err != nil {
				return err
			}
		}
		if f.pos == f.plen {
			f.inPkt = false
		}
	}
	return nil
}

// headComplete runs once the first f.want payload bytes of a packet are captured.
func (m *mysqlScanner) headComplete(server bool, f *mysqlFrame) error {
	if !server {
		caps := binary.LittleEndian.Uint32(f.head[:4])
		if caps&mysqlCapCompress != 0 {
			return &mysqlLimitError{"compressed protocol is not supported on a guarded connection"}
		}
		if f.plen == mysqlSSLReqLen && caps&mysqlCapSSL != 0 {
			m.sealed = true
		}
		return nil
	}
	b := f.head[0]
	var cols uint64
	switch {
	case b == 0x00 || b == 0xff || b == 0xfb:
		return nil // OK, ERR, LOCAL INFILE request: not a result set header
	case b < 0xfb:
		cols = uint64(b)
	case b == 0xfc:
		if f.plen < 3 {
			return &mysqlLimitError{"truncated column count"}
		}
		cols = uint64(binary.LittleEndian.Uint16(f.head[1:3]))
	case b == 0xfd:
		if f.plen < 4 {
			return &mysqlLimitError{"truncated column count"}
		}
		cols = uint64(f.head[1]) | uint64(f.head[2])<<8 | uint64(f.head[3])<<16
	default: // 0xfe
		if f.plen < 9 {
			return nil // EOF / OK-with-0xfe packet, not a result set header
		}
		cols = binary.LittleEndian.Uint64(f.head[1:9])
	}
	if cols > m.lim.MaxColumns {
		return &mysqlLimitError{fmt.Sprintf("result set announces more than %d columns", m.lim.MaxColumns)}
	}
	return nil
}

type mysqlGuardConn struct {
	net.Conn
	mu  sync.Mutex
	sc  *mysqlScanner
	err error
}

func (c *mysqlGuardConn) failed() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *mysqlGuardConn) scan(server bool, p []byte) error {
	c.mu.Lock()
	err := c.sc.feed(server, p)
	if err != nil {
		c.err = err
	}
	c.mu.Unlock()
	if err != nil {
		_ = c.Conn.Close()
	}
	return err
}

func (c *mysqlGuardConn) Read(p []byte) (int, error) {
	if err := c.failed(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		// Withhold the whole chunk on a violation: the driver never sees the header.
		if verr := c.scan(true, p[:n]); verr != nil {
			return 0, verr
		}
	}
	return n, err
}

func (c *mysqlGuardConn) Write(p []byte) (int, error) {
	if err := c.failed(); err != nil {
		return 0, err
	}
	if verr := c.scan(false, p); verr != nil {
		return 0, verr
	}
	return c.Conn.Write(p)
}

// SyscallConn keeps the driver's pre-reuse liveness check working through the wrapper.
func (c *mysqlGuardConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("netutil: underlying connection has no syscall access")
}

// MySQLGuardDialer wraps next (nil selects a plain net.Dialer) so every connection it
// returns enforces lim on the MySQL packet stream. Install it as mysql.Config.DialFunc.
// See the file comment for exactly what is and is not covered.
func MySQLGuardDialer(next func(ctx context.Context, network, addr string) (net.Conn, error), lim MySQLLimits) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if next == nil {
		next = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := next(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The driver enables keepalive only on a bare *net.TCPConn, which the wrapper hides.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
		}
		return &mysqlGuardConn{Conn: conn, sc: newMySQLScanner(lim)}, nil
	}
}
