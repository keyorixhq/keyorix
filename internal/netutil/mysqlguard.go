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
// Which packet is a result set header follows the driver, not the protocol
// documents: the first packet of the response to a command, and, after an OK
// packet whose status has SERVER_MORE_RESULTS_EXISTS (or after a LOCAL INFILE
// request), the packet that follows it, because the driver reads that one as the
// next result set header inside Query itself (rows.NextResultSet). A hostile
// server sets that status bit on its own; no multi-statement setting is needed.
// Every first-response shape the pinned driver would panic on (a truncated
// length-encoded count or OK packet, a short prepare response, a MariaDB header
// without its metadata byte) is refused as well.
//
// Coverage is deliberately narrow and stated here, not implied:
//   - Result sets that follow a non-empty result set (the terminating EOF/OK of
//     its rows carries the status) are not inspected. The driver reads those
//     only when the caller calls rows.NextResultSet, which no caller in this
//     repository does, or skips them without allocating when rows close.
//   - Once the client asks for TLS (an SSLRequest packet with CLIENT_SSL set) the
//     stream is ciphertext and the guard steps aside: a TLS connection is NOT
//     covered, because the driver wraps the connection it dials in its own TLS
//     layer, which a dial-time wrapper cannot sit above. That includes
//     tls=skip-verify (an interceptor can terminate TLS itself) and tls=preferred
//     when the server offers TLS; tls=preferred stays guarded only when the
//     server, or an interceptor stripping SSL, does not offer it.
//   - The compressed protocol changes the framing; a client that asks for
//     CLIENT_COMPRESS is refused rather than left unguarded.
//   - Arming follows wire order. A header the server sends before the client's
//     command is not inspected; it is safe only because the driver refuses to
//     write a new command while it still holds unread bytes (ErrBusyBuffer in
//     its buffer.busy check), so such a header is never read as a response.
//
// The framing tracker follows exactly the bytes the driver reads and writes
// (4-byte header: 3-byte little-endian length, 1-byte sequence id; a packet of
// 0xffffff bytes continues in the next one), so the guard and the driver cannot
// disagree about where a logical packet starts.

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
	mysqlCapMySQL    uint32 = 0x00000001 // CLIENT_LONG_PASSWORD; MariaDB clears it and sends extended caps
	mysqlCapCompress uint32 = 0x00000020
	mysqlCapSSL      uint32 = 0x00000800
	mysqlExtCapCache uint32 = 0x00000010 // MariaDB MARIADB_CLIENT_CACHE_METADATA
	mysqlSSLReqLen          = 32         // SSLRequest payload: caps(4) max packet(4) charset(1) filler(23)
	mysqlHeadCap            = 32         // payload bytes kept: handshake caps..extended caps (32), OK up to status (21)
	mysqlMaxPkt             = 0xffffff   // a packet of this length continues in the next one
	mysqlMoreResults uint16 = 0x0008     // SERVER_MORE_RESULTS_EXISTS

	mysqlComQuit         byte = 0x01
	mysqlComStmtPrepare  byte = 0x16
	mysqlComStmtLongData byte = 0x18
	mysqlComStmtClose    byte = 0x19
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
	hdr      [4]byte
	hdrN     int
	inPkt    bool
	plen     int
	seq      byte
	contNext bool // the last packet was mysqlMaxPkt long: the next one continues it
	pos      int  // payload bytes consumed in the current packet
	want     int  // payload bytes to capture into head (0: none)
	head     [mysqlHeadCap]byte
}

// mysqlScanner is the two-direction state machine. Not safe for concurrent use.
type mysqlScanner struct {
	lim       MySQLLimits
	armed     bool // the next logical server packet is read by the driver as a response head
	cmd       byte // command byte of the request that packet answers
	hsDone    bool // the client's handshake response (capability flags) has been seen
	cacheMeta bool // MariaDB cache-metadata negotiated: a column count is followed by a flag byte
	sealed    bool // TLS requested: ciphertext from here on, nothing more to inspect
	c, s      mysqlFrame
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
			cont := f.contNext
			f.contNext = f.plen == mysqlMaxPkt
			switch {
			case cont:
				// The tail of a logical packet whose head was already handled.
			case server:
				if m.armed {
					m.armed = false
					f.want = min(f.plen, mysqlHeadCap)
				}
			case !m.hsDone && f.seq == 1:
				m.hsDone = true
				if f.plen >= 4 {
					f.want = min(f.plen, mysqlHeadCap) // handshake response / SSLRequest
				}
			case m.hsDone && f.seq == 0:
				if f.plen == 0 {
					m.armed, m.cmd = true, 0
				} else {
					f.want = 1 // the command byte decides how the response is read
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

// mysqlLenEncSize is the size of the length-encoded integer starting with b, as the
// driver's readLengthEncodedInteger counts it.
func mysqlLenEncSize(b byte) int {
	switch b {
	case 0xfc:
		return 3
	case 0xfd:
		return 4
	case 0xfe:
		return 9
	}
	return 1
}

// headComplete runs once the first f.want payload bytes of a packet are captured.
func (m *mysqlScanner) headComplete(server bool, f *mysqlFrame) error {
	if !server {
		if f.seq == 0 { // a command
			switch c := f.head[0]; c {
			case mysqlComQuit, mysqlComStmtLongData, mysqlComStmtClose:
				// No response follows.
			default:
				m.armed, m.cmd = true, c
			}
			return nil
		}
		caps := binary.LittleEndian.Uint32(f.head[:4])
		if caps&mysqlCapCompress != 0 {
			return &mysqlLimitError{"compressed protocol is not supported on a guarded connection"}
		}
		if f.plen == mysqlSSLReqLen && caps&mysqlCapSSL != 0 {
			m.sealed = true
			return nil
		}
		if caps&mysqlCapMySQL == 0 && f.want >= 32 {
			m.cacheMeta = binary.LittleEndian.Uint32(f.head[28:32])&mysqlExtCapCache != 0
		}
		return nil
	}
	b := f.head[0]
	if b == 0xff {
		return errPacket(f)
	}
	if m.cmd == mysqlComStmtPrepare {
		// COM_STMT_PREPARE_OK: fixed fields up to the parameter count; anything but
		// 0x00 and 0xff is refused by the driver as a malformed packet.
		if b == 0x00 && f.plen < 9 {
			return &mysqlLimitError{"truncated prepare response"}
		}
		return nil
	}
	var cols uint64
	n := mysqlLenEncSize(b)
	switch {
	case b == 0x00:
		return m.okPacket(f)
	case b == 0xfb:
		// LOCAL INFILE request: the driver reads the OK that ends the transfer as the
		// response, and follows its status like any other first-packet OK.
		m.armed = true
		return nil
	case f.plen < n:
		return &mysqlLimitError{"truncated column count"}
	case b < 0xfb:
		cols = uint64(b)
	case b == 0xfc:
		cols = uint64(binary.LittleEndian.Uint16(f.head[1:3]))
	case b == 0xfd:
		cols = uint64(f.head[1]) | uint64(f.head[2])<<8 | uint64(f.head[3])<<16
	default: // 0xfe: the driver never reads a first-response 0xfe as EOF
		cols = binary.LittleEndian.Uint64(f.head[1:9])
	}
	if cols > m.lim.MaxColumns {
		return &mysqlLimitError{fmt.Sprintf("result set announces more than %d columns", m.lim.MaxColumns)}
	}
	if m.cacheMeta && f.plen <= n {
		return &mysqlLimitError{"column count without its metadata flag"}
	}
	return nil
}

// errPacket checks an ERR packet read as a response head: the driver slices the
// error number, the SQL state marker and, when the marker is present, the state.
func errPacket(f *mysqlFrame) error {
	if f.plen < 4 || (f.head[3] == '#' && f.plen < 9) {
		return &mysqlLimitError{"truncated error packet"}
	}
	return nil
}

// okPacket checks an OK packet read as a response head: it must hold the two
// length-encoded integers and the status the driver slices out of it, and with
// SERVER_MORE_RESULTS_EXISTS set the next packet is read as a result set header.
func (m *mysqlScanner) okPacket(f *mysqlFrame) error {
	end := 1
	for range 2 { // affected rows, last insert id
		if end >= f.plen {
			return &mysqlLimitError{"truncated OK packet"}
		}
		end += mysqlLenEncSize(f.head[end])
	}
	if f.plen < end+2 {
		return &mysqlLimitError{"truncated OK packet"}
	}
	if binary.LittleEndian.Uint16(f.head[end:end+2])&mysqlMoreResults != 0 {
		m.armed = true
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

// mysqlGuardSysConn is a mysqlGuardConn over a connection with syscall access. It
// keeps the driver's pre-reuse liveness check (connCheck) working through the
// wrapper; over a connection without it the driver skips that check, which an
// erroring SyscallConn would instead turn into a bad connection on every reuse.
type mysqlGuardSysConn struct {
	*mysqlGuardConn
	sys syscall.Conn
}

func (c *mysqlGuardSysConn) SyscallConn() (syscall.RawConn, error) { return c.sys.SyscallConn() }

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
		gc := &mysqlGuardConn{Conn: conn, sc: newMySQLScanner(lim)}
		if sys, ok := conn.(syscall.Conn); ok {
			return &mysqlGuardSysConn{mysqlGuardConn: gc, sys: sys}, nil
		}
		return gc, nil
	}
}
