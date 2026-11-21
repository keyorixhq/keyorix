package netutil

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded, reproducible test-input generator, not a secret
	"net"
	"slices"
	"testing"
	"time"
)

func myPkt(seq byte, payload []byte) []byte {
	b := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	return append(b, payload...)
}

func myLenEnc(n uint64) []byte {
	switch {
	case n < 0xfb:
		return []byte{byte(n)}
	case n < 1<<16:
		return []byte{0xfc, byte(n), byte(n >> 8)}
	case n < 1<<24:
		return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}
	}
	b := make([]byte, 9)
	b[0] = 0xfe
	binary.LittleEndian.PutUint64(b[1:], n)
	return b
}

type myEv struct {
	server bool
	data   []byte
}

func myGreeting() myEv { return myEv{true, myPkt(0, append([]byte{0x0a}, make([]byte, 40)...))} }
func myResponse(caps uint32, plen int) myEv {
	pl := make([]byte, plen)
	binary.LittleEndian.PutUint32(pl, caps)
	return myEv{false, myPkt(1, pl)}
}
func myOK(seq byte) myEv     { return myEv{true, myPkt(seq, []byte{0, 0, 0, 2, 0, 0, 0})} }
func myCmd() myEv            { return myEv{false, myPkt(0, []byte{0x03, 'S', 'E', 'L', 'E', 'C', 'T'})} }
func myCmdByte(c byte) myEv  { return myEv{false, myPkt(0, []byte{c, 1, 0, 0, 0})} }
func myHeader(n uint64) myEv { return myEv{true, myPkt(1, myLenEnc(n))} }
func myRaw(p []byte) myEv    { return myEv{true, myPkt(1, p)} }

// myOKStatus is an OK packet with the given server status (0x0008: more results follow).
func myOKStatus(status uint16) []byte { return []byte{0, 0, 0, byte(status), byte(status >> 8), 0, 0} }

// myMariaResponse is a MariaDB handshake response (CLIENT_MYSQL clear) with extended caps.
func myMariaResponse(caps, ext uint32) myEv {
	pl := make([]byte, 40)
	binary.LittleEndian.PutUint32(pl, caps)
	binary.LittleEndian.PutUint32(pl[28:], ext)
	return myEv{false, myPkt(1, pl)}
}

func runMySQL(evs []myEv, chunk int, lim MySQLLimits) error {
	sc := newMySQLScanner(lim)
	for _, e := range evs {
		d := e.data
		for len(d) > 0 {
			n := len(d)
			if chunk > 0 && n > chunk {
				n = chunk
			}
			if err := sc.feed(e.server, d[:n]); err != nil {
				return err
			}
			d = d[n:]
		}
	}
	return nil
}

func session(rest ...myEv) []myEv {
	return append([]myEv{myGreeting(), myResponse(0x0000820d, 40), myOK(2)}, rest...)
}

func TestMySQLScannerVerdicts(t *testing.T) {
	max := DefaultMySQLMaxColumns
	tests := []struct {
		name    string
		evs     []myEv
		wantErr bool
	}{
		{"handshake only", session(), false},
		{"small result set", session(myCmd(), myHeader(3)), false},
		{"one-byte count at limit of the form", session(myCmd(), myHeader(250)), false},
		{"count at the limit", session(myCmd(), myHeader(max)), false},
		{"count over the limit, 3-byte form", session(myCmd(), myHeader(max+1)), true},
		{"huge count, 3-byte form", session(myCmd(), myHeader(5_000_000)), true},
		{"huge count, 8-byte form", session(myCmd(), myHeader(1<<62)), true},
		{"maximal count", session(myCmd(), myHeader(^uint64(0))), true},
		{"ok response", session(myCmd(), myRaw([]byte{0, 0, 0, 2, 0, 0, 0})), false},
		{"err response", session(myCmd(), myRaw([]byte{0xff, 0x15, 0x04, '#', '4', '2', '0', '0', '0', 'x'})), false},
		{"local infile request", session(myCmd(), myRaw([]byte{0xfb, 'f'})), false},
		// The driver never reads a first-response 0xfe as EOF: it decodes 8 bytes and panics on fewer.
		{"0xfe short packet is a truncated header", session(myCmd(), myRaw([]byte{0xfe, 0, 0, 2, 0})), true},
		{"0xfe alone", session(myCmd(), myRaw([]byte{0xfe})), true},
		{"more results: header after OK is checked", session(myCmd(), myRaw(myOKStatus(0x0008)), myHeader(5_000_000)), true},
		{"more results: small header after OK", session(myCmd(), myRaw(myOKStatus(0x0008)), myHeader(3)), false},
		{"more results: chain of empty results", session(myCmd(), myRaw(myOKStatus(0x000a)), myRaw(myOKStatus(0x0008)), myHeader(1<<40)), true},
		{"more results: short 0xfe after OK", session(myCmd(), myRaw(myOKStatus(0x0008)), myRaw([]byte{0xfe, 1, 0, 0, 0})), true},
		{"OK without more results ends the response", session(myCmd(), myRaw(myOKStatus(0x0002)), myHeader(5_000_000)), false},
		{"more results on a later command", session(myCmd(), myHeader(1), myCmd(), myRaw(myOKStatus(0x0008)), myHeader(5_000_000)), true},
		{"local infile: header after the closing OK is checked", session(myCmd(), myRaw([]byte{0xfb, 'f'}), myRaw(myOKStatus(0x0008)), myHeader(5_000_000)), true},
		{"local infile: plain closing OK", session(myCmd(), myRaw([]byte{0xfb, 'f'}), myRaw(myOKStatus(0x0002)), myHeader(5_000_000)), false},
		{"OK with 8-byte lengths", session(myCmd(), myRaw(append(append([]byte{0}, myLenEnc(1<<40)...), append(myLenEnc(1<<41), 2, 0, 0, 0)...))), false},
		{"truncated OK: marker only", session(myCmd(), myRaw([]byte{0})), true},
		{"truncated OK: no status", session(myCmd(), myRaw([]byte{0, 0, 0, 2})), true},
		{"truncated OK: cut length", session(myCmd(), myRaw([]byte{0, 0xfc, 1})), true},
		{"truncated OK answers a ping too", session(myCmdByte(0x0e), myRaw([]byte{0, 0})), true},
		{"prepare response is not an OK packet", session(myCmdByte(0x16), myRaw([]byte{0, 0xfe, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})), false},
		{"prepare response with more-results bits does not arm", session(myCmdByte(0x16), myRaw([]byte{0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}), myHeader(5_000_000)), false},
		{"truncated prepare response", session(myCmdByte(0x16), myRaw([]byte{0, 1, 0, 0, 0, 0})), true},
		{"prepare error", session(myCmdByte(0x16), myRaw([]byte{0xff, 0x15, 0x04, 'x'})), false},
		{"truncated error: no state marker byte", session(myCmd(), myRaw([]byte{0xff, 0x15, 0x04})), true},
		{"truncated error: cut SQL state", session(myCmd(), myRaw([]byte{0xff, 0x15, 0x04, '#', '4', '2'})), true},
		{"truncated error answers a prepare too", session(myCmdByte(0x16), myRaw([]byte{0xff})), true},
		{"error without SQL state", session(myCmd(), myRaw([]byte{0xff, 0x15, 0x04, 'n', 'o'})), false},
		{"execute response is checked", session(myCmdByte(0x16), myRaw([]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), myCmdByte(0x17), myHeader(5_000_000)), true},
		{"statement close has no response", session(myCmdByte(0x19), myHeader(5_000_000)), false},
		{"long data has no response", session(myCmdByte(0x18), myHeader(5_000_000)), false},
		{"mariadb cache metadata: count without flag byte", []myEv{myGreeting(), myMariaResponse(0x820c, 0x10), myOK(2), myCmd(), myRaw([]byte{0x01})}, true},
		{"mariadb cache metadata: count with flag byte", []myEv{myGreeting(), myMariaResponse(0x820c, 0x10), myOK(2), myCmd(), myRaw([]byte{0x01, 0x01})}, false},
		{"mariadb without cache metadata", []myEv{myGreeting(), myMariaResponse(0x820c, 0x04), myOK(2), myCmd(), myRaw([]byte{0x01})}, false},
		{"ext caps ignored when CLIENT_MYSQL is set", []myEv{myGreeting(), myMariaResponse(0x820d, 0x10), myOK(2), myCmd(), myRaw([]byte{0x01})}, false},
		{"seq-1 packet after the handshake does not seal", session(myResponse(0x800, 32), myCmd(), myHeader(5_000_000)), true},
		{"seq-1 packet after the handshake is not a compression request", session(myResponse(0x20, 8)), false},
		{"command before the handshake does not arm", []myEv{myGreeting(), myCmd(), myHeader(5_000_000)}, false},
		{"truncated 2-byte count", session(myCmd(), myRaw([]byte{0xfc, 1})), true},
		{"truncated 3-byte count", session(myCmd(), myRaw([]byte{0xfd, 1, 2})), true},
		{"unsolicited header is not a response", session(myHeader(5_000_000)), false},
		{"only the first packet of a response is a header", session(myCmd(), myHeader(2), myHeader(5_000_000)), false},
		{"second command is checked again", session(myCmd(), myHeader(2), myCmd(), myHeader(5_000_000)), true},
		{"seq-0 command without a reply keeps the next command armed", session(myCmd(), myCmd(), myHeader(5_000_000)), true},
		{"greeting is never a response", []myEv{myEv{true, myPkt(0, append([]byte{0xfd, 0xff, 0xff, 0xff}, make([]byte, 40)...))}, myResponse(0x820d, 40), myOK(2)}, false},
		{"compression requested", []myEv{myGreeting(), myResponse(0x820d|0x20, 40)}, true},
		{"tls requested: later bytes are ciphertext", []myEv{myGreeting(), myResponse(0x820d|0x800, 32),
			{true, []byte{0x16, 0x03, 0x03, 0x00, 0x30, 0xfd, 0xff, 0xff, 0xff}}, {false, []byte{0x16, 0x03, 0x01}}, myCmd(), myHeader(5_000_000)}, false},
		{"plaintext response with ssl bit but long payload is not a seal", []myEv{myGreeting(), myResponse(0x820d|0x800, 40), myOK(2), myCmd(), myHeader(5_000_000)}, true},
		{"large first packet", session(myCmd(), myEv{true, append(myPkt(1, append(myLenEnc(3), make([]byte, 1<<20)...))[:0:0], myPkt(1, append(myLenEnc(3), make([]byte, 1<<20)...))...)}), false},
	}
	for _, tc := range tests {
		for _, chunk := range []int{0, 1, 2, 3, 5} {
			err := runMySQL(tc.evs, chunk, MySQLLimits{})
			if (err != nil) != tc.wantErr {
				t.Errorf("%s (chunk %d): err = %v, wantErr %v", tc.name, chunk, err, tc.wantErr)
			} else if err != nil && !errors.Is(err, ErrMySQLLimit) {
				t.Errorf("%s: error %v does not match ErrMySQLLimit", tc.name, err)
			}
		}
	}
}

// myDriverLenEnc is go-sql-driver/mysql v1.10.1 readLengthEncodedInteger (utils.go),
// including its unchecked slicing, so a truncated value panics here as it does there.
func myDriverLenEnc(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 1
	}
	switch b[0] {
	case 0xfb:
		return 0, 1
	case 0xfc:
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3
	case 0xfd:
		v := b[1:]
		return uint64(v[0]) | uint64(v[1])<<8 | uint64(v[2])<<16, 4
	case 0xfe:
		return binary.LittleEndian.Uint64(b[1:]), 9
	}
	return uint64(b[0]), 1
}

// myDriverHead reads pl (capacity capped at its length) the way the v1.10.1 driver reads a response head
// (readPrepareResultPacket for COM_STMT_PREPARE, else readResultSetHeaderPacket and
// handleOkPacket): whether it panics, the column count it sizes a slice from, and
// whether it reads the next packet as another result set header (rows.NextResultSet
// after an OK with SERVER_MORE_RESULTS_EXISTS, the OK after a LOCAL INFILE request).
func myDriverHead(cmd byte, pl []byte, cacheMeta bool) (panicked bool, cols uint64, next bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	if pl[0] == 0xff { // handleErrorPacket
		if _ = pl[1:3]; pl[3] == '#' {
			_ = pl[4 : 4+5]
		}
		return false, 0, false
	}
	if cmd == 0x16 {
		if pl[0] == 0x00 {
			_, _, _ = pl[1:5], pl[5:7], pl[7:9]
		}
		return false, 0, false
	}
	switch pl[0] {
	case 0x00:
		_, n := myDriverLenEnc(pl[1:])
		_, m := myDriverLenEnc(pl[1+n:])
		return false, 0, binary.LittleEndian.Uint16(pl[1+n+m:1+n+m+2])&0x0008 != 0
	case 0xfb:
		return false, 0, true
	}
	cols, n := myDriverLenEnc(pl)
	if cacheMeta {
		_ = pl[n]
	}
	return false, cols, false
}

// myReference derives the verdict from whole packets with no byte state: violation
// when the driver, reading the packets it reads as response heads, would panic or
// size a column slice above maxCols. It shares no code with the scanner.
func myReference(evs []myEv, maxCols uint64) bool {
	armed, sealed, hsDone, cacheMeta := false, false, false, false
	var cmd byte
	for _, e := range evs {
		d := e.data
		for len(d) >= 4 && !sealed {
			plen := int(d[0]) | int(d[1])<<8 | int(d[2])<<16
			seq := d[3]
			pl := d[4:]
			if plen < len(pl) {
				pl = pl[:plen]
			}
			// Cap the capacity: a slice expression past the packet end, which the driver's
			// buffer would satisfy with the following bytes, then panics here instead.
			pl = slices.Clip(pl)
			d = d[min(4+plen, len(d)):]
			if len(pl) < plen {
				continue // the event ends mid-packet: nothing is complete to judge
			}
			switch {
			case e.server && armed:
				armed = false
				if plen == 0 {
					continue // the driver rejects an empty packet itself
				}
				panicked, cols, next := myDriverHead(cmd, pl, cacheMeta)
				if panicked || cols > maxCols {
					return true
				}
				armed = next
			case e.server:
			case !hsDone && seq == 1:
				hsDone = true
				if plen < 4 {
					continue
				}
				caps := binary.LittleEndian.Uint32(pl)
				if caps&0x20 != 0 {
					return true
				}
				if plen == 32 && caps&0x800 != 0 {
					sealed = true
				} else if caps&1 == 0 && plen >= 32 {
					cacheMeta = binary.LittleEndian.Uint32(pl[28:])&0x10 != 0
				}
			case hsDone && seq == 0:
				if plen == 0 {
					armed, cmd = true, 0
				} else if c := pl[0]; c != 0x01 && c != 0x18 && c != 0x19 {
					armed, cmd = true, c
				}
			}
		}
	}
	return false
}

func TestMySQLScannerMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	counts := []uint64{0, 1, 5, 250, 251, 1000, 65535, 65536, 65537, 1 << 24, 1 << 40, ^uint64(0)}
	cmds := []byte{0x03, 0x03, 0x17, 0x16, 0x0e, 0x19, 0x18, 0x01}
	lenencHeads := []byte{0, 1, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	for i := range 20000 {
		var evs []myEv
		for k, n := 0, 1+rng.Intn(10); k < n; k++ {
			switch rng.Intn(10) {
			case 0:
				evs = append(evs, myCmd())
			case 1:
				evs = append(evs, myHeader(counts[rng.Intn(len(counts))]))
			case 2:
				evs = append(evs, myOK(byte(rng.Intn(4))))
			case 3:
				pl := make([]byte, rng.Intn(12))
				rng.Read(pl)
				evs = append(evs, myRaw(pl))
			case 4:
				caps := uint32(rng.Intn(1 << 16))
				evs = append(evs, myResponse(caps, 4+rng.Intn(40)))
			case 5:
				evs = append(evs, myEv{false, myPkt(byte(rng.Intn(3)), make([]byte, rng.Intn(6)))})
			case 6:
				// OK packets with every length-encoding head, cut at a random length.
				pl := []byte{0, lenencHeads[rng.Intn(len(lenencHeads))], 1, 2, 3, 4, 5, 6, 7, 8, lenencHeads[rng.Intn(len(lenencHeads))], 1, 2, 3, 4, 5, 6, 7, 8}
				pl = append(pl, byte(rng.Intn(16)), 0, 0, 0)
				evs = append(evs, myRaw(pl[:rng.Intn(len(pl)+1)]))
			case 7:
				evs = append(evs, myCmdByte(cmds[rng.Intn(len(cmds))]))
			case 8:
				evs = append(evs, myMariaResponse(uint32(rng.Intn(1<<16)), uint32(rng.Intn(32))))
			default:
				evs = append(evs, myGreeting())
			}
		}
		want := myReference(evs, DefaultMySQLMaxColumns)
		for _, chunk := range []int{0, 1, 3} {
			if got := runMySQL(evs, chunk, MySQLLimits{}) != nil; got != want {
				t.Fatalf("case %d chunk %d: scanner violation=%v, reference=%v; dialogue %+v", i, chunk, got, want, evs)
			}
		}
	}
}

// A packet of 0xffffff bytes continues in the next one, whatever its sequence id: the
// continuation of a large command is not a handshake response, and the continuation of
// a large response head is not another head.
func TestMySQLScannerContinuationPackets(t *testing.T) {
	big := func(first byte) []byte {
		pl := make([]byte, 0xffffff)
		pl[0] = first
		return pl
	}
	bigCmd := myEv{false, myPkt(0, big(0x03))}
	cont := func(server bool, seq byte, pl []byte) myEv { return myEv{server, myPkt(seq, pl)} }
	sslCaps := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslCaps, 0x820d|0x800)
	compCaps := make([]byte, 40)
	binary.LittleEndian.PutUint32(compCaps, 0x820d|0x20)
	bigOK := big(0)
	bigOK[3] = 0x08 // status: more results
	tests := []struct {
		name    string
		evs     []myEv
		wantErr bool
	}{
		{"command continuation with the SSL bit does not seal", session(bigCmd, cont(false, 1, sslCaps), myHeader(5_000_000)), true},
		{"command continuation with the compress bit is not refused", session(bigCmd, cont(false, 1, compCaps), myHeader(3)), false},
		{"continuation after a wrapped sequence id does not arm", session(myCmd(), myHeader(1), bigCmd, cont(false, 0, []byte{0x03}), myHeader(1), myHeader(5_000_000)), false},
		{"continuation of a large header is not a header", session(myCmd(), myEv{true, myPkt(1, big(3))}, cont(true, 2, []byte{0xfd, 0xff, 0xff, 0xff})), false},
		{"header after the continuation of a more-results OK is checked", session(myCmd(), myEv{true, myPkt(1, bigOK)}, cont(true, 2, []byte{1}), myHeader(5_000_000)), true},
		{"continuation of a more-results OK is not the header", session(myCmd(), myEv{true, myPkt(1, bigOK)}, cont(true, 2, []byte{0xfd, 0xff, 0xff, 0xff}), myHeader(3)), false},
	}
	for _, tc := range tests {
		for _, chunk := range []int{0, 4093} {
			err := runMySQL(tc.evs, chunk, MySQLLimits{})
			if (err != nil) != tc.wantErr {
				t.Errorf("%s (chunk %d): err = %v, wantErr %v", tc.name, chunk, err, tc.wantErr)
			}
		}
	}
}

// The verdict must not depend on how the stream is split across reads and writes.
func FuzzMySQLScannerChunking(f *testing.F) {
	f.Add([]byte{0x0a, 0, 0, 0, 0x0a}, []byte{1, 0, 0, 0, 3}, uint8(3))
	f.Add(myPkt(0, []byte{3, 'x'}), myPkt(1, myLenEnc(9_000_000)), uint8(1))
	f.Fuzz(func(t *testing.T, client, server []byte, split uint8) {
		evs := []myEv{{false, client}, {true, server}, {false, client}, {true, server}}
		whole := runMySQL(evs, 0, MySQLLimits{}) != nil
		cut := int(split)%7 + 1
		if got := runMySQL(evs, cut, MySQLLimits{}) != nil; got != whole {
			t.Fatalf("chunk %d verdict %v differs from whole-buffer %v", cut, got, whole)
		}
		if got := runMySQL(evs, 1, MySQLLimits{}) != nil; got != whole {
			t.Fatalf("byte-at-a-time verdict %v differs from whole-buffer %v", got, whole)
		}
	})
}

func pipeGuard(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	dial := MySQLGuardDialer(func(context.Context, string, string) (net.Conn, error) { return a, nil }, MySQLLimits{})
	c, err := dial(context.Background(), "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = b.Close() })
	return c, b
}

func TestMySQLGuardConnBenignAndOversized(t *testing.T) {
	c, s := pipeGuard(t)
	go func() {
		_, _ = s.Write(myPkt(0, append([]byte{0x0a}, make([]byte, 20)...)))
		buf := make([]byte, 64)
		_, _ = s.Read(buf) // handshake response
		_, _ = s.Write(myPkt(2, []byte{0, 0, 0, 2, 0, 0, 0}))
		_, _ = s.Read(buf) // command
		_, _ = s.Write(myPkt(1, myLenEnc(5_000_000)))
	}()
	buf := make([]byte, 128)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := c.Write(myResponse(0x820d, 40).data); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("ok: %v", err)
	}
	if _, err := c.Write(myCmd().data); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(buf)
	if n != 0 || !errors.Is(err, ErrMySQLLimit) {
		t.Fatalf("oversized header: read %d bytes, err %v; want 0 bytes and ErrMySQLLimit", n, err)
	}
	if _, err := c.Read(buf); !errors.Is(err, ErrMySQLLimit) {
		t.Fatalf("error must be sticky, got %v", err)
	}
	if _, err := c.Write([]byte{1}); !errors.Is(err, ErrMySQLLimit) {
		t.Fatalf("writes after a violation must fail, got %v", err)
	}
}

func TestMySQLGuardConnRefusesCompression(t *testing.T) {
	c, s := pipeGuard(t)
	go func() { _, _ = io.Copy(io.Discard, s) }()
	if _, err := c.Write(myPkt(0, make([]byte, 0))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(myResponse(0x820d|0x20, 40).data); !errors.Is(err, ErrMySQLLimit) {
		t.Fatalf("compress capability: err = %v, want ErrMySQLLimit", err)
	}
}

func TestMySQLGuardConnTLSStepsAside(t *testing.T) {
	c, s := pipeGuard(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		_, _ = s.Read(buf)
		_, _ = s.Write([]byte{0x16, 0x03, 0x03, 0xfd, 0xff, 0xff, 0xff, 0xff}) // "TLS" bytes shaped like a huge header
	}()
	if _, err := c.Write(myResponse(0x820d|0x800, 32).data); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err != nil || n == 0 {
		t.Fatalf("after SSLRequest the guard must pass bytes through, got n=%d err=%v", n, err)
	}
	<-done
}
