package netutil

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
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
func myHeader(n uint64) myEv { return myEv{true, myPkt(1, myLenEnc(n))} }
func myRaw(p []byte) myEv    { return myEv{true, myPkt(1, p)} }

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
		{"0xfe short packet is EOF, not a header", session(myCmd(), myRaw([]byte{0xfe, 0, 0, 2, 0})), false},
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

// reference derives the verdict from the structured dialogue, with no byte state.
func myReference(evs []myEv, maxCols uint64) bool {
	armed, sealed := false, false
	for _, e := range evs {
		if sealed {
			return false
		}
		d := e.data
		for len(d) >= 4 {
			plen := int(d[0]) | int(d[1])<<8 | int(d[2])<<16
			seq := d[3]
			pl := d[4:]
			if plen < len(pl) {
				pl = pl[:plen]
			}
			if e.server {
				if armed {
					armed = false
					if len(pl) > 0 {
						b := pl[0]
						var cols uint64
						switch {
						case b == 0 || b == 0xff || b == 0xfb:
						case b < 0xfb:
							cols = uint64(b)
						case b == 0xfc:
							if plen < 3 {
								return true
							}
							cols = uint64(binary.LittleEndian.Uint16(pl[1:3]))
						case b == 0xfd:
							if plen < 4 {
								return true
							}
							cols = uint64(pl[1]) | uint64(pl[2])<<8 | uint64(pl[3])<<16
						default:
							if plen >= 9 {
								cols = binary.LittleEndian.Uint64(pl[1:9])
							}
						}
						if cols > maxCols {
							return true
						}
					}
				}
			} else {
				if seq == 0 {
					armed = true
				}
				if seq == 1 && plen >= 4 {
					caps := binary.LittleEndian.Uint32(pl[:4])
					if caps&0x20 != 0 {
						return true
					}
					if plen == 32 && caps&0x800 != 0 {
						sealed = true
						break
					}
				}
			}
			d = d[4+plen:]
		}
	}
	return false
}

func TestMySQLScannerMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	counts := []uint64{0, 1, 5, 250, 251, 1000, 65535, 65536, 65537, 1 << 24, 1 << 40, ^uint64(0)}
	for i := 0; i < 20000; i++ {
		var evs []myEv
		for k, n := 0, 1+rng.Intn(8); k < n; k++ {
			switch rng.Intn(7) {
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
			default:
				evs = append(evs, myGreeting())
			}
		}
		want := myReference(evs, DefaultMySQLMaxColumns)
		for _, chunk := range []int{0, 1, 3} {
			if got := runMySQL(evs, chunk, MySQLLimits{}) != nil; got != want {
				t.Fatalf("case %d chunk %d: scanner violation=%v, reference=%v", i, chunk, got, want)
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
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if n, err := c.Read(buf); err != nil || n == 0 {
		t.Fatalf("after SSLRequest the guard must pass bytes through, got n=%d err=%v", n, err)
	}
	<-done
}
