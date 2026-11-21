package netutil

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// memConn serves a fixed byte stream from memory so the benchmarks measure the guard,
// not a socket.
type memConn struct {
	r *bytes.Reader
}

func (m *memConn) Read(p []byte) (int, error)       { return m.r.Read(p) }
func (m *memConn) Write(p []byte) (int, error)      { return len(p), nil }
func (m *memConn) Close() error                     { return nil }
func (m *memConn) LocalAddr() net.Addr              { return nil }
func (m *memConn) RemoteAddr() net.Addr             { return nil }
func (m *memConn) SetDeadline(time.Time) error      { return nil }
func (m *memConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memConn) SetWriteDeadline(time.Time) error { return nil }

// resultStream is one command's response: a header for cols columns, the column
// definitions, then rows of about rowBytes each.
func resultStream(cols, rows, rowBytes int) []byte {
	var s []byte
	seq := byte(1)
	s = append(s, myPkt(seq, myLenEnc(uint64(cols)))...)
	for range cols {
		seq++
		s = append(s, myPkt(seq, append([]byte{3, 'd', 'e', 'f', 0, 0, 0, 1, 'c', 0}, make([]byte, 11)...))...)
	}
	row := make([]byte, rowBytes)
	for i := range row {
		row[i] = 'x'
	}
	for range rows {
		seq++
		s = append(s, myPkt(seq, row)...)
	}
	return s
}

func BenchmarkMySQLScannerThroughput(b *testing.B) {
	for _, tc := range []struct {
		name         string
		rows, rowLen int
	}{{"small-rows-50B", 20000, 50}, {"medium-rows-500B", 4000, 500}, {"large-rows-16KB", 200, 16 << 10}} {
		stream := resultStream(10, tc.rows, tc.rowLen)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(stream)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sc := newMySQLScanner(MySQLLimits{})
				_ = sc.feed(false, myPkt(0, []byte{3, 'q'}))
				for off := 0; off < len(stream); off += 16 << 10 {
					end := min(off+16<<10, len(stream))
					if err := sc.feed(true, stream[off:end]); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// Read through the wrapper versus the bare connection, both from memory in 16 KiB reads
// (the driver's buffer size): the difference is the guard's whole per-byte cost.
func BenchmarkMySQLGuardConnRead(b *testing.B) {
	stream := resultStream(10, 20000, 50)
	read := func(b *testing.B, c net.Conn, mem *memConn) {
		buf := make([]byte, 16<<10)
		b.SetBytes(int64(len(stream)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mem.r.Reset(stream)
			if _, err := c.Write(myPkt(0, []byte{3, 'q'})); err != nil {
				b.Fatal(err)
			}
			for {
				_, err := c.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	b.Run("bare", func(b *testing.B) {
		mem := &memConn{r: bytes.NewReader(stream)}
		read(b, mem, mem)
	})
	b.Run("guarded", func(b *testing.B) {
		mem := &memConn{r: bytes.NewReader(stream)}
		c, _ := MySQLGuardDialer(func(context.Context, string, string) (net.Conn, error) { return mem, nil }, MySQLLimits{})(context.Background(), "tcp", "x")
		read(b, c, mem)
	})
}
