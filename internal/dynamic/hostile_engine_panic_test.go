package dynamic_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
)

// DYNAMIC-ENGINE-PANIC-1 item 1 (#4133): every engine that wraps a third-party
// client is pointed at an in-process hostile target that answers with a malformed
// frame. A panic in the client library must never reach the caller of Issue, Revoke
// or Renew (core code that holds a lease row or an uncommitted audit step): the
// call returns, with an error or without one.
//
// The loopback server here is local to the test: fuzz/thirdparty/internal/hostile is
// a Go internal package of the fuzz tree and cannot be imported from internal/dynamic.

// hostileCase is one malformed answer for one wire protocol.
type hostileCase struct {
	name  string
	stage string // protocol-specific: where in the conversation the frame is sent
	frame []byte
}

func serveHostile(t *testing.T, handler func(c net.Conn)) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener (environment): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				handler(c)
			}()
		}
	}()
	host, port, _ = net.SplitHostPort(ln.Addr().String())
	return host, port
}

// ---- PostgreSQL ---------------------------------------------------------------

func pgMsg(typ byte, payload ...byte) []byte {
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)+4))
	return append(out, payload...)
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func pgReady() []byte  { return pgMsg('Z', 'I') }
func pgAuthOK() []byte { return pgMsg('R', be32(0)...) }

var pgCases = []hostileCase{
	{"auth-no-type", "startup", pgMsg('R')},
	{"auth-md5-short-salt", "startup", pgMsg('R', append(be32(5), 1, 2)...)},
	{"auth-sasl-empty", "startup", pgMsg('R', be32(10)...)},
	{"auth-sasl-continue-garbage", "startup", pgMsg('R', append(be32(11), 'x')...)},
	{"auth-sasl-final-garbage", "startup", pgMsg('R', append(be32(12), 'v', '=')...)},
	{"param-status-unterminated", "startup", append(pgAuthOK(), pgMsg('S', 'a', 'b', 'c')...)},
	{"backend-key-short", "startup", append(pgAuthOK(), pgMsg('K', 1, 2)...)},
	{"ready-empty", "startup", append(pgAuthOK(), pgMsg('Z')...)},
	{"error-unterminated", "startup", pgMsg('E', 'S')},
	{"row-desc-huge-count", "query", pgMsg('T', 0x7f, 0xff)},
	{"row-desc-short-field", "query", pgMsg('T', 0, 1, 'a')},
	{"data-row-huge-count", "query", pgMsg('D', 0x7f, 0xff)},
	{"data-row-negative-len", "query", pgMsg('D', 0, 1, 0x80, 0, 0, 0)},
	{"command-complete-empty", "query", pgMsg('C')},
	{"error-truncated", "query", pgMsg('E', 'C', '4')},
	{"copy-in-short", "query", pgMsg('G', 0)},
	{"param-desc-huge", "query", pgMsg('t', 0xff, 0xff)},
	{"notification-short", "query", pgMsg('A', 0, 0)},
}

func pgHandler(tc hostileCase) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			var lb [4]byte
			if _, err := io.ReadFull(r, lb[:]); err != nil {
				return
			}
			body := make([]byte, int(binary.BigEndian.Uint32(lb[:]))-4)
			if _, err := io.ReadFull(r, body); err != nil {
				return
			}
			if len(body) == 4 && binary.BigEndian.Uint32(body) == 80877103 { // SSLRequest
				_, _ = c.Write([]byte{'N'})
				continue
			}
			break
		}
		if tc.stage == "startup" {
			_, _ = c.Write(tc.frame)
			return
		}
		_, _ = c.Write(append(pgAuthOK(), pgReady()...))
		for {
			typ, err := r.ReadByte()
			if err != nil {
				return
			}
			var lb [4]byte
			if _, err := io.ReadFull(r, lb[:]); err != nil {
				return
			}
			if n := int(binary.BigEndian.Uint32(lb[:])) - 4; n > 0 {
				if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
					return
				}
			}
			if typ == 'Q' || typ == 'S' {
				_, _ = c.Write(tc.frame)
				return
			}
		}
	}
}

// ---- MySQL --------------------------------------------------------------------

func myFrame(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

func myGreetingPayload() []byte {
	const caps = 0x00000001 | 0x00000004 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00020000 | 0x00080000 | 0x00200000
	p := []byte{0x0a}
	p = append(p, []byte("8.0.40")...)
	p = append(p, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0)
	p = binary.LittleEndian.AppendUint16(p, caps&0xffff)
	p = append(p, 0x2d)
	p = binary.LittleEndian.AppendUint16(p, 2)
	p = binary.LittleEndian.AppendUint16(p, caps>>16)
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0)
	p = append(p, []byte("mysql_native_password")...)
	return append(p, 0)
}

var myCases = []hostileCase{
	{"greeting-version-only", "greeting", myFrame(0, []byte{0x0a})},
	{"greeting-unterminated-version", "greeting", myFrame(0, []byte{0x0a, '8', '.', '0'})},
	{"greeting-short-scramble", "greeting", myFrame(0, append([]byte{0x0a, '8', 0, 1, 0, 0, 0}, 1, 2, 3))},
	{"auth-switch-empty", "auth", myFrame(2, []byte{0xfe})},
	{"auth-switch-no-data", "auth", myFrame(2, append([]byte{0xfe}, []byte("mysql_native_password")...))},
	{"auth-more-data-empty", "auth", myFrame(2, []byte{0x01})},
	{"auth-err-short", "auth", myFrame(2, []byte{0xff, 0x01})},
	{"ok-short", "query", myFrame(1, []byte{0x00})},
	{"ok-truncated-lenenc", "query", myFrame(1, []byte{0x00, 0xfc, 0x01})},
	{"err-short", "query", myFrame(1, []byte{0xff})},
	{"column-count-huge", "query", myFrame(1, []byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})},
	{"column-def-truncated", "query", append(myFrame(1, []byte{0x01}), myFrame(2, []byte{0x03, 'd', 'e', 'f'})...)},
	{"local-infile-short", "query", myFrame(1, []byte{0xfb})},
	{"eof-short", "query", myFrame(1, []byte{0xfe, 0x00})},
}

func myHandler(tc hostileCase) func(net.Conn) {
	return func(c net.Conn) {
		if tc.stage == "greeting" {
			_, _ = c.Write(tc.frame)
			return
		}
		_, _ = c.Write(myFrame(0, myGreetingPayload()))
		r := bufio.NewReader(c)
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, r, int64(h[0])|int64(h[1])<<8|int64(h[2])<<16); err != nil {
			return
		}
		if tc.stage == "auth" {
			_, _ = c.Write(tc.frame)
			return
		}
		_, _ = c.Write(myFrame(2, []byte{0, 0, 0, 2, 0, 0, 0}))
		for { // answer the first command after the handshake (and each later one) alike
			if _, err := io.ReadFull(r, h[:]); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, r, int64(h[0])|int64(h[1])<<8|int64(h[2])<<16); err != nil {
				return
			}
			_, _ = c.Write(tc.frame)
		}
	}
}

// ---- Redis (RESP) -------------------------------------------------------------

var redisCases = []hostileCase{
	{"bare-array-marker", "any", []byte("*")},
	{"negative-array-len", "any", []byte("*-5\r\n")},
	// Length-prefix frames announcing gigabytes (array/bulk/map) are deliberately not
	// here: one of them makes the client allocate >6 GB, which is a memory-bound
	// finding, not a panic, and kills the test process. Tracked in the report.
	{"negative-bulk-len", "any", []byte("$-2\r\n")},
	{"empty-simple-string", "any", []byte("+")},
	{"empty-error", "any", []byte("-\r\n")},
	{"non-numeric-int", "any", []byte(":abc\r\n")},
	{"set-negative", "any", []byte("~-3\r\n")},
	{"push-short", "any", []byte(">\r\n")},
	{"attribute-nested", "any", []byte("|1\r\n+a\r\n|1\r\n")},
	{"nested-arrays", "any", []byte("*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*-1\r\n")},
	{"unknown-type", "any", []byte("?x\r\n")},
	{"verbatim-short", "any", []byte("=3\r\nab\r\n")},
	{"double-garbage", "any", []byte(",1e\r\n")},
	{"bignum-garbage", "any", []byte("(zz\r\n")},
}

func redisHandler(tc hostileCase) func(net.Conn) {
	return func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
			if _, err := c.Write(tc.frame); err != nil {
				return
			}
		}
	}
}

// ---- MongoDB (OP_MSG / OP_REPLY) ----------------------------------------------

func mongoMsg(op uint32, length int32, body []byte) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:], uint32(length))
	binary.LittleEndian.PutUint32(h[4:], 1)
	binary.LittleEndian.PutUint32(h[8:], 1)
	binary.LittleEndian.PutUint32(h[12:], op)
	return append(h, body...)
}

var mongoCases = []hostileCase{
	{"header-only", "any", mongoMsg(2013, 16, nil)},
	{"length-below-header", "any", mongoMsg(2013, 4, nil)},
	{"length-huge", "any", mongoMsg(2013, 0x7fffffff, []byte{0, 0, 0, 0})},
	{"length-negative", "any", mongoMsg(2013, -1, nil)},
	{"flags-only", "any", mongoMsg(2013, 20, []byte{0, 0, 0, 0})},
	{"kind0-doc-len-5-missing", "any", mongoMsg(2013, 26, []byte{0, 0, 0, 0, 0, 5, 0, 0, 0, 0})},
	{"kind0-doc-len-huge", "any", mongoMsg(2013, 26, []byte{0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0})},
	{"kind0-string-neg-len", "any", mongoMsg(2013, 36, []byte{0, 0, 0, 0, 0, 14, 0, 0, 0, 2, 'a', 0, 0xff, 0xff, 0xff, 0xff, 0, 0})},
	{"kind1-sequence-short", "any", mongoMsg(2013, 25, []byte{0, 0, 0, 0, 1, 4, 0, 0, 0})},
	{"kind-unknown", "any", mongoMsg(2013, 21, []byte{0, 0, 0, 0, 9})},
	{"op-reply-short", "any", mongoMsg(1, 24, []byte{0, 0, 0, 0, 0, 0, 0, 0})},
	{"op-compressed-short", "any", mongoMsg(2012, 20, []byte{0, 0, 0, 0})},
	{"op-unknown", "any", mongoMsg(31337, 16, nil)},
}

func mongoHandler(tc hostileCase) func(net.Conn) {
	return func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
			if _, err := c.Write(tc.frame); err != nil {
				return
			}
		}
	}
}

// ---- driver -------------------------------------------------------------------

type engineTarget struct {
	backend string
	cases   []hostileCase
	handler func(hostileCase) func(net.Conn)
	dsn     func(host, port string) string
}

var engineTargets = []engineTarget{
	{"postgres", pgCases, pgHandler, func(h, p string) string {
		return fmt.Sprintf("postgres://admin:s3cret@%s:%s/app?sslmode=disable&connect_timeout=2", h, p)
	}},
	{"mysql", myCases, myHandler, func(h, p string) string {
		return fmt.Sprintf("admin:s3cret@tcp(%s:%s)/app?timeout=2s&readTimeout=2s&writeTimeout=2s", h, p)
	}},
	{"redis", redisCases, redisHandler, func(h, p string) string {
		return fmt.Sprintf("redis://admin:s3cret@%s:%s/0", h, p)
	}},
	{"mongodb", mongoCases, mongoHandler, func(h, p string) string {
		return fmt.Sprintf("mongodb://admin:s3cret@%s:%s/admin?directConnection=true&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000&socketTimeoutMS=2000", h, p)
	}},
}

// callEngine runs fn and reports whether it panicked.
func callEngine(fn func()) (panicked bool, val any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, val = true, r
		}
	}()
	fn()
	return false, nil
}

func TestHostileTargetNeverPanicsIntoCaller(t *testing.T) {
	ops := []struct {
		name string
		run  func(ctx context.Context, e dynamic.CredentialEngine, dsn string)
	}{
		{"Issue", func(ctx context.Context, e dynamic.CredentialEngine, dsn string) {
			_, _, _ = e.Issue(ctx, dsn, "", time.Hour)
		}},
		{"Revoke", func(ctx context.Context, e dynamic.CredentialEngine, dsn string) {
			_ = e.Revoke(ctx, dsn, "kx_dyn_probe")
		}},
		{"Renew", func(ctx context.Context, e dynamic.CredentialEngine, dsn string) {
			_ = e.Renew(ctx, dsn, "kx_dyn_probe", time.Now().Add(time.Hour))
		}},
	}
	for _, tg := range engineTargets {
		for _, tc := range tg.cases {
			for _, op := range ops {
				t.Run(tg.backend+"/"+tc.name+"/"+op.name, func(t *testing.T) {
					host, port := serveHostile(t, tg.handler(tc))
					eng, err := dynamic.New(tg.backend, true, true)
					if err != nil {
						t.Fatalf("dynamic.New(%q): %v", tg.backend, err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
					defer cancel()
					if panicked, val := callEngine(func() { op.run(ctx, eng, tg.dsn(host, port)) }); panicked {
						t.Errorf("PANIC escaped %s.%s on %q: %T", tg.backend, op.name, tc.name, val)
					}
				})
			}
		}
	}
}
