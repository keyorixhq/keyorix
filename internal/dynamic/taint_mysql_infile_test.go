//go:build taintoverlay

package dynamic

// Server-originated taint (see internal/fuzzutil/taint): a rogue MySQL-protocol
// server answers the first statement with a LOCAL INFILE request whose file name
// is the oracle marker, i.e. every string the server supplies carries the marker.
// The fuzz input picks one DSN option name from the mechanically mined
// vocabulary (testdata/taint-keys.txt) and sets it to "true". If any option
// makes the driver open the server-requested name, the marker reaches os.OpenFile.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintMySQLServerInfile ./internal/dynamic

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

func taintRogueWrite(c net.Conn, seq byte, p []byte) {
	h := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}
	_, _ = c.Write(append(h, p...))
}

func taintRogueRead(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	b := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
	_, err := io.ReadFull(c, b)
	return b, err
}

// taintRogueMySQL is the rogue server of TestMySQLEngineNeverSendsLocalFilesToTheServer
// with the requested file name fixed to the marker.
func taintRogueMySQL(l net.Listener, want string) {
	c, err := l.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	hs := []byte{10}
	hs = append(hs, []byte("5.7.0-rogue\x00")...)
	hs = append(hs, 1, 0, 0, 0)
	hs = append(hs, []byte("abcdefgh\x00")...)
	caps := uint32(0x0200 | 0x8000 | 0x80000 | 0x0008 | 0x0001 | 0x00800000 | 0x00020000)
	hs = append(hs, byte(caps), byte(caps>>8), 33, 2, 0, byte(caps>>16), byte(caps>>24), 21)
	hs = append(hs, make([]byte, 10)...)
	hs = append(hs, []byte("ijklmnopqrst\x00")...)
	hs = append(hs, []byte("mysql_native_password\x00")...)
	taintRogueWrite(c, 0, hs)
	_, _ = taintRogueRead(c)
	taintRogueWrite(c, 2, []byte{0, 0, 0, 2, 0, 0, 0})
	for {
		p, err := taintRogueRead(c)
		if err != nil {
			return
		}
		if len(p) > 0 && p[0] == 3 {
			taintRogueWrite(c, 1, append([]byte{0xfb}, []byte(want)...))
			for {
				d, err := taintRogueRead(c)
				if err != nil || len(d) == 0 {
					break
				}
			}
			taintRogueWrite(c, 4, []byte{0, 0, 0, 2, 0, 0, 0})
			return
		}
		taintRogueWrite(c, 1, []byte{0, 0, 0, 2, 0, 0, 0})
	}
}

func FuzzTaintMySQLServerInfile(f *testing.F) {
	keys := strings.Fields(taintMySQLKeysRaw)
	f.Add(uint16(0))
	f.Fuzz(func(t *testing.T, keyIdx uint16) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		taint.ResetRules() // no rules: the loopback address never carries the marker
		defer taint.Check(t.Fatalf)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer func() { _ = l.Close() }()
		go taintRogueMySQL(l, taint.Marker())
		e := &MySQLEngine{allowPrivateNetwork: true}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		d := fmt.Sprintf("root:x@tcp(%s)/db?timeout=2s&%s=true", l.Addr(), keys[int(keyIdx)%len(keys)])
		func() {
			defer func() { _ = recover() }() // driver panics are another fuzz target's business
			_, _, _ = e.Issue(ctx, d, "", time.Minute)
		}()
	})
}
