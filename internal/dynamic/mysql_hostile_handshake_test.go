package dynamic

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestOpenMySQL_ShortHandshake_PanicIsSynchronous drives the real openMySQL
// (the function Issue and Revoke call) against a loopback server that answers
// with a 2-byte initial handshake. go-sql-driver/mysql slices that packet
// without a length check and panics. This test establishes WHERE the panic
// surfaces: in the calling goroutine (so a recover() in the request or
// scheduler goroutine contains it) rather than in a goroutine the library or
// database/sql started (which no caller could recover). It does not prove what
// any recover() in the server does; that is traced separately in the report.
func TestOpenMySQL_ShortHandshake_PanicIsSynchronous(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		// packet: length 2, sequence 0, protocol version 0x0a + NUL.
		_, _ = c.Write([]byte{0x02, 0x00, 0x00, 0x00, 0x0a, 0x00})
		time.Sleep(500 * time.Millisecond)
	}()
	dsn := fmt.Sprintf("u:p@tcp(%s)/db?timeout=3s&readTimeout=3s", ln.Addr().String())

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = openMySQL(context.Background(), dsn, true)
	}()
	if recovered == nil {
		t.Skip("openMySQL did not panic: the library may have been fixed")
	}
	if !strings.Contains(fmt.Sprint(recovered), "out of range") {
		t.Fatalf("unexpected panic: %v", recovered)
	}
	t.Logf("panic recovered in the calling goroutine: %v", recovered)
}
