package dynamic

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// FuzzDSNHostsCoverDriverHosts skips a host whose brackets stay unbalanced or
// nested after one layer is stripped, because the driver cannot dial it. This test
// is the evidence for that skip: against a live loopback listener, pgx connects for
// a plain loopback host (the control) and for none of the malformed bracket forms.
func TestPgxNeverDialsMalformedBracketHosts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	hits := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits <- struct{}{}
			_ = c.Close()
		}
	}()
	dials := func(host string) bool {
		s := fmt.Sprintf("host=%s port=%d connect_timeout=1 sslmode=disable user=u dbname=d", host, port)
		cfg, err := pgconn.ParseConfig(s)
		if err != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if c, _ := pgconn.ConnectConfig(ctx, cfg); c != nil {
			_ = c.Close(context.Background())
		}
		select {
		case <-hits:
			return true
		case <-time.After(150 * time.Millisecond):
			return false
		}
	}
	if !dials("127.0.0.1") {
		t.Fatal("control failed: pgx did not reach the loopback listener, so this test proves nothing")
	}
	for _, host := range []string{"[]", "[[]]", "[[127.0.0.1]]", "[[[127.0.0.1]]]", "[[127.0.0.1]", "[127.0.0.1", "127.0.0.1]"} {
		if dials(host) {
			t.Errorf("pgx reached the loopback listener for host=%s: the fuzz skip for bracket-malformed hosts is wrong", host)
		}
	}
}
