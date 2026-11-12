package redisfuzz

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestRedis_ConnectSequence_Diag is a throwaway diagnostic: it logs every
// command the go-redis client sends during connect + one Do, so the harness
// knows exactly what the fake server must answer before it can stream
// fuzz-controlled reply bytes to the command-reply parser. Not an oracle.
func TestRedis_ConnectSequence_Diag(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, err := c.Read(buf)
			if n > 0 {
				t.Logf("server <- %q", buf[:n])
				// Reply -ERR to whatever the client sent so HELLO falls back to
				// RESP2 and the command returns an error (connection stays usable
				// long enough to observe the sequence).
				_ = c.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = c.Write([]byte("-ERR diag\r\n"))
			}
			if err != nil {
				return
			}
		}
	}()

	opt := &redis.Options{
		Addr:            ln.Addr().String(),
		Protocol:        3,
		Username:        "canaryuser",
		Password:        "s3cr3t-canary-pw-9f3a2b1c",
		DisableIdentity: true,
		DialTimeout:     time.Second,
		ReadTimeout:     300 * time.Millisecond,
		WriteTimeout:    300 * time.Millisecond,
		MaxRetries:      -1,
	}
	client := redis.NewClient(opt)
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := client.Do(ctx, "PING")
	t.Logf("Do(PING) -> val=%v err=%v", res.Val(), res.Err())
}
