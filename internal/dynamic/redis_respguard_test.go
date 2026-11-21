package dynamic

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// fakeRedisHostileOnCommand speaks just enough RESP3 to get a go-redis client past
// its handshake (HELLO, CLIENT SETINFO, AUTH) and answers the first other command
// with reply. It returns the listener address.
func fakeRedisHostileOnCommand(t *testing.T, reply string) string {
	t.Helper()
	const helloMap = "%7\r\n+server\r\n+redis\r\n+version\r\n+7.2.0\r\n+proto\r\n:3\r\n+id\r\n:1\r\n+mode\r\n+standalone\r\n+role\r\n+master\r\n+modules\r\n*0\r\n"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	readCommand := func(r *bufio.Reader) (string, error) {
		line, err := r.ReadString('\n')
		if err != nil || len(line) < 3 || line[0] != '*' {
			return "", errors.New("not a command")
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil {
			return "", err
		}
		name := ""
		for i := 0; i < n; i++ {
			hdr, err := r.ReadString('\n')
			if err != nil || len(hdr) < 3 || hdr[0] != '$' {
				return "", errors.New("bad bulk header")
			}
			l, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
			if err != nil {
				return "", err
			}
			buf := make([]byte, l+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return "", err
			}
			if i == 0 {
				name = strings.ToUpper(string(buf[:l]))
			}
		}
		return name, nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					name, err := readCommand(r)
					if err != nil {
						return
					}
					switch name {
					case "HELLO":
						_, _ = c.Write([]byte(helloMap))
					case "CLIENT", "AUTH", "SELECT":
						_, _ = c.Write([]byte("+OK\r\n"))
					default:
						_, _ = c.Write([]byte(reply))
						_, _ = io.Copy(io.Discard, c) // hold the connection until the client closes it
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// A hostile server must not be able to make connectRedis allocate what the reply
// announces: the RESP guard closes the connection before go-redis sees the header.
func TestConnectRedisRejectsHostileDeclaredLengths(t *testing.T) {
	for _, reply := range []string{
		"$1000000000\r\nshort\r\n",
		"*100000000\r\n:1\r\n",
		"%50000000\r\n+k\r\n+v\r\n",
		"$9223372036854775807\r\nshort\r\n",
	} {
		addr := fakeRedisHostileOnCommand(t, reply)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		client, err := connectRedis(ctx, "redis://"+addr+"/0", true, true)
		cancel()
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		if client != nil {
			_ = client.Close()
			t.Fatalf("%q: connectRedis succeeded against a hostile server", reply)
		}
		if err == nil || !(errors.Is(err, netutil.ErrRESPLimit) || strings.Contains(err.Error(), "RESP reply rejected")) {
			t.Fatalf("%q: error = %v, want the RESP guard's rejection", reply, err)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
			t.Fatalf("%q: allocated %d MiB; the guard should stop it near zero", reply, grew>>20)
		}
		if elapsed > 8*time.Second {
			t.Fatalf("%q: took %s", reply, elapsed)
		}
	}
}
