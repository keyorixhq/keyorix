package notifychan

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/require"
)

// TestEmailSink_SCRAMNotSelectedWithoutTLS is the notifychan half of the closure of
// finding TP1-GOMAIL-scram-iter (#4383), mirroring internal/delivery's
// TestSCRAMNotSelectedWithoutTLS. go-mail v0.8.2 runs PBKDF2 with the iteration count
// the relay announces, unbounded, and its SMTPAuthAutoDiscover picked SCRAM with or
// without TLS. EmailSink.newClient now hands the choice to internal/smtpauth, which
// never starts SCRAM on a connection without TLS.
//
// The test drives the real path (EmailSink.send -> newClient -> DialAndSendWithContext)
// against a loopback relay that offers only SCRAM-SHA-256 and answers with
// i=2147483647, and asserts that no AUTH SCRAM line is sent and that the send returns
// promptly.
//
// What this does NOT verify: a TLS connection (the loopback relay cannot speak TLS);
// the bound over TLS is tested in internal/smtpauth.
func TestEmailSink_SCRAMNotSelectedWithoutTLS(t *testing.T) {
	port, lines := scramOnlySMTPServer(t, "2147483647")
	s := &EmailSink{cfg: EmailConfig{
		Host: "127.0.0.1", Port: port, From: "ops@x.io", TLS: "none",
		Username: "relay-user", Password: "relay-pass-placeholder",
	}}

	// Off the test goroutine: without the fix this derives a key for minutes, and the
	// test must say so within seconds rather than hang the run.
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_, _ = s.send(context.Background(), core.NotificationEvent{Email: "ada@x.io", Title: "t", Message: "m"})
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		// Refusing is instant; deriving the key takes minutes. 3s sits far from both
		// so a loaded runner cannot trip it.
		if took > 3*time.Second {
			t.Errorf("send against a relay announcing i=2147483647 took %v, want under 3s", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still deriving a SCRAM key 5s after a relay announced i=2147483647 over a connection without TLS")
	}
	for _, l := range lines() {
		require.False(t, strings.HasPrefix(strings.ToUpper(l), "AUTH SCRAM"), "the email sink started SCRAM without TLS: %q", lines())
	}
}

// scramOnlySMTPServer advertises only AUTH SCRAM-SHA-256 and no STARTTLS, and answers
// a SCRAM exchange with a server-first message carrying iter. lines returns every
// command line the client sent.
func scramOnlySMTPServer(t *testing.T, iter string) (port int, lines func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var got []string
	record := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(conn)
				writeLine := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				writeLine("220 fake.smtp ESMTP ready")
				inSCRAM := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(line)
					record(cmd)
					switch {
					case inSCRAM:
						// The client-first message: answer with a server-first message
						// that echoes the client nonce and asks for iter iterations.
						inSCRAM = false
						writeLine("334 " + scramServerFirst(cmd, iter))
					case strings.HasPrefix(cmd, "EHLO"):
						writeLine("250-fake.smtp")
						writeLine("250 AUTH SCRAM-SHA-256")
					case strings.HasPrefix(strings.ToUpper(cmd), "AUTH SCRAM"):
						inSCRAM = true
						writeLine("334 ")
					case strings.HasPrefix(cmd, "AUTH"):
						writeLine("535 5.7.8 unexpected AUTH")
					case strings.EqualFold(cmd, "QUIT"):
						writeLine("221 2.0.0 Bye")
						return
					default:
						writeLine("250 OK")
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// scramServerFirst builds a base64 server-first message for a base64 client-first
// message ("n,,n=<user>,r=<nonce>").
func scramServerFirst(clientFirstB64, iter string) string {
	nonce := ""
	if raw, err := base64.StdEncoding.DecodeString(clientFirstB64); err == nil {
		for part := range strings.SplitSeq(string(raw), ",") {
			if v, ok := strings.CutPrefix(part, "r="); ok {
				nonce = v
			}
		}
	}
	first := "r=" + nonce + "srv,s=c2FsdA==,i=" + iter
	return base64.StdEncoding.EncodeToString([]byte(first))
}
