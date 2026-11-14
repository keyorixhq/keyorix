// Hostile-SERVER fuzz harness for github.com/wneessen/go-mail, the SMTP client
// Keyorix uses to deliver a new principal's single-use setup link
// (internal/delivery/smtp.go) and operational notification emails
// (internal/notifychan/email.go) through the OPERATOR-CONFIGURED mail relay
// (credential_delivery.smtp.host/port, notify.email.host/port).
//
// Threat model: the configured SMTP relay is attacker-controlled (the operator
// pointed it at a hostile host, or an on-path attacker owns it) and replies with
// hostile SMTP dialogue bytes — a mutated greeting, EHLO capability list,
// multiline continuation responses, over-long lines. Keyorix's real call is
// mail.NewClient(host, ...).DialAndSendWithContext(ctx, msg) (see
// SMTPDelivery.newClient). This harness drives that exact client against a
// loopback TCP server whose entire server-side script is fuzzer-controlled.
//
// The client is built with WithTLSPolicy(mail.NoTLS) so the dialogue is plaintext
// and every server byte is fuzzer-chosen — this exercises go-mail's SMTP
// response-line / textproto parser directly, the SAME parser the STARTTLS and
// implicit-TLS production paths reach once their TLS layer is up. Auth is
// configured (AutoDiscover + username + a PASSWORD CANARY) exactly as production
// does when credentials are present.
//
// Oracles (sound only):
//   - Panic: no panic escapes go-mail's documented error return (RunGuarded).
//   - Bounded time: DialAndSendWithContext returns within the guard deadline even
//     against a slow/greedy dialogue (the per-conn 4s server deadline in
//     hostile.NewServer plus the client's own WithTimeout bound it).
//   - No goroutine / fd leak after the call returns (CheckNoLeak).
//   - Credential confidentiality on the wire: with TLS disabled, go-mail must
//     NEVER transmit the configured password to the relay (SMTPAuthAutoDiscover
//     drops PLAIN/LOGIN without TLS — it will not send a cleartext password). The
//     harness records EVERY byte the client sends and asserts the password canary
//     never appears in them.
//   - Credential confidentiality in errors: the password canary must never appear
//     in the returned error string (AssertNoSecretInError).
//
// What these oracles do NOT verify (stated, per the method):
//   - NOT error-on-malformed-response. go-mail legitimately returns success
//     whenever the fuzzer happens to emit a fully valid 220→EHLO→MAIL→RCPT→DATA
//     dialogue, and deciding "this response SHOULD have been rejected" would mean
//     reimplementing the SMTP state machine — an unsound reference oracle. Error
//     vs success is left to the panic/time/leak/credential oracles.
//   - NOT the TLS transport (STARTTLS upgrade, implicit-TLS handshake, cert
//     verification). Only the plaintext dialogue parser is fuzzed here; TLS
//     correctness is delegated to go-mail and asserted elsewhere.
//   - NOT message-body/header injection (CRLF smuggling) into the rendered email;
//     that is a client-input concern, not a hostile-server one.
package smtphostile

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/cloudfuzz"
	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// smtpPasswordCanary is the password this harness's client is configured with —
// the value the credential-confidentiality oracles scan for. Distinctive so a
// substring match cannot be a coincidence.
const smtpPasswordCanary = "sMtP-PaSsWoRd-CaNaRy-7e91xy-do-not-send-cleartext"

const smtpUsername = "relay-user@keyorix.example"

func FuzzSMTPDialogue(f *testing.F) {
	// A minimal valid dialogue (greeting, EHLO reply, and per-command OKs) so the
	// mutator starts from a corpus that actually walks go-mail through EHLO and on
	// toward MAIL/RCPT/DATA, not just a rejected greeting.
	f.Add([]byte("220 hostile ESMTP ready\r\n" +
		"250-hostile greets you\r\n250 SIZE 10485760\r\n" + // EHLO reply (multiline)
		"250 OK\r\n" + // MAIL FROM
		"250 OK\r\n" + // RCPT TO
		"354 start mail input\r\n" + // DATA
		"250 queued\r\n" + // end of data
		"221 bye\r\n"))
	f.Add([]byte("220 ok\r\n250 SIZE 0\r\n")) // truncated after EHLO
	f.Add([]byte("421 service not available\r\n"))
	f.Add([]byte("200 wrong-code greeting\r\n"))       // non-standard greeting code
	f.Add([]byte("250-a\r\n250-b\r\n250-c\r\n250 d\r\n")) // no 220 greeting at all
	f.Add([]byte("220 \r\n"))                            // empty-text greeting
	f.Add([]byte(""))                                    // empty: immediate EOF
	f.Add([]byte("220-multi\r\n220-line\r\n220 greeting\r\n250 ok\r\n")) // multiline greeting
	f.Add(append([]byte("220 ok\r\n250 "), bytes.Repeat([]byte("X"), 70000)...)) // over-long EHLO line
	f.Add([]byte("220 ok\r\n250 AUTH PLAIN LOGIN\r\n"))                            // advertise cleartext auth under NoTLS

	f.Fuzz(func(t *testing.T, script []byte) {
		var recordedMu = make(chan struct{}, 1)
		recordedMu <- struct{}{} // 1-slot mutex
		recorded := &bytes.Buffer{}

		srv := hostile.NewServer(t, func(c net.Conn) {
			// Pre-send the entire fuzzer-controlled server script. SMTP is
			// server-greets-first and lock-step, but TCP preserves order, so the
			// client consumes responses one at a time out of the socket buffer as
			// it issues each command. Then drain + RECORD everything the client
			// sends, so the credential-on-the-wire oracle can inspect it.
			_, _ = c.Write(script)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					<-recordedMu
					recorded.Write(buf[:n])
					recordedMu <- struct{}{}
				}
				if err != nil {
					return
				}
			}
		})
		defer srv.Close()

		host, portStr := srv.HostPort()
		port := atoiSafe(portStr)

		// Mirror SMTPDelivery.newClient's option set, forcing NoTLS so the
		// dialogue is the fuzzer-controlled plaintext stream.
		client, err := mail.NewClient(host,
			mail.WithPort(port),
			mail.WithTimeout(2*time.Second),
			mail.WithTLSPolicy(mail.NoTLS),
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(smtpUsername),
			mail.WithPassword(smtpPasswordCanary),
		)
		if err != nil {
			t.Fatalf("harness bug: mail.NewClient failed: %v", err)
		}

		msg := mail.NewMsg()
		if err := msg.From("sender@keyorix.example"); err != nil {
			t.Fatalf("harness bug: msg.From: %v", err)
		}
		if err := msg.To("recipient@keyorix.example"); err != nil {
			t.Fatalf("harness bug: msg.To: %v", err)
		}
		msg.Subject("Set up your Keyorix access")
		msg.SetBodyString(mail.TypeTextPlain, "single-use setup link: https://keyorix.example/setup/abc\n")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var sendErr error
		cloudfuzz.RunGuarded(t, "go-mail DialAndSendWithContext", func() {
			sendErr = client.DialAndSendWithContext(ctx, msg)
		})

		// Oracle: the password must never have been written to the wire under NoTLS.
		<-recordedMu
		onWire := recorded.String()
		recordedMu <- struct{}{}
		if bytes.Contains([]byte(onWire), []byte(smtpPasswordCanary)) {
			t.Fatalf("LEAK: the SMTP password was transmitted in cleartext to a TLS-disabled relay")
		}

		// Oracle: the password must never appear in the returned error string.
		cloudfuzz.AssertNoSecretInError(t, "go-mail DialAndSendWithContext", sendErr, smtpPasswordCanary)

		cloudfuzz.CheckNoLeak(t, "go-mail DialAndSendWithContext")
	})
}

// atoiSafe parses a port string without importing strconv at call sites; the
// hostile listener always yields a valid numeric port.
func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
