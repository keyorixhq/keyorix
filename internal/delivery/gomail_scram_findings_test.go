package delivery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail/smtp"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestSCRAMNotSelectedWithoutTLS is the Keyorix-side closure of finding
// TP1-GOMAIL-scram-iter (issue #4383). wneessen/go-mail v0.8.2 takes the PBKDF2
// iteration count of the SCRAM server-first message ("i=") from the relay and runs it
// with no upper bound, and its SMTPAuthAutoDiscover picked SCRAM whenever the relay
// listed it, with or without TLS. SMTPDelivery.newClient (and notifychan's
// EmailSink.newClient) configured that whenever a relay username is set, and
// DeliverSetupLink runs in the admin's create-user request: a relay, or anyone on the
// path of a tls=none connection, announcing i=2147483647 held the request for minutes
// of CPU that no I/O timeout interrupts.
//
// internal/smtpauth now chooses the mechanism: SCRAM only over TLS. This test drives
// the real path (newClient, buildMessage, DialAndSendWithContext) against the
// in-memory relay and asserts the client never starts SCRAM over a connection
// without TLS and the whole send costs under 100 ms. With TLS the count is bounded
// instead (internal/smtpauth tests: TestSCRAMRefusesHugeIterationCountBeforeDeriving).
//
// What this does NOT verify: a TLS connection (the in-memory relay cannot speak TLS).
func TestSCRAMNotSelectedWithoutTLS(t *testing.T) {
	sc := &smtpScript{
		ehlo:      []string{"AUTH SCRAM-SHA-256 SCRAM-SHA-1"},
		authStep:  []string{"334 ", "334 {scram}", "535 no"},
		scramIter: "2147483647",
	}
	rec := &smtpRecord{}
	cfg := SMTPSettings{Host: "relay.test", Port: 2525, From: fuzzFrom, TLS: smtpTLSNone, Username: fuzzSMTPUser, Password: fuzzSMTPPass}
	req := SetupLinkRequest{RecipientEmail: "alice@example.com", Link: "https://k/s"}

	// Run it off the test goroutine: before the fix this derives a key for minutes, and
	// the test must say so within seconds rather than hang the run.
	type result struct{ took time.Duration }
	done := make(chan result, 1)
	go func() {
		took, _ := sendViaPipe(t, cfg, req, sc, rec)
		done <- result{took}
	}()
	select {
	case r := <-done:
		if r.took > 100*time.Millisecond {
			t.Errorf("send against a relay announcing i=2147483647 took %v, want under 100ms", r.took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still deriving a SCRAM key 5s after a relay announced i=2147483647 over a connection without TLS")
	}
	for _, l := range rec.lines {
		if strings.HasPrefix(l, "AUTH SCRAM") {
			t.Errorf("the client started SCRAM without TLS: %q", rec.lines)
		}
	}
}

// Without TLS the mechanisms that remain are the ones that never put the password on
// the wire and cost nothing to answer; when the relay offers one next to SCRAM, that
// one is used.
func TestChallengeResponseStillUsedWithoutTLS(t *testing.T) {
	sc := &smtpScript{
		ehlo:     []string{"AUTH SCRAM-SHA-256 CRAM-MD5 PLAIN"},
		authStep: []string{"334 PDEyMzQ1Ni4xMjM0QHJlbGF5Pg==", "535 no"},
	}
	rec := &smtpRecord{}
	cfg := SMTPSettings{Host: "relay.test", Port: 2525, From: fuzzFrom, TLS: smtpTLSNone, Username: fuzzSMTPUser, Password: fuzzSMTPPass}
	req := SetupLinkRequest{RecipientEmail: "alice@example.com", Link: "https://k/s"}
	_, _ = sendViaPipe(t, cfg, req, sc, rec)
	var auth []string
	for _, l := range rec.lines {
		if strings.HasPrefix(l, "AUTH") {
			auth = append(auth, l)
		}
	}
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "AUTH CRAM-MD5") {
		t.Fatalf("want exactly one AUTH CRAM-MD5, got %q (all lines %q)", auth, rec.lines)
	}
	for _, l := range rec.lines {
		if strings.Contains(l, fuzzSMTPPass) {
			t.Errorf("the relay password reached the wire: %q", l)
		}
	}
}

// TestGoMailFindingSCRAMIterationsUnbounded still pins the upstream finding
// TP1-GOMAIL-scram-iter (#4383) in wneessen/go-mail v0.8.2, now at the library: its
// SCRAM takes the iteration count from the relay's server-first message and runs
// pbkdf2.Key with it, with no upper bound. Keyorix no longer reaches that code
// unbounded (internal/smtpauth selects SCRAM only over TLS and refuses a count above
// its bound before handing the message to go-mail), so this test is the signal for
// the day go-mail fixes it: it then reports the finding closed
// (guardrules.KnownFindingClosed); remove this test, and consider dropping the bound
// in internal/smtpauth, and close #4383.
//
// What this does NOT verify: the exact cost per iteration (machine-dependent);
// SCRAM-SHA-1, which shares the same code path.
func TestGoMailFindingSCRAMIterationsUnbounded(t *testing.T) {
	if testing.Short() {
		t.Skip("spends about a second of CPU on purpose")
	}
	run := func(iter string) (time.Duration, error) {
		a := smtp.ScramSHA256Auth("relay-user", "pw")
		first, err := a.Next(nil, true) // client-first: "n,,n=<user>,r=<nonce>"
		if err != nil {
			t.Fatalf("harness: client-first message: %v", err)
		}
		_, nonce, ok := strings.Cut(string(first), ",r=")
		if !ok {
			t.Fatalf("harness: no nonce in %q", first)
		}
		serverFirst := fmt.Sprintf("r=%ssrv,s=c2FsdA==,i=%s", nonce, iter)
		start := time.Now()
		_, err = a.Next([]byte(serverFirst), true)
		return time.Since(start), err
	}
	small, err := run("4096")
	if err != nil {
		t.Fatalf("harness: i=4096 refused: %v", err)
	}
	// 250x the small count (the ratio check needs 50x): about 0.15s plain and 1.5s
	// under -race.
	big, err := run("1024000")
	if err != nil {
		guardrules.KnownFindingClosed(t, "TP1-GOMAIL-scram-iter", fmt.Sprintf("go-mail now refuses i=1024000 (%v): #4383 is fixed upstream", err))
		return
	}
	if big < 50*small {
		t.Fatalf("i=1024000 took %v, i=4096 took %v: the iteration count no longer drives the cost", big, small)
	}
	t.Logf("go-mail SCRAM: i=4096: %v, i=1024000: %v", small, big)
}
