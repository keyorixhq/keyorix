package smtphostile

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the go-mail hostile-SMTP-server target onto resguard. The existing
// oracles (no-panic, bounded-time, no goroutine/fd leak, password-never-on-wire,
// password-never-in-error) are UNCHANGED. resguard adds:
//   - the AIR-GAP oracle (NetMeter): the client's dial is routed through
//     NetMeter.DialContext, so ANY non-loopback dial fails the input. The hostile
//     server is loopback, so a benign run passes; a client that tried to reach the
//     real network (DNS, a redirect, a misconfig) turns an input into a reproducer.
//   - net_bytes_in / net_bytes_out recording (response/request size signal).
//   - alloc_bytes / mallocs (fatal per-byte slope): a response-line parser that
//     allocated super-linearly on a hostile dialogue (e.g. an over-long EHLO line)
//     is caught.
//
// What the resguard oracle does NOT verify here: it does NOT meter go-mail's
// internal timeout sleeps (go-mail uses context deadlines / net timeouts, not an
// injectable clock seam, so SleepClock is not wired — the existing bounded-time
// oracle and the 2 s context deadline bound wall time instead). net_bytes_in is
// ~linear in the script size (the client reads what the loopback server sends), so
// it is a size SIGNAL, not an amplification signal, for this echo-style server.
// CPU/wall/goroutines advisory.

const rgBudgetPath = "testdata/resguard-smtp.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

// rgDial runs one SMTP dialogue (hostile loopback server pre-sending `script`)
// through a real go-mail client whose dial is routed via the NetMeter, and
// returns the measured Cost. hostOverride != "" replaces the loopback host (used
// by the air-gap RED case to drive a non-loopback dial, which NetMeter blocks and
// counts without ever opening a real socket).
func rgDial(tb testing.TB, p *resguard.Probe, net0 *resguard.NetMeter, script []byte, hostOverride string) resguard.Cost {
	tb.Helper()
	srv := hostile.NewServer(tb, func(c net.Conn) {
		_, _ = c.Write(script)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			_ = n
			if err != nil {
				return
			}
		}
	})
	defer srv.Close()

	host, portStr := srv.HostPort()
	port := atoiSafe(portStr)
	if hostOverride != "" {
		host = hostOverride
	}

	client, err := mail.NewClient(host,
		mail.WithPort(port),
		mail.WithTimeout(2*time.Second),
		mail.WithTLSPolicy(mail.NoTLS),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
		mail.WithUsername(smtpUsername),
		mail.WithPassword(smtpPasswordCanary),
		mail.WithDialContextFunc(net0.DialContext),
	)
	if err != nil {
		tb.Fatalf("harness bug: mail.NewClient: %v", err)
	}
	msg := mail.NewMsg()
	_ = msg.From("sender@keyorix.example")
	_ = msg.To("recipient@keyorix.example")
	msg.Subject("Set up your Keyorix access")
	msg.SetBodyString(mail.TypeTextPlain, "single-use setup link\n")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return p.Measure(len(script), func() {
		_ = client.DialAndSendWithContext(ctx, msg)
	})
}

func rgBenignCorpus() [][]byte {
	return [][]byte{
		[]byte("220 hostile ESMTP ready\r\n250-hostile greets you\r\n250 SIZE 10485760\r\n250 OK\r\n250 OK\r\n354 start mail input\r\n250 queued\r\n221 bye\r\n"),
		[]byte("220 ok\r\n250 SIZE 0\r\n"),
		[]byte("421 service not available\r\n"),
		[]byte("220-multi\r\n220-line\r\n220 greeting\r\n250 ok\r\n"),
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, script := range rgBenignCorpus() {
		for range 3 {
			nm := resguard.NewNetMeter()
			p := resguard.New(tb, resguard.Options{SampleEvery: 1, Net: nm})
			costs = append(costs, rgDial(tb, p, nm, script, ""))
		}
	}
	b := resguard.Calibrate("smtp_dialogue", costs, resguard.DefaultFactor)
	// Keep only per-input-attributable meters: a live TLS-less client + loopback
	// server still spins server goroutines and pools, so the process-global memory
	// meters are noisy (RSG2 KeepOnly lesson). alloc_bytes is kept as the parser
	// signal; net_bytes_in/out are the size signal. Air-gap (NonLoopbackDials) is
	// checked independently of the meter set and is never dropped.
	b.KeepOnly("alloc_bytes", "net_bytes_in", "net_bytes_out")
	return b
}

func TestResguardSMTPCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no meters calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardSMTPRedGreen proves the AIR-GAP oracle with a REAL red: GREEN is a
// benign loopback dialogue (zero non-loopback dials, passes). RED points the
// client at a non-loopback address; NetMeter blocks and counts the dial (no real
// socket is opened) and the air-gap oracle fires. No production code is modified.
func TestResguardSMTPRedGreen(t *testing.T) {
	b := rgCalibrate(t)
	script := rgBenignCorpus()[0]

	// GREEN: loopback.
	nmG := resguard.NewNetMeter()
	pG := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nmG})
	green := rgDial(t, pG, nmG, script, "")
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign loopback dialogue tripped the budget: nonloopback=%d net_in=%d alloc=%d",
			green.NonLoopbackDials, green.NetBytesIn, green.AllocBytes)
	}
	if green.NonLoopbackDials != 0 {
		t.Fatalf("benign dialogue recorded %d non-loopback dials (expected 0)", green.NonLoopbackDials)
	}

	// RED: non-loopback destination — air-gap must fire.
	nmR := resguard.NewNetMeter()
	pR := resguard.New(t, resguard.Options{SampleEvery: 1, Net: nmR})
	red := rgDial(t, pR, nmR, script, "203.0.113.7") // TEST-NET-3, never routed
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("air-gap RED did not fire: non-loopback dial to 203.0.113.7 was not caught (nonloopback=%d)", red.NonLoopbackDials)
	}
	t.Logf("RED tripped (air-gap: %d non-loopback dial(s) to 203.0.113.7 blocked): %s", red.NonLoopbackDials, msg)
}
