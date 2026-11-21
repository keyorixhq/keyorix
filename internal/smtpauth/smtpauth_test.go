package smtpauth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
)

func start(t *testing.T, tls bool, mechs ...string) (smtp.Auth, string, error) {
	t.Helper()
	a := New("relay-user", "relay-pass", "relay.test")
	proto, _, err := a.Start(&smtp.ServerInfo{Name: "relay.test", TLS: tls, Auth: mechs})
	return a, proto, err
}

func TestMechanismSelection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tls   bool
		offer []string
		want  string // "" = ErrNoMechanism
	}{
		{"tls prefers scram-sha-256", true, []string{"PLAIN", "LOGIN", "SCRAM-SHA-1", "SCRAM-SHA-256"}, "SCRAM-SHA-256"},
		{"tls falls back to scram-sha-1", true, []string{"PLAIN", "SCRAM-SHA-1"}, "SCRAM-SHA-1"},
		{"tls cram-md5 before plain", true, []string{"PLAIN", "CRAM-MD5"}, "CRAM-MD5"},
		{"tls plain", true, []string{"LOGIN", "PLAIN"}, "PLAIN"},
		{"tls login", true, []string{"LOGIN"}, "LOGIN"},
		{"tls case-insensitive", true, []string{"scram-sha-256"}, "SCRAM-SHA-256"},
		{"tls nothing usable", true, []string{"XOAUTH2", "SCRAM-SHA-256-PLUS"}, ""},
		{"tls no AUTH at all", true, nil, ""},

		{"clear cram-md5", false, []string{"SCRAM-SHA-256", "PLAIN", "CRAM-MD5"}, "CRAM-MD5"},
		{"clear scram only", false, []string{"SCRAM-SHA-256", "SCRAM-SHA-1"}, ""},
		{"clear plain and login only", false, []string{"PLAIN", "LOGIN"}, ""},
		{"clear no AUTH at all", false, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, proto, err := start(t, tc.tls, tc.offer...)
			if tc.want == "" {
				if !errors.Is(err, ErrNoMechanism) || !errors.Is(err, mail.ErrNoSupportedAuthDiscovered) {
					t.Fatalf("want ErrNoMechanism (wrapping go-mail's no-auth error), got proto=%q err=%v", proto, err)
				}
				return
			}
			if err != nil || proto != tc.want {
				t.Fatalf("want %s, got proto=%q err=%v", tc.want, proto, err)
			}
		})
	}
}

func TestNextBeforeStartFails(t *testing.T) {
	if _, err := New("u", "p", "h").Next([]byte("x"), true); !errors.Is(err, ErrNoMechanism) {
		t.Fatalf("got %v", err)
	}
}

// serverFirst answers the client-first message of a started SCRAM exchange.
func serverFirst(t *testing.T, a smtp.Auth, iter string) []byte {
	t.Helper()
	first, err := a.Next(nil, true)
	if err != nil {
		t.Fatalf("client-first: %v", err)
	}
	_, nonce, ok := strings.Cut(string(first), ",r=")
	if !ok {
		t.Fatalf("no nonce in %q", first)
	}
	return []byte(fmt.Sprintf("r=%ssrv,s=c2FsdA==,i=%s", nonce, iter))
}

// A relay that announces the largest count costs the client nothing: the message is
// refused before any key derivation.
func TestSCRAMRefusesHugeIterationCountBeforeDeriving(t *testing.T) {
	for _, iter := range []string{"2147483647", "1000001", "9223372036854775807"} {
		a, _, err := start(t, true, "SCRAM-SHA-256")
		if err != nil {
			t.Fatal(err)
		}
		msg := serverFirst(t, a, iter)
		t0 := time.Now()
		_, err = a.Next(msg, true)
		took := time.Since(t0)
		if !errors.Is(err, ErrSCRAMIterations) {
			t.Fatalf("i=%s: want ErrSCRAMIterations, got %v", iter, err)
		}
		if took > 100*time.Millisecond {
			t.Errorf("i=%s: refusal took %v, want under 100ms", iter, took)
		}
	}
}

func TestSCRAMAcceptsOrdinaryIterationCounts(t *testing.T) {
	for _, iter := range []string{"4096", "310000", "600000", "1000000"} {
		for _, mech := range []string{"SCRAM-SHA-256", "SCRAM-SHA-1"} {
			a, _, err := start(t, true, mech)
			if err != nil {
				t.Fatal(err)
			}
			final, err := a.Next(serverFirst(t, a, iter), true)
			if err != nil || !strings.HasPrefix(string(final), "c=biws,r=") {
				t.Fatalf("%s i=%s: want a client-final message, got %q err=%v", mech, iter, final, err)
			}
		}
	}
}

// No placement of a count can get past the check, whichever field go-mail reads.
func TestScramIterationsReadsEveryCount(t *testing.T) {
	for in, want := range map[string]int{
		"r=n,s=c2FsdA==,i=4096":                 4096,
		"r=n,i=5,i=2147483647":                  2147483647,
		"r=n,i=2147483647,s=c2FsdA==":           2147483647,
		"r=n,s=c2FsdA==,i=+2147483647":          2147483647,
		"r=n,s=c2FsdA==,i=abc":                  0,
		"r=n,s=c2FsdA==,i=99999999999999999999": 0, // not a number to go-mail either
		"r=n,s=c2FsdA==,i=":                     0,
		"r=n,s=c2FsdA==":                        0,
		"r=n,s=c2FsdA==,xi=2147483647":          0,
		"r=n,s=c2FsdA==,i=-5":                   0,
	} {
		if got := scramIterations([]byte(in)); got != want {
			t.Errorf("%q: got %d, want %d", in, got, want)
		}
	}
}
