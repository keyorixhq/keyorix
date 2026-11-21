// Package smtpauth chooses the SMTP AUTH mechanism for the relay clients behind
// setup-link delivery and the email notification sink, instead of leaving it to
// go-mail's SMTPAuthAutoDiscover.
//
// The relay is the party that announces which mechanisms it offers, and a hostile
// one (an operator-configured host, or anyone in the path of a connection without
// TLS) picks the cheapest mechanism for itself and the costliest for us. go-mail's
// SCRAM takes the PBKDF2 iteration count from the relay's server-first message and
// runs it with no upper bound (finding TP1-GOMAIL-scram-iter, #4383), so a relay
// announcing i=2147483647 burns CPU inside the admin's create-user request, and a
// client I/O timeout does not interrupt CPU work. Two rules close that here:
//
//   - SCRAM, PLAIN and LOGIN are only used over TLS. Without TLS the only mechanisms
//     left are the ones that never send the password and cost nothing to answer
//     (CRAM-MD5, NTLM); a relay offering only SCRAM, PLAIN or LOGIN over a clear
//     connection gets no authentication attempt at all (ErrNoMechanism).
//   - Over TLS, SCRAM refuses an iteration count above MaxSCRAMIterations before it
//     computes anything.
//
// What this does not do: channel binding. go-mail's SCRAM-*-PLUS needs the TLS
// connection state, which a custom smtp.Auth is not given, so the -PLUS variants are
// not offered; plain SCRAM over a verified TLS connection is used instead.
package smtpauth

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	mail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
)

// MaxSCRAMIterations is the largest PBKDF2 iteration count a relay may ask for. Relays
// in use announce 4096 (RFC 7677's minimum) to a few hundred thousand; 1,000,000
// costs this client well under a second, where 2^31-1 costs minutes.
const MaxSCRAMIterations = 1_000_000

// ErrNoMechanism is returned when the relay offers no mechanism this connection may
// use. It wraps mail.ErrNoSupportedAuthDiscovered, the error go-mail's own discovery
// gave for the same situation, so callers that explain it keep working.
var ErrNoMechanism = fmt.Errorf("smtpauth: no usable AUTH mechanism for this connection: %w", mail.ErrNoSupportedAuthDiscovered)

// ErrSCRAMIterations is returned, before any key derivation, when the relay's SCRAM
// server-first message asks for more than MaxSCRAMIterations.
var ErrSCRAMIterations = errors.New("smtpauth: relay asked for an unreasonable SCRAM iteration count; refusing to authenticate")

// New returns the smtp.Auth to hand to mail.WithSMTPAuthCustom. host is the relay's
// host name (PLAIN and LOGIN check it against the server name).
func New(username, password, host string) smtp.Auth {
	return &auth{user: username, pass: password, host: host}
}

type auth struct {
	user, pass, host string
	inner            smtp.Auth
}

// Mechanism preference, strongest first, per connection class. SCRAM-SHA-1 stays
// behind SCRAM-SHA-256 for relays that offer nothing newer.
var (
	overTLS    = []string{"SCRAM-SHA-256", "SCRAM-SHA-1", "NTLM", "CRAM-MD5", "PLAIN", "LOGIN"}
	withoutTLS = []string{"NTLM", "CRAM-MD5"}
)

func (a *auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	order := withoutTLS
	if server.TLS {
		order = overTLS
	}
	for _, mech := range order {
		if !slices.ContainsFunc(server.Auth, func(s string) bool { return strings.EqualFold(s, mech) }) {
			continue
		}
		a.inner = a.build(mech)
		return a.inner.Start(server)
	}
	return "", nil, ErrNoMechanism
}

func (a *auth) build(mech string) smtp.Auth {
	switch mech {
	case "SCRAM-SHA-256":
		return &boundedSCRAM{Auth: smtp.ScramSHA256Auth(a.user, a.pass)}
	case "SCRAM-SHA-1":
		return &boundedSCRAM{Auth: smtp.ScramSHA1Auth(a.user, a.pass)}
	case "NTLM":
		return smtp.NTLMAuth(a.user, a.pass, "")
	case "CRAM-MD5":
		return smtp.CRAMMD5Auth(a.user, a.pass)
	case "PLAIN":
		return smtp.PlainAuth("", a.user, a.pass, a.host, false)
	default: // LOGIN
		return smtp.LoginAuth(a.user, a.pass, a.host, false)
	}
}

func (a *auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if a.inner == nil {
		return nil, ErrNoMechanism
	}
	return a.inner.Next(fromServer, more)
}

// boundedSCRAM is go-mail's SCRAM with the iteration count checked before it is used.
type boundedSCRAM struct{ smtp.Auth }

func (b *boundedSCRAM) Next(fromServer []byte, more bool) ([]byte, error) {
	if more && bytes.HasPrefix(fromServer, []byte("r=")) && scramIterations(fromServer) > MaxSCRAMIterations {
		return nil, ErrSCRAMIterations
	}
	return b.Auth.Next(fromServer, more)
}

// scramIterations is the largest "i=" count in a server-first message. go-mail reads
// the third comma-separated field; taking the largest of every field that looks like
// one means no placement of a count can get past the check. A field that is not a
// number counts as 0: go-mail fails on it by itself.
func scramIterations(serverFirst []byte) int {
	most := 0
	for part := range bytes.SplitSeq(serverFirst, []byte(",")) {
		v, ok := bytes.CutPrefix(part, []byte("i="))
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(string(v)); err == nil && n > most {
			most = n
		}
	}
	return most
}
