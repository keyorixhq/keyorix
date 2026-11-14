package notifychan

// notify_mail_injection_fuzz_test.go — ML1 injection-class fuzzing of outbound
// mail formatting (task ML1, piece 1), notification-email arm.
//
// This is the higher-privilege-reach sibling of
// delivery.FuzzMailSetupLinkInjection: the setup-link mailer's fields are
// admin/inviter-set, but a NOTIFICATION email's Subject is ev.Title and its body
// is ev.Message, and those fold in secret names and project names that ANY
// authenticated user can choose (internal/core notification builders). So the
// attacker who can set a header-injecting secret name reaches go-mail here.
//
// The real caller is EmailSink.send (email.go:117): it calls renderEmail(ev) and
// then builds the *mail.Msg with From/To/Subject/SetBodyString. send() needs a
// live SMTP dial, so this harness reproduces send()'s EXACT message-building
// sequence (the five lines email.go:119-127) and serialises with Msg.WriteTo —
// the bytes DialAndSendWithContext would transmit.
//
// Oracle: identical structural-equality oracle to the delivery target — the
// multiset of header field names and the To-recipient count parsed by an
// INDEPENDENT parser (net/mail) must equal the benign baseline's. A notification
// body is single-part text/plain (no multipart), so partCount is not the lever
// here; CRLF header injection via Title (Subject) or Email (To) is.
//
// What this oracle does NOT verify (report):
//   - Plaintext body content is not structurally constrained (a newline in
//     ev.Message is legitimate body text, not an injection) — the oracle
//     deliberately ignores body bytes and watches only the header block and
//     recipient count.
//   - It does not re-run send()'s retry/deliver logic, only the message build.
//   - Same net/mail-only header-visibility caveat as the delivery target.

import (
	"net/mail"
	"sort"
	"strings"
	"testing"

	gomail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const notifyFrom = "Keyorix <noreply@keyorix.example>"

type hdrShape struct {
	keys    []string
	toCount int
}

func (a hdrShape) equal(b hdrShape) bool {
	if a.toCount != b.toCount || len(a.keys) != len(b.keys) {
		return false
	}
	for i := range a.keys {
		if a.keys[i] != b.keys[i] {
			return false
		}
	}
	return true
}

// buildNotifyBytes reproduces EmailSink.send's message build (email.go:119-127)
// exactly and returns the serialised bytes, or ("", false) if go-mail rejected
// the From/To (a legitimate rejection).
func buildNotifyBytes(t *testing.T, ev core.NotificationEvent) (string, bool) {
	t.Helper()
	subject, body := renderEmail(ev)
	var raw string
	ok := true
	fuzzutil.Guard(t.Fatalf, "notifychan.buildMsg", func() {
		msg := gomail.NewMsg()
		if err := msg.From(notifyFrom); err != nil {
			ok = false
			return
		}
		if err := msg.To(ev.Email); err != nil {
			ok = false
			return
		}
		msg.Subject(subject)
		msg.SetBodyString(gomail.TypeTextPlain, body)
		var sb strings.Builder
		if _, err := msg.WriteTo(&sb); err != nil {
			t.Fatalf("notify msg WriteTo failed for %#v: %v", ev, err)
		}
		raw = sb.String()
	})
	return raw, ok
}

func parseHdrShape(t *testing.T, raw string) hdrShape {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("produced notification mail is unparseable by net/mail: %v\n%s", err, raw)
	}
	var keys []string
	for k := range m.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	toCount := 0
	if addrs, err := m.Header.AddressList("To"); err == nil {
		toCount = len(addrs)
	}
	return hdrShape{keys: keys, toCount: toCount}
}

func benignEvent(ev core.NotificationEvent) core.NotificationEvent {
	set := func(src, b string) string {
		if src == "" {
			return ""
		}
		return b
	}
	return core.NotificationEvent{
		Email:   "recipient@keyorix.example",
		Title:   set(ev.Title, "Access granted"),
		Message: set(ev.Message, "You were granted access"),
		Link:    set(ev.Link, "https://keyorix.example/n/1"),
		Type:    ev.Type,
	}
}

func FuzzNotifyEmailInjection(f *testing.F) {
	add := func(email, title, message, link string) { f.Add(email, title, message, link) }
	add("recipient@keyorix.example", "Access granted", "You were granted access to secret db", "https://x.example/n/1")
	add("victim@x.example\r\nBcc: attacker@evil.example", "T", "m", "")
	add("r@x.example", "Granted access to secret foo\r\nBcc: e@evil.example", "m", "")
	add("r@x.example", "T\nX-Injected: 1", "m", "")
	add("r@x.example", "T\r\nSubject: second subject", "m", "")
	add("r@x.example", "=?utf-8?B?SGk=?=\r\nX-H: v", "m", "")
	add("r@x.example", "secret \"ab\r\n.cd\" shared", "line1\nline2", "https://x.example/n")
	add("r@x.example", "T\x00", "m\x00", "")

	f.Fuzz(func(t *testing.T, email, title, message, link string) {
		ev := core.NotificationEvent{Email: email, Title: title, Message: message, Link: link}
		hostileRaw, ok := buildNotifyBytes(t, ev)
		if !ok {
			return // From/To legitimately rejected
		}
		hostile := parseHdrShape(t, hostileRaw)
		benignRaw, ok := buildNotifyBytes(t, benignEvent(ev))
		if !ok {
			t.Fatalf("benign baseline rejected for shape of %#v", ev)
		}
		benign := parseHdrShape(t, benignRaw)
		if !hostile.equal(benign) {
			t.Fatalf("structural inequality — attacker bytes changed notification-mail headers\nhostile: keys=%v to=%d\nbenign:  keys=%v to=%d\n--- hostile ---\n%s",
				hostile.keys, hostile.toCount, benign.keys, benign.toCount, hostileRaw)
		}
	})
}
