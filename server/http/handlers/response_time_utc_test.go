package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type utcTimesPayload struct {
	Name         string
	LastActivity time.Time
	DeletedAt    *time.Time
	Nested       struct{ At time.Time }
	Items        []utcTimesItem
	Any          map[string]interface{}
	secret       string
}

type utcTimesItem struct{ ExpiresAt time.Time }

// #2951 item 4: one zone in every API payload. A time read back in the server's
// local offset must be emitted as UTC RFC 3339 ("Z"), wherever it sits in the
// response, while strings that merely look like timestamps are left alone.
func TestSendSuccessAndCreated_EmitEveryTimeInUTC(t *testing.T) {
	plus2 := time.FixedZone("", 2*3600)
	local := time.Date(2026, 10, 10, 3, 53, 40, 0, plus2)
	del := local.Add(time.Hour)
	look := "2026-10-10T03:53:40+02:00" // a secret value / description: not a time, must survive

	build := func() utcTimesPayload {
		p := utcTimesPayload{Name: look, LastActivity: local, DeletedAt: &del, secret: "x"}
		p.Nested.At = local
		p.Items = []utcTimesItem{{ExpiresAt: local}}
		p.Any = map[string]interface{}{"t": local, "ptr": &del, "s": look}
		return p
	}

	for name, send := range map[string]func(w *httptest.ResponseRecorder, d interface{}){
		"sendSuccess": func(w *httptest.ResponseRecorder, d interface{}) { sendSuccess(w, d, "") },
		"sendCreated": func(w *httptest.ResponseRecorder, d interface{}) { sendCreated(w, d, "") },
	} {
		p := build()
		w := httptest.NewRecorder()
		send(w, map[string]interface{}{"project": p, "list": []*utcTimesPayload{&p}})
		body := w.Body.String()

		if strings.Contains(body, "+02:00\"") && strings.Count(body, "+02:00") != strings.Count(body, look) {
			t.Errorf("%s: a time was emitted with a +02:00 offset: %s", name, body)
		}
		if !strings.Contains(body, `"LastActivity":"2026-10-10T01:53:40Z"`) {
			t.Errorf("%s: LastActivity not UTC: %s", name, body)
		}
		if !strings.Contains(body, `"DeletedAt":"2026-10-10T02:53:40Z"`) || !strings.Contains(body, `"ExpiresAt":"2026-10-10T01:53:40Z"`) ||
			!strings.Contains(body, `"At":"2026-10-10T01:53:40Z"`) || !strings.Contains(body, `"t":"2026-10-10T01:53:40Z"`) ||
			!strings.Contains(body, `"ptr":"2026-10-10T02:53:40Z"`) {
			t.Errorf("%s: nested/pointer/slice/map times not UTC: %s", name, body)
		}
		if !strings.Contains(body, `"Name":"`+look+`"`) || !strings.Contains(body, `"s":"`+look+`"`) {
			t.Errorf("%s: a string that looks like a timestamp was rewritten: %s", name, body)
		}
		// display only: the caller's own data is not mutated
		if p.LastActivity.Location() != plus2 || del.Location() != plus2 {
			t.Errorf("%s: payload was mutated in place", name)
		}
	}
}
