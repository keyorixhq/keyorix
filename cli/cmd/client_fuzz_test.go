package cmd

import (
	"encoding/json"
	"testing"
	"unicode"
)

// FuzzApiError is CLI-FUZZ target 2 (ADR-108): apiError turns an arbitrary server
// response (status code + body) into the error text main.go prints straight to the
// user's terminal via fmt.Fprintln(os.Stderr, "Error:", err) -- there is no
// cliout.SanitizeForTerminal call anywhere between apiError and that print. The server
// is not a trusted input source here (a compromised, misconfigured, or malicious/MITM
// server can return any bytes in the JSON "message" field), so this is the same
// terminal-injection surface cliout.SanitizeForTerminal exists to close for other free
// text -- apiError just never routes through it.
//
// Invariants: apiError must never panic on any (statusCode, body) pair, and the
// resulting error's message must never carry a raw control rune (ESC, any C0/C1 byte)
// through to the terminal.
func FuzzApiError(f *testing.F) {
	f.Add(404, []byte(`{"error":"not_found","message":"secret not found"}`))
	f.Add(500, []byte(`{"error":"internal","message":"boom"}`))
	f.Add(400, []byte(`not json at all`))
	f.Add(403, []byte(``))
	f.Add(200, []byte(`{"message":""}`))

	// The actual terminal-injection payload: an escape sequence in the server's
	// message field, built via json.Marshal so the seed body is properly
	// JSON-escaped (json.Marshal escapes control runes as \u00XX). A raw,
	// unescaped control byte embedded directly in a quoted JSON string is invalid
	// JSON and json.Unmarshal rejects it before eb.Message is ever populated --
	// the escaped form is what a real server's JSON encoder would actually emit.
	mustJSON := func(v map[string]string) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			f.Fatalf("seed setup: %v", err)
		}
		return b
	}
	esc := string(rune(0x1b))
	f.Add(400, mustJSON(map[string]string{"message": esc + "[31minjected" + esc + "[0m"}))
	f.Add(400, mustJSON(map[string]string{"message": esc + "]0;evil-title\a"}))

	f.Fuzz(func(t *testing.T, statusCode int, body []byte) {
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("apiError panicked on statusCode=%d body=%q: %v", statusCode, body, r)
				}
			}()
			err = apiError("do thing", statusCode, body)
		}()

		if err == nil {
			t.Fatalf("apiError(%d, %q) returned nil", statusCode, body)
		}

		msg := err.Error()
		for _, r := range msg {
			if unicode.IsControl(r) {
				t.Fatalf("apiError(%d, %q).Error() = %q contains raw control rune %U -- unsanitized server text reaches the terminal", statusCode, body, msg, r)
			}
		}
	})
}
