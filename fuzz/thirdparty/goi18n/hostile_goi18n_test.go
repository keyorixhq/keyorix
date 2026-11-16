// Hostile message-file fuzz harness for nicksnyder/go-i18n/v2.
//
// Keyorix call path (internal/i18n/i18n.go): bundle.ParseMessageFileBytes(data,
// filePath) is called on each locale file; Keyorix's own locale files are
// embedded (so low direct untrusted exposure), but ParseMessageFileBytes is the
// exact PUBLIC entry point and go-i18n documents it for caller-supplied files.
// The structural interpretation that turns a decoded map into []*Message
// (plural-form keys, nested sections, id/description/other fields) is
// go-i18n's own code, exercised identically regardless of the wire format.
//
// This target attacks that structural layer through three real decoders
// (JSON via encoding/json, TOML via BurntSushi/toml, YAML via yaml.v3) wired
// exactly as a go-i18n caller would wire them.
//
// Oracle (crash-only parser — go-i18n has no serialiser to round-trip against):
//   - no panic inside ParseMessageFileBytes.
//   - bounded work: parse of a <=64KiB input returns within a generous wall
//     budget; a timeout is a hang/CPU-DoS finding since the input is tiny.
//
// What this oracle does NOT verify: that the parsed messages are semantically
// correct, plural-rule correctness, allocation ceilings (relies on the go
// fuzzer's own OOM detection), or anything about the underlying JSON/TOML/YAML
// decoders themselves (those are separate leaf targets) beyond "go-i18n must
// not panic on whatever they return".
package goi18nhostile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"gopkg.in/yaml.v3"
)

func unmarshalFuncs() map[string]i18n.UnmarshalFunc {
	return map[string]i18n.UnmarshalFunc{
		"json": json.Unmarshal,
		"toml": toml.Unmarshal,
		"yaml": yaml.Unmarshal,
	}
}

func FuzzGoI18nParseMessageFile(f *testing.F) {
	f.Add(uint8(0), []byte(`{"hello":"world"}`))
	f.Add(uint8(0), []byte(`{"msg":{"one":"a","other":"b"}}`))
	f.Add(uint8(0), []byte(`{"m":{"description":"d","other":"{{.Count}}"}}`))
	f.Add(uint8(1), []byte("hello = \"world\"\n[msg]\none = \"a\"\nother = \"b\"\n"))
	f.Add(uint8(2), []byte("hello: world\nmsg:\n  one: a\n  other: b\n"))
	f.Add(uint8(0), []byte(`{"":{"":""}}`))

	exts := []string{"json", "toml", "yaml"}
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		ext := exts[int(sel)%len(exts)]
		path := "active." + ext
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Return value intentionally ignored: an error on hostile input is
			// expected and fine; only a panic or hang is a finding.
			_, _ = i18n.ParseMessageFileBytes(data, path, unmarshalFuncs())
		}()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("bounded-work: ParseMessageFileBytes(%s) did not return in 15s for %d-byte input", ext, len(data))
		}
	})
}
