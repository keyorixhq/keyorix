package libconformance

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	v4yaml "go.yaml.in/yaml/v4"
)

// FuzzYAMLV4RoundTrip: decode -> encode -> decode idempotence for
// go.yaml.in/yaml/v4, the parser every production Keyorix YAML path uses
// (internal/config, internal/k8ssync, the CLI credential store, secret import).
//
// Property: re-decoding v4's OWN Marshal output reproduces the value of the first
// decode. A non-idempotent round-trip is a library footgun that a one-shot decode
// check cannot see (a config written back by Keyorix would not read back as written).
//
// It is v4 against itself, not a differential: the earlier v3-vs-v4 differential
// targets were retired with the v3 dependency, and this is the part of that family
// that never needed v3. It does NOT cover typed (struct) decode, multi-document
// streams or strict KnownFields mode; those lived in the retired differential and
// are not replaced here.
func FuzzYAMLV4RoundTrip(f *testing.F) {
	seeds := []string{
		"x: 1\n", "a:\n  b: 2\n", "- 1\n- 2\n", "n: .nan\n", "i: .inf\n",
		"s: 'hello world'\n", "t: true\n", "f: 3.14\n", "! 00\n", "!\n",
		"anchor: &a 1\nref: *a\n", "key: |\n  multi\n  line\n",
		"m: {a: 1, b: 2}\n", "e: 1_000\n", "neg: -0\n", "ts: 2020-01-02\n",
		"-.000\n", "v: -0.0\n", ">\n>\n!!",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		var v1 any
		if v4yaml.Unmarshal(data, &v1) != nil {
			return // not accepted; nothing to round-trip
		}
		enc, err := v4yaml.Marshal(v1)
		if err != nil {
			t.Fatalf("decoded but Marshal failed\n  input=%q\n  value=%#v\n  err=%v", data, v1, err)
		}
		var v2 any
		if err := v4yaml.Unmarshal(enc, &v2); err != nil {
			// Known defect (class roundtrip:marshal-dup-key): two distinct decoded map
			// keys that serialise to the same text (`{08,8}`: "08" and 8 both Marshal to
			// `8`) make the library's own output non-re-decodable. Tolerated by name so
			// it does not mask other re-decode failures, which still fail.
			if strings.Contains(err.Error(), "already defined") {
				return
			}
			t.Fatalf("re-decode of own Marshal output FAILED\n  input=%q\n  encoded=%q\n  err=%v", data, enc, err)
		}
		// Canonicalise both through Marshal so NaN and map ordering compare stably.
		c1, m1 := v4yaml.Marshal(v1)
		c2, m2 := v4yaml.Marshal(v2)
		if m1 != nil || m2 != nil || bytes.Equal(c1, c2) || reflect.DeepEqual(v1, v2) {
			return
		}
		t.Fatalf("round-trip NOT idempotent\n  input=%q\n  first decode canonical=%q\n  re-decode canonical=%q", data, c1, c2)
	})
}
