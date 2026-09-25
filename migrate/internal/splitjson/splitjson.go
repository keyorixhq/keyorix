// Package splitjson implements the --split-json behavior shared by awssource, azuresource, and
// gcpsource: exploding a JSON-object secret value into one entry per top-level key, instead of
// importing the whole string as a single secret. Factored out once, not copy-pasted three times,
// since all three providers need the exact same decode/order/coerce rules.
package splitjson

import (
	"encoding/json"
	"sort"
)

// Field is one top-level key/value pair of a decoded JSON object.
type Field struct {
	Key   string
	Value string
}

// Object decodes value as a JSON object and returns its top-level fields in a deterministic
// (sorted-key) order, skipping any key whose value is empty. ok is false when value does not
// decode as a JSON object at all (a plain string, a JSON array/scalar, or invalid JSON) — the
// caller should fall back to importing the whole value as one secret in that case.
func Object(value string) (fields []Field, ok bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &obj); err != nil || len(obj) == 0 {
		return nil, false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fields = make([]Field, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			continue
		}
		v := rawToString(obj[k])
		if v == "" {
			continue
		}
		fields = append(fields, Field{Key: k, Value: v})
	}
	return fields, true
}

// rawToString renders one JSON value as a secret string: a JSON string decodes to its own
// content (so {"user":"alice"} imports as the plain value "alice", not the quoted JSON literal
// "\"alice\""); every other JSON type (number, bool, object, array) is kept as its compact JSON
// text; "null" becomes empty (and is therefore skipped by Object above).
func rawToString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	if string(raw) == "null" {
		return ""
	}
	return string(raw)
}
