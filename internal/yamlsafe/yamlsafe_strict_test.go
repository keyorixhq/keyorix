package yamlsafe

import (
	"strings"
	"testing"
)

type strictTarget struct {
	Name string `yaml:"name"`
	Port int    `yaml:"port"`
}

// TestUnmarshalStrict_RejectsUnknownKey: the key and its line are named, the value is not.
func TestUnmarshalStrict_RejectsUnknownKey(t *testing.T) {
	const sentinel = "MARKER-NOT-A-SECRET"
	var v strictTarget
	err := UnmarshalStrict([]byte("name: a\nprot: "+sentinel+"\n"), &v)
	if err == nil {
		t.Fatal("unknown key must be rejected")
	}
	for _, want := range []string{"prot", "line 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("error echoes the value: %q", err)
	}
}

// TestUnmarshalStrict_KnownKeysAndPlainUnmarshalUnchanged: strict mode only adds the
// unknown-key check; Unmarshal itself keeps ignoring unknown keys.
func TestUnmarshalStrict_KnownKeysAndPlainUnmarshalUnchanged(t *testing.T) {
	var v strictTarget
	if err := UnmarshalStrict([]byte("name: a\nport: 80\n"), &v); err != nil || v.Name != "a" || v.Port != 80 {
		t.Fatalf("known keys: v=%+v err=%v", v, err)
	}
	var w strictTarget
	if err := Unmarshal([]byte("name: a\nextra: 1\n"), &w); err != nil || w.Name != "a" {
		t.Fatalf("plain Unmarshal must still ignore unknown keys: v=%+v err=%v", w, err)
	}
}

func TestUnmarshalStrict_StillRejectsDuplicateKeys(t *testing.T) {
	var v strictTarget
	if err := UnmarshalStrict([]byte("name: a\nname: b\n"), &v); err == nil {
		t.Fatal("duplicate key must still be rejected in strict mode")
	}
}
