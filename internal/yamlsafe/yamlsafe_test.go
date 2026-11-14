package yamlsafe

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"
)

func TestUnmarshal_MatchesLibraryWithoutDuplicates(t *testing.T) {
	docs := []string{
		"a: 1\nb: [1, 2, 3]\nc:\n  d: x\n  e: true\n",
		"",
		"# only a comment\n",
		"base: &b {x: 1}\nuse:\n  <<: *b\n  y: 2\n",
		"? [1, 2]\n: seq-key\n? [3]\n: other\n",
		"a: 1\n---\na: 2\n",    // second document is ignored, like yaml.Unmarshal
		"1: a\n2: b\n'1': c\n", // int 1 and string "1" are different keys
	}
	for _, d := range docs {
		var want, got any
		wantErr := yaml.Unmarshal([]byte(d), &want)
		gotErr := Unmarshal([]byte(d), &got)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("doc %q: library err=%v, yamlsafe err=%v", d, wantErr, gotErr)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("doc %q: library %#v, yamlsafe %#v", d, want, got)
		}
	}
}

func TestUnmarshal_EmptyDocumentLeavesTargetUntouched(t *testing.T) {
	v := map[string]int{"keep": 1}
	if err := Unmarshal(nil, &v); err != nil {
		t.Fatal(err)
	}
	if v["keep"] != 1 {
		t.Fatalf("target changed: %v", v)
	}
}

func TestUnmarshal_RejectsDuplicates(t *testing.T) {
	cases := map[string]string{
		"identical":       "k: 1\nk: 2\n",
		"nested":          "outer:\n  k: 1\n  k: 2\n",
		"inside sequence": "- a: 1\n  a: 2\n",
		"other spelling":  "1: a\n01: b\n",
		"hex spelling":    "1: a\n0x1: b\n",
		"quoted vs plain": "k: 1\n'k': 2\n",
		"alias key":       "x: &a key\n*a : 1\nkey: 2\n",
	}
	for name, d := range cases {
		var v any
		err := Unmarshal([]byte(d), &v)
		if err == nil || !strings.Contains(err.Error(), "already defined") {
			t.Errorf("%s: want a duplicate-key error, got %v", name, err)
		}
	}
}

func TestUnmarshal_AliasBombStaysCheap(t *testing.T) {
	// A billion-laughs shape: the walk must not expand aliases.
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	start := time.Now()
	if err := CheckDuplicateKeysFromBytes([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("alias bomb walk took %v", d)
	}
}

// CheckDuplicateKeysFromBytes parses data to a node and runs the duplicate check only.
func CheckDuplicateKeysFromBytes(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	return CheckDuplicateKeys(&root)
}

// TestUnmarshal_DuplicateKeyCostIsLinear is the regression proof for
// https://github.com/yaml/go-yaml/issues/510: 20000 identical keys cost the
// library about 1.4 GB and seconds; the pre-check must fail them in a few MB.
func TestUnmarshal_DuplicateKeyCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement; skipped in -short")
	}
	dup := []byte(strings.Repeat("k: v\n", 20000))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var v any
	err := Unmarshal(dup, &v)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want a duplicate-key error, got %v", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Fatalf("20000 duplicate keys allocated %d bytes; the library alone allocates ~1.4 GB, the pre-check must stay linear", alloc)
	}
}
