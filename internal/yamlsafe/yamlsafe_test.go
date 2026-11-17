package yamlsafe

import (
	"fmt"
	"reflect"
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
	errChan := make(chan error, 1)
	go func() {
		errChan <- CheckDuplicateKeysFromBytes([]byte(b.String()))
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("alias bomb walk timed out: possible exponential expansion or infinite hang")
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
// https://github.com/yaml/go-yaml/issues/510: the library's duplicate-key scan is
// quadratic (about 2.3 million allocations for 1000 identical keys, 39 million for
// 4000), while the pre-check rejects the same document in a few allocations per key.
// The count is allocations, not bytes, so it does not depend on GC timing.
func TestUnmarshal_DuplicateKeyCostIsLinear(t *testing.T) {
	const keys = 2000
	dup := []byte(strings.Repeat("k: v\n", keys))
	var err error
	allocs := testing.AllocsPerRun(2, func() {
		var v any
		err = Unmarshal(dup, &v)
	})
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want a duplicate-key error, got %v", err)
	}
	if limit := float64(20 * keys); allocs > limit {
		t.Fatalf("%d duplicate keys took %.0f allocations (limit %.0f); the pre-check must stay linear", keys, allocs, limit)
	}
}

// TestUnmarshal_DuplicateShapesStayLinear covers the key shapes the pre-check
// used to skip (a key that fails to decode, a merge key, a sequence key, a
// mapping key). The library's own pairwise check compares them by kind and raw
// value, so n repeats cost it O(n^2) memory: about 0.5 GB at n=2000.
func TestUnmarshal_DuplicateShapesStayLinear(t *testing.T) {
	const n = 2000
	shapes := map[string]string{
		"int tag, value not an int": "!!int x: v\n",
		"binary tag, bad base64":    "!!binary '%': v\n",
		"merge key":                 "<<: {}\n",
		"sequence key":              "? []\n: x\n",
		"mapping key":               "? {}\n: x\n",
	}
	for name, unit := range shapes {
		t.Run(name, func(t *testing.T) {
			data := []byte(strings.Repeat(unit, n))
			var err error
			allocs := testing.AllocsPerRun(1, func() {
				var v any
				err = Unmarshal(data, &v)
			})
			if err == nil || !strings.Contains(err.Error(), "already defined") {
				t.Fatalf("want a duplicate-key error, got %v", err)
			}
			if limit := float64(50 * n); allocs > limit {
				t.Fatalf("%d repeats took %.0f allocations (limit %.0f); the pre-check must reject them before the library's quadratic check runs", n, allocs, limit)
			}
		})
	}
}

// TestUnmarshal_DistinctKeysLinear: a document without duplicates must not pay
// the library's O(n^2) pairwise key comparison either (100000 keys took ~2 minutes).
func TestUnmarshal_DistinctKeysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped in -short")
	}
	var b strings.Builder
	for i := range 100000 {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	var m map[string]string
	start := time.Now()
	if err := Unmarshal([]byte(b.String()), &m); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("100000 distinct keys took %v; decoding must be linear", d)
	}
	if len(m) != 100000 {
		t.Fatalf("decoded %d keys, want 100000", len(m))
	}
}
