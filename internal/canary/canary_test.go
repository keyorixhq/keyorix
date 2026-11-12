package canary

import (
	"bytes"
	"strings"
	"testing"
)

// TestScanner_DetectsEveryVariantAndFragment is the matching engine's own
// planted-leak self-test: every encoded form of every canary shape, planted
// in noise at several offsets, must be reported; noise alone and a canary of
// a different seed must not be.
func TestScanner_DetectsEveryVariantAndFragment(t *testing.T) {
	noise := bytes.Repeat([]byte("the quick brown fox 0123456789 {\"a\":\"b\"} "), 20)
	for _, hostile := range []bool{false, true} {
		c := New("self", Secret, 7, hostile)
		other := New("self", Secret, 8, hostile)
		sc := NewScanner(c)

		if hits := sc.Scan("clean", noise); len(hits) != 0 {
			t.Fatalf("false positive on noise: %+v", hits)
		}
		if hits := sc.Scan("decoy", append(append([]byte(nil), noise...), []byte(other.Raw)...)); len(hits) != 0 {
			t.Fatalf("false positive on a different canary of the same shape: %+v", hits)
		}
		for _, v := range c.Variants() {
			for _, pos := range []int{0, 17, len(noise)} {
				hay := append(append(append([]byte(nil), noise[:pos]...), v.Bytes...), noise[pos:]...)
				if hits := sc.Scan("plant", hay); len(hits) == 0 {
					t.Errorf("hostile=%v: planted variant %q at %d NOT detected", hostile, v.Name, pos)
				}
			}
		}
		// Truncated fragments of the core.
		for _, frag := range []string{c.Core[:WindowLen], c.Core[coreLen-WindowLen:], c.Core[5 : 5+WindowLen+3]} {
			hay := append(append([]byte("xx"), frag...), noise...)
			hits := sc.Scan("frag", hay)
			if len(hits) == 0 {
				t.Errorf("hostile=%v: truncated fragment %q NOT detected", hostile, frag)
			}
		}
		// One char short of the window must NOT match (bounds the false-positive rate).
		short := c.Core[:WindowLen-1]
		if hits := sc.Scan("short", append([]byte(short), noise...)); len(hits) != 0 {
			t.Errorf("sub-window fragment matched: %+v", hits)
		}
	}
}

func TestNew_DeterministicAndDistinct(t *testing.T) {
	a, b := New("x", Secret, 1, true), New("x", Secret, 1, true)
	if a != b {
		t.Fatal("same (label, class, seed) must give an identical canary")
	}
	if New("x", Secret, 2, true).Core == a.Core || New("y", Secret, 1, true).Core == a.Core {
		t.Fatal("different seed or label must give a different core")
	}
	for _, v := range a.Variants() {
		if v.Name == "json" && strings.Contains(string(v.Bytes), `"`) && !strings.Contains(string(v.Bytes), `\"`) {
			t.Fatalf("json variant is not escaped: %q", v.Bytes)
		}
	}
}

func TestSnippetNeverCarriesFullCanary(t *testing.T) {
	c := New("snip", Secret, 3, false)
	hits := NewScanner(c).Scan("s", []byte("xxxxxxxxxxxxxxxxxxxxxxxx"+c.Raw+"yyyy"))
	if len(hits) == 0 {
		t.Fatal("no hit")
	}
	if strings.Contains(hits[0].Snippet, c.Core) {
		t.Fatalf("snippet leaks the whole core: %s", hits[0].Snippet)
	}
}
