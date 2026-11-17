package main

// Tests of helpers added with the Reviewer-2 fixes on #4043 (they use API the first version did not have).

import (
	"bufio"
	"strings"
	"testing"
)

// The 1, 16 and 64 MiB strings of U18-U20 are built on first use, not at package init.
func TestHostileBigStringsLazy(t *testing.T) {
	for id, n := range map[string]int{"U18": 1 << 20, "U19": 16 << 20, "U20": 64 << 20} {
		m := mutByID(id)
		if m.WantMain != "" || m.WantMainFn == nil {
			t.Fatalf("%s: expected string held eagerly", id)
		}
		if id == "U18" && len(m.wantMain()) != n {
			t.Errorf("%s: wantMain has %d bytes, want %d", id, len(m.wantMain()), n)
		}
	}
}

func TestReadLineMax(t *testing.T) {
	in := strings.Repeat("a", 5000) + "\n" + `{"ok":true}` + "\n"
	r := bufio.NewReaderSize(strings.NewReader(in), 16)
	l, over, err := readLineMax(r, 1024)
	if err != nil || !over || l != "" {
		t.Fatalf("long line: %q %v %v", trunc(l, 20), over, err)
	}
	l, over, err = readLineMax(r, 1024)
	if err != nil || over || l != `{"ok":true}`+"\n" {
		t.Fatalf("next line: %q %v %v", l, over, err)
	}
}

// An answer longer than hMaxLine is drained, not held, and the next call still reads its own answer.
func TestHDriverOversizeAnswerBounded(t *testing.T) {
	old := hMaxLine
	hMaxLine = 1024
	t.Cleanup(func() { hMaxLine = old })
	d := shDriver(t, `read l; i=0; while [ $i -lt 300 ]; do printf 'aaaaaaaaaaaaaaaaaaaa'; i=$((i+1)); done; echo; read l; echo '{"ok":true}'`)
	if drv, info := d.call("x"); drv != nil || info.Reason != "oversize" {
		t.Fatalf("first: drv=%v reason=%q", drv, info.Reason)
	}
	if drv, info := d.call("y"); drv == nil || drv["ok"] != true {
		t.Fatalf("second: drv=%v info=%+v", drv, info)
	}
}
