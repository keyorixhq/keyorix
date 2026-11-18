package main

// Tests of helpers added with the Reviewer-2 fixes on #4043 (they use API the first version did not have).

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"
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

// The last answer of a driver that exits right after printing it must still be readable once the process has
// been waited for. exec.Cmd.Wait closes a StdoutPipe as soon as the process has exited, so a reader that had not
// yet picked the answer up (a loaded runner) got "file already closed" and the call was recorded as "died" with
// exit status nil (#4390). Here the read is made late on purpose: it starts only after Wait has returned, which
// is the worst case of that race and no longer depends on scheduling.
func TestHDriverAnswerSurvivesTheDriverExiting(t *testing.T) {
	d := shDriver(t, `read l; echo '{"ok":true}'`)
	if err := d.start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(d.in, "x\n"); err != nil {
		t.Fatal(err)
	}
	for stop := time.Now().Add(20 * time.Second); len(d.waitCh) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(stop) {
			t.Fatal("the driver did not exit")
		}
	}
	line, over, err := readLineMax(d.out, 1024)
	if err != nil || over || line != `{"ok":true}`+"\n" {
		t.Fatalf("answer printed before the exit: %q over=%v err=%v", line, over, err)
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
