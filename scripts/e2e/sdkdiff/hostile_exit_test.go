package main

import (
	"testing"
	"time"
)

// A driver that prints its answer and exits before the harness reads it must still have the answer read (M1 of the
// #4043 review): exec.Cmd.Wait closes a StdoutPipe's read end on exit, so the read used to fail with
// "file already closed" and the call was reported as an O1 driver crash.
func TestHDriverAnswerSurvivesExit(t *testing.T) {
	d := shDriver(t, `read l; echo '{"ok":true}'`)
	if err := d.start(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.in.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-d.waitCh: // the process has exited and Wait has returned
		d.waitCh <- err // kill() drains it again
	case <-time.After(10 * time.Second):
		t.Fatal("driver did not exit")
	}
	line, over, err := readLineMax(d.out, 1024)
	if err != nil || over || line != "{\"ok\":true}\n" {
		t.Fatalf("answer lost after exit: line=%q over=%v err=%v", line, over, err)
	}
	// After the answer, the pipe ends with EOF rather than an error about a closed file.
	if _, _, err := readLineMax(d.out, 1024); err == nil || err.Error() != "EOF" {
		t.Fatalf("want EOF after the answer, got %v", err)
	}
}
