package main

import "testing"

type closeRecorder struct{ closed int }

func (c *closeRecorder) Close() error { c.closed++; return nil }

func TestCloseStorageIfCloser(t *testing.T) {
	r := &closeRecorder{}
	closeStorageIfCloser(r)
	if r.closed != 1 {
		t.Fatalf("Close called %d times, want 1", r.closed)
	}
	closeStorageIfCloser(struct{}{}) // no Close method: left alone, no panic
}
