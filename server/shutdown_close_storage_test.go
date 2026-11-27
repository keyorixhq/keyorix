package main

import (
	"testing"
	"time"
)

type closeRecorder struct{ closed int }

func (c *closeRecorder) Close() error { c.closed++; return nil }

func TestCloseStorageWithin_ClosesACloser(t *testing.T) {
	r := &closeRecorder{}
	closeStorageWithin(r, nil, time.Second)
	if r.closed != 1 {
		t.Fatalf("Close called %d times, want 1", r.closed)
	}
	closeStorageWithin(struct{}{}, nil, time.Second) // no Close method: left alone, no panic
}

// blockingCloser stands in for a Postgres storage whose pgxpool.Pool.Close
// waits for a connection a stuck request never returns.
type blockingCloser struct{ release chan struct{} }

func (b blockingCloser) Close() error { <-b.release; return nil }

// returnsWithin fails the test unless f returns within limit.
func returnsWithin(t *testing.T, limit time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("still blocked after %s: shutdown would hang on the storage close", limit)
	}
}

// A Close that never returns must not hold shutdown: the defers after it (KEK
// wipe, lock release, the lock-loss os.Exit(1)) have to run.
func TestCloseStorageWithin_BoundsABlockedClose(t *testing.T) {
	b := blockingCloser{release: make(chan struct{})}
	defer close(b.release)
	returnsWithin(t, 2*time.Second, func() { closeStorageWithin(b, nil, 50*time.Millisecond) })
}

// The schedulers are awaited before Close, within the same bound.
func TestCloseStorageWithin_WaitsForSchedulersFirst(t *testing.T) {
	r := &closeRecorder{}
	var waited bool
	closeStorageWithin(r, func() { waited = true }, time.Second)
	if !waited || r.closed != 1 {
		t.Fatalf("waited=%v closed=%d, want the scheduler wait and then one Close", waited, r.closed)
	}

	stuck := make(chan struct{})
	defer close(stuck)
	r2 := &closeRecorder{}
	returnsWithin(t, 2*time.Second, func() {
		closeStorageWithin(r2, func() { <-stuck }, 50*time.Millisecond)
	})
	if r2.closed != 0 {
		t.Fatalf("Close called %d times while a scheduler was still running, want 0", r2.closed)
	}
}
