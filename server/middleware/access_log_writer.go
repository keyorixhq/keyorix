package middleware

import (
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// maxPendingAccessLogBytes bounds the memory held by lines waiting for the
// current flusher. Past it a line is dropped and counted, never blocked on: the
// access log is not the audit trail.
const maxPendingAccessLogBytes = 1 << 20

// accessLogWriter is the access log's replacement for the global *log.Logger.
//
// log.Logger holds its mutex across the write syscall, so at high concurrency
// every request queued behind one another's write. Here the lock covers only an
// in-memory append. Whichever caller finds no flush in progress becomes the
// flusher and writes everything pending (its own line included) outside the
// lock; callers arriving meanwhile append and return without waiting.
//
// Properties kept from the std logger: lines are written whole, in the order
// they were appended, in the same "prefix + timestamp + message" format, and an
// uncontended Print has written its line to the sink before it returns.
type accessLogWriter struct {
	out    io.Writer
	prefix string
	flags  int

	mu       sync.Mutex
	pending  []byte
	spare    []byte
	flushing bool

	dropped atomic.Uint64
}

// newAccessLogWriter snapshots the std logger's destination, prefix and flags,
// so output goes where log.Default() would have sent it.
func newAccessLogWriter() *accessLogWriter {
	return &accessLogWriter{out: log.Writer(), prefix: log.Prefix(), flags: log.Flags()}
}

// Dropped reports how many lines were discarded because the sink fell behind.
func (w *accessLogWriter) Dropped() uint64 { return w.dropped.Load() }

// Print implements chi's middleware.LoggerInterface.
func (w *accessLogWriter) Print(v ...interface{}) {
	line := w.format(time.Now(), fmt.Sprint(v...))

	w.mu.Lock()
	if len(w.pending) >= maxPendingAccessLogBytes {
		w.mu.Unlock()
		w.dropped.Add(1)
		return
	}
	w.pending = append(w.pending, line...)
	if w.flushing {
		w.mu.Unlock()
		return
	}
	w.flushing = true
	for len(w.pending) > 0 {
		batch := w.pending
		w.pending = w.spare[:0]
		w.mu.Unlock()
		_, _ = w.out.Write(batch) // a failing sink loses lines, as with log.Logger
		w.mu.Lock()
		w.spare = batch[:0]
	}
	w.flushing = false
	w.mu.Unlock()
}

// format renders one line the way log.Logger does for the flags in use.
func (w *accessLogWriter) format(t time.Time, msg string) []byte {
	b := make([]byte, 0, len(w.prefix)+len(msg)+32)
	if w.flags&log.Lmsgprefix == 0 {
		b = append(b, w.prefix...)
	}
	if w.flags&(log.Ldate|log.Ltime|log.Lmicroseconds) != 0 {
		if w.flags&log.LUTC != 0 {
			t = t.UTC()
		}
		if w.flags&log.Ldate != 0 {
			y, m, d := t.Date()
			b = appendPadded(b, y, 4)
			b = append(b, '/')
			b = appendPadded(b, int(m), 2)
			b = append(b, '/')
			b = appendPadded(b, d, 2)
			b = append(b, ' ')
		}
		if w.flags&(log.Ltime|log.Lmicroseconds) != 0 {
			h, mi, s := t.Clock()
			b = appendPadded(b, h, 2)
			b = append(b, ':')
			b = appendPadded(b, mi, 2)
			b = append(b, ':')
			b = appendPadded(b, s, 2)
			if w.flags&log.Lmicroseconds != 0 {
				b = append(b, '.')
				b = appendPadded(b, t.Nanosecond()/1e3, 6)
			}
			b = append(b, ' ')
		}
	}
	if w.flags&log.Lmsgprefix != 0 {
		b = append(b, w.prefix...)
	}
	b = append(b, msg...)
	if len(msg) == 0 || msg[len(msg)-1] != '\n' {
		b = append(b, '\n')
	}
	return b
}

func appendPadded(b []byte, n, width int) []byte {
	s := strconv.Itoa(n)
	for i := len(s); i < width; i++ {
		b = append(b, '0')
	}
	return append(b, s...)
}
