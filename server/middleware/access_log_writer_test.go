package middleware

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogger_AccessLineKeepsFields pins the shape of one access-log line: std
// logger timestamp, method, URI, protocol, remote address, status, byte count and
// elapsed time, exactly as chi's DefaultLogFormatter emits them.
func TestLogger_AccessLineKeepsFields(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/things?x=1", nil)
	req.RemoteAddr = "192.0.2.7:4242"
	Logger()(h).ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	re := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} "POST http://example\.com/api/v1/things\?x=1 HTTP/1\.1" from 192\.0\.2\.7:4242 - 201 5B in \S+\n$`)
	assert.Regexp(t, re, line)
}

// TestAccessLogWriter_FormatMatchesStdLogger compares our line formatting with
// log.Logger for the flag combinations a process can set.
func TestAccessLogWriter_FormatMatchesStdLogger(t *testing.T) {
	ts := time.Date(2026, 10, 14, 9, 5, 3, 123456000, time.UTC)
	for _, flags := range []int{
		log.LstdFlags, log.LstdFlags | log.LUTC, log.Ldate, log.Ltime | log.Lmicroseconds,
		log.LstdFlags | log.Lmsgprefix, 0,
	} {
		var want bytes.Buffer
		l := log.New(&want, "pfx: ", flags)
		w := &accessLogWriter{prefix: "pfx: ", flags: flags}
		got := w.format(ts, "msg")
		// log.Logger stamps time.Now(), so compare with the timestamp
		// stripped; the layout around it must be identical.
		l.Print("msg")
		stamp := regexp.MustCompile(`\d{4}/\d{2}/\d{2} |\d{2}:\d{2}:\d{2}(\.\d{6})? `)
		assert.Equal(t, stamp.ReplaceAllString(want.String(), ""), stamp.ReplaceAllString(string(got), ""), "flags=%d", flags)
		assert.Equal(t, len(want.String()), len(got), "flags=%d", flags)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// TestAccessLogWriter_ConcurrentLinesWholeAndOrdered runs under -race: every line
// arrives whole, none is lost, and each goroutine's lines keep their order.
func TestAccessLogWriter_ConcurrentLinesWholeAndOrdered(t *testing.T) {
	sink := &lockedBuf{}
	w := &accessLogWriter{out: sink}
	const goroutines, perG = 32, 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				w.Print(fmt.Sprintf("g%d seq%d", g, i))
			}
		}(g)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(sink.b.String(), "\n"), "\n")
	require.Len(t, lines, goroutines*perG)
	next := make(map[int]int)
	for _, ln := range lines {
		var g, seq int
		_, err := fmt.Sscanf(ln, "g%d seq%d", &g, &seq)
		require.NoError(t, err, "torn line %q", ln)
		require.Equal(t, next[g], seq, "goroutine %d out of order", g)
		next[g]++
	}
	assert.Zero(t, w.Dropped())
}

type blockingSink struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingSink) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return len(p), nil
}

// TestAccessLogWriter_DropsAreCountedNotBlocking: with a stalled sink, callers
// still return, and the overflow is counted rather than silent.
func TestAccessLogWriter_DropsAreCountedNotBlocking(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{}), started: make(chan struct{})}
	w := &accessLogWriter{out: sink}
	big := strings.Repeat("x", 64<<10)

	done := make(chan struct{})
	go func() { w.Print("first"); close(done) }() // becomes the flusher, stalls in Write
	<-sink.started

	for i := 0; i < 40; i++ { // 40 x 64 KiB > the 1 MiB cap
		w.Print(big)
	}
	assert.NotZero(t, w.Dropped())
	close(sink.release)
	<-done
}
