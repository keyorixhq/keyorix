package canary

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Channel names used by Capture's process hooks.
const (
	ChannelLog    = "log"
	ChannelSlog   = "slog"
	ChannelStdout = "stdout"
	ChannelStderr = "stderr"
)

// Output is the data one channel produced.
type Output struct {
	Channel string
	Data    []byte
}

// Capture collects output by channel. Writers and Record are safe to use from
// background goroutines.
type Capture struct {
	mu       sync.Mutex
	channels map[string]*bytes.Buffer
	files    []*capturedFile

	installOnce sync.Once
	restore     func()
}

type capturedFile struct {
	channel string
	f       *os.File
	offset  int64
}

// NewCapture returns an empty Capture.
func NewCapture() *Capture { return &Capture{channels: map[string]*bytes.Buffer{}} }

func (c *Capture) buffer(channel string) *bytes.Buffer {
	b, ok := c.channels[channel]
	if !ok {
		b = &bytes.Buffer{}
		c.channels[channel] = b
	}
	return b
}

// Record appends data to channel.
func (c *Capture) Record(channel string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buffer(channel).Write(data)
}

// Writer returns a writer that appends to channel.
func (c *Capture) Writer(channel string) io.Writer { return channelWriter{c, channel} }

type channelWriter struct {
	c       *Capture
	channel string
}

func (w channelWriter) Write(p []byte) (int, error) {
	w.c.Record(w.channel, p)
	return len(p), nil
}

// Drain returns everything captured since the last Drain, sorted by channel.
// Standard output and error are read from their files, so a write that returned
// before Drain was called is always included; no wait is needed.
func (c *Capture) Drain() []Output {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cf := range c.files {
		data, err := io.ReadAll(io.NewSectionReader(cf.f, cf.offset, 1<<40))
		if err != nil {
			// A channel that cannot be read must not look like a clean one.
			panic("canary: reading captured " + cf.channel + ": " + err.Error())
		}
		cf.offset += int64(len(data))
		c.buffer(cf.channel).Write(data)
	}
	out := make([]Output, 0, len(c.channels))
	for name, b := range c.channels {
		if b.Len() > 0 {
			out = append(out, Output{Channel: name, Data: bytes.Clone(b.Bytes())})
			b.Reset()
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Channel < out[j].Channel })
	return out
}

// RunTimeout is the budget of one RunGuarded call. A canary execution runs a real
// database and several operations, so fuzzutil.Guard's 3 seconds trips on a loaded
// machine; this only needs to catch a hang.
const RunTimeout = 60 * time.Second

// RunGuarded runs fn with a deadline and reports a hang through fatalf. fn must not
// call t.Fatalf, which only works on the test's own goroutine.
func RunGuarded(fatalf func(format string, args ...any), label string, fn func()) {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	select {
	case p := <-done:
		if p != nil {
			panic(p)
		}
	case <-time.After(RunTimeout):
		fatalf("%s exceeded %s", label, RunTimeout)
	}
}

// InstallOnce redirects the logs and standard streams, once per Capture, until
// Uninstall. Fuzz targets call it from the first execution rather than when building
// their fixture: the coordinator process builds the fixture too but never runs an
// input, and redirecting its standard output would swallow the fuzzer's progress
// lines. Safe to call on every execution.
func (c *Capture) InstallOnce(dir string) error {
	var err error
	c.installOnce.Do(func() {
		restoreLogs := c.InstallLogs()
		restoreStdio, stdioErr := c.InstallStdio(dir)
		if stdioErr != nil {
			restoreLogs()
			err = stdioErr
			return
		}
		c.restore = func() {
			restoreStdio()
			restoreLogs()
		}
	})
	return err
}

// Uninstall undoes InstallOnce. It does nothing if InstallOnce never ran.
func (c *Capture) Uninstall() {
	if c.restore != nil {
		c.restore()
		c.restore = nil
	}
}

// InstallLogs redirects the standard logger and the slog default logger into this
// Capture until the returned function is called. They are process-wide, so a fuzz
// target calls this once per process. slog.SetDefault itself repoints the standard
// logger, so it has to come first.
func (c *Capture) InstallLogs() (restore func()) {
	prevLog, prevSlog := log.Writer(), slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(c.Writer(ChannelSlog), nil)))
	log.SetOutput(c.Writer(ChannelLog))
	return func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
	}
}

// InstallStdio points os.Stdout and os.Stderr at files in dir until the returned
// function is called. It replaces the two variables, so it sees everything that
// writes through them; it does not see a direct write to file descriptor 1 or 2,
// or a writer that copied the variable earlier.
func (c *Capture) InstallStdio(dir string) (restore func(), err error) {
	open := func(channel string) (*capturedFile, error) {
		f, err := os.Create(filepath.Join(dir, "captured-"+channel))
		if err != nil {
			return nil, err
		}
		return &capturedFile{channel: channel, f: f}, nil
	}
	out, err := open(ChannelStdout)
	if err != nil {
		return nil, err
	}
	errf, err := open(ChannelStderr)
	if err != nil {
		_ = out.f.Close()
		return nil, err
	}
	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = out.f, errf.f
	c.mu.Lock()
	c.files = append(c.files, out, errf)
	c.mu.Unlock()
	return func() {
		os.Stdout, os.Stderr = prevOut, prevErr
		c.mu.Lock()
		defer c.mu.Unlock()
		c.files = nil
		_ = out.f.Close()
		_ = errf.f.Close()
	}, nil
}
