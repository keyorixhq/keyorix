package resguard

import (
	"io"
	"sync/atomic"
)

// LogMeter is the log-volume seam: an io.Writer that counts bytes and discards
// them. Point a logger (log.SetOutput, a slog handler's writer, a zap/zerolog
// sink, the gorm logger) at Writer() so a per-input log explosion — an attacker
// input that makes the code emit megabytes of log for one request — becomes a
// measurable Cost.LogBytes instead of silently filling a disk.
//
// It meters only what is written to Writer(); a logger left pointing at os.Stderr
// is invisible to it. Wrap or tee in the harness if both the real sink and the
// meter are wanted.
type LogMeter struct {
	bytes atomic.Int64
	lines atomic.Int64

	// onWrite, when set (by a Sentinel), is handed every logged byte slice so
	// the secret sentinel can scan log output for a planted secret.
	onWrite func([]byte)
}

// NewLogMeter returns a LogMeter.
func NewLogMeter() *LogMeter { return &LogMeter{} }

// Writer returns an io.Writer that counts and drops. Safe for concurrent use.
func (m *LogMeter) Writer() io.Writer { return (*logWriter)(m) }

func (m *LogMeter) reset() { m.bytes.Store(0); m.lines.Store(0) }

// Bytes is the log volume written since the last reset.
func (m *LogMeter) Bytes() int64 { return m.bytes.Load() }

// Lines is the number of Write calls since the last reset (a coarse line proxy).
func (m *LogMeter) Lines() int64 { return m.lines.Load() }

type logWriter LogMeter

func (w *logWriter) Write(p []byte) (int, error) {
	w.bytes.Add(int64(len(p)))
	w.lines.Add(1)
	if w.onWrite != nil {
		w.onWrite(p)
	}
	return len(p), nil
}

var _ io.Writer = (*logWriter)(nil)
