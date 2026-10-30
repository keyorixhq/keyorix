package handlers

// capture_log_buf_race_test.go -- CAPTURELOG-RACE-1. The standard logger is process-global,
// so a goroutine an earlier test left behind (the last-used coalescer's finishFlush calls
// log.Printf) can write while the current test reads the capture. Under -race a bare
// bytes.Buffer fails here; captureLogBuf must stay safe against that.

import (
	"log"
	"strings"
	"sync"
	"testing"
)

func TestCaptureLogBuf_ConcurrentLoggerWritesAndReads(t *testing.T) {
	prevOut, prevFlags := log.Writer(), log.Flags()
	t.Run("capture", func(t *testing.T) {
		buf := captureLogBuf(t)

		const writers, lines = 4, 200
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				for range lines {
					log.Printf("late goroutine line")
				}
			})
		}
		// Read while the writers are still logging.
		for range lines {
			_ = buf.String()
			_ = buf.Bytes()
		}
		wg.Wait()

		if got := strings.Count(buf.String(), "late goroutine line"); got != writers*lines {
			t.Fatalf("captured %d lines, want %d", got, writers*lines)
		}
	})
	if log.Writer() != prevOut || log.Flags() != prevFlags {
		t.Fatal("captureLogBuf did not restore the previous log writer and flags on cleanup")
	}
}
