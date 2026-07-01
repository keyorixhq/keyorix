// spool.go — an opt-in, durable on-disk backlog for audit events that could not be
// delivered to the SIEM (a full queue, or retries exhausted). Without it, a SIEM
// outage longer than the in-memory retry budget silently loses the off-box copy of
// those events. When Config.SpoolDir is set, such events are appended to a JSONL file
// and a background loop replays them until the SIEM accepts them.
//
// The local audit chain remains the durable system of record either way; the spool
// only protects the off-box mirror. It is best-effort: a crash mid-rewrite may at
// worst re-deliver an event (SIEMs dedupe on the event id), never silently drop one.
package siem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	spoolFileName         = "siem-spool.jsonl"
	defaultReplayInterval = 30 * time.Second
	// defaultSpoolMaxBytes caps the on-disk backlog so an indefinite SIEM outage (the
	// spool's whole purpose) can't fill the volume and take the server down — the local
	// audit chain remains the durable system of record regardless. Beyond the cap, new
	// events are dropped (counted) rather than appended.
	defaultSpoolMaxBytes int64 = 100 << 20 // 100 MiB
)

// spool persists undelivered events and replays them on an interval. deliverOnce
// attempts a single delivery and returns nil on success.
type spool struct {
	path        string
	interval    time.Duration
	maxBytes    int64
	deliverOnce func(context.Context, *models.AuditEvent) error

	mu sync.Mutex // serializes file mutation (append + replay rewrite); NOT held across delivery
	// replayMu serializes replay() end-to-end (distinct from mu, which is deliberately
	// released across delivery). Without it, the loop's immediate on-start replay can
	// race a concurrently-triggered one: both read the same undelivered snapshot before
	// either rewrites the file, and both attempt delivery — double-delivering the same
	// backlog to the SIEM. A skipped replay is harmless (the ticker or the next trigger
	// retries the same backlog), so this blocks rather than drops.
	replayMu sync.Mutex
	stop     chan struct{}
	done     chan struct{}
}

// newSpool prepares the spool directory and starts the replay loop.
func newSpool(dir string, interval time.Duration, deliverOnce func(context.Context, *models.AuditEvent) error) (*spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("siem: create spool dir: %w", err)
	}
	// MkdirAll leaves a pre-existing directory's mode untouched, so tighten it: the spool
	// holds audit events (secret names, usernames, IPs, justifications) that must not be
	// group/world-readable.
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs the owner execute bit to be traversable; 0700 is the tightest valid dir mode
		return nil, fmt.Errorf("siem: tighten spool dir perms: %w", err)
	}
	if interval <= 0 {
		interval = defaultReplayInterval
	}
	s := &spool{
		path:        filepath.Join(dir, spoolFileName),
		interval:    interval,
		maxBytes:    defaultSpoolMaxBytes,
		deliverOnce: deliverOnce,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// add appends an event to the spool for later replay, unless the backlog is already at its
// size cap (in which case the event is dropped + counted, bounding disk use).
func (s *spool) add(event *models.AuditEvent) {
	line, err := json.Marshal(event)
	if err != nil {
		log.Printf("siem: spool marshal of audit event %d failed: %v", event.ID, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBytes > 0 {
		if info, serr := os.Stat(s.path); serr == nil && info.Size() >= s.maxBytes {
			log.Printf("siem: spool at cap (%d bytes); dropping audit event %d off-box copy (local audit chain retains it)", s.maxBytes, event.ID)
			siemForwards.WithLabelValues(outcomeDropped).Inc()
			return
		}
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("siem: open spool to persist audit event %d failed: %v", event.ID, err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("siem: write spool for audit event %d failed: %v", event.ID, err)
		return
	}
	siemForwards.WithLabelValues(outcomeSpooled).Inc()
}

func (s *spool) loop() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.replay() // drain any backlog left by a prior run immediately on start
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.replay()
		}
	}
}

// replay re-attempts delivery of every spooled event, then rewrites the file with only
// those that still failed. The lock is NOT held across the (slow, network) deliveries —
// only across the snapshot read and the final reconcile — so a concurrent add() (which is
// on the audited request path) never blocks behind a SIEM round-trip. Crash-safe: every
// undelivered line stays on disk until the atomic rewrite at the end.
func (s *spool) replay() {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	// Snapshot under the lock, recording the byte length we read; any add() during the
	// lock-free delivery below only appends BEYOND this offset (add never rewrites), so the
	// reconcile can cleanly separate "what we attempted" from "what arrived meanwhile".
	s.mu.Lock()
	data, err := os.ReadFile(s.path)
	snapshotLen := int64(len(data))
	s.mu.Unlock()
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("siem: read spool failed: %v", err)
		}
		return
	}

	var remaining [][]byte
	sc := bufio.NewScanner(data2reader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event models.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			// A corrupt line can never be delivered; drop it loudly rather than wedging
			// the whole spool on it forever.
			log.Printf("siem: discarding unparseable spool line: %v", err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		derr := s.deliverOnce(ctx, &event) // network I/O — deliberately NOT under s.mu
		cancel()
		if derr != nil {
			kept := make([]byte, len(line))
			copy(kept, line)
			remaining = append(remaining, kept)
		} else {
			siemForwards.WithLabelValues(outcomeDelivered).Inc()
		}
	}

	// Reconcile under the lock: the file is now [snapshot bytes][lines add()ed meanwhile].
	// Rewrite = still-failed snapshot lines + the concurrently-added tail, so nothing that
	// arrived during delivery is lost and nothing delivered is re-sent.
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, rerr := os.ReadFile(s.path)
	if rerr != nil {
		if !os.IsNotExist(rerr) {
			log.Printf("siem: re-read spool failed: %v", rerr)
		}
		if len(remaining) > 0 {
			s.rewrite(remaining) // file vanished unexpectedly — re-persist the failed lines
		}
		return
	}
	if int64(len(cur)) > snapshotLen {
		ts := bufio.NewScanner(data2reader(cur[snapshotLen:]))
		ts.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for ts.Scan() {
			line := ts.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			kept := make([]byte, len(line))
			copy(kept, line)
			remaining = append(remaining, kept)
		}
	}

	if len(remaining) == 0 {
		_ = os.Remove(s.path)
		return
	}
	s.rewrite(remaining)
}

// rewrite atomically replaces the spool file with the given lines.
func (s *spool) rewrite(lines [][]byte) {
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "siem-spool-*.tmp")
	if err != nil {
		log.Printf("siem: rewrite spool (tempfile) failed: %v", err)
		return
	}
	tmpName := tmp.Name()
	for _, l := range lines {
		if _, err := tmp.Write(append(l, '\n')); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			log.Printf("siem: rewrite spool (write) failed: %v", err)
			return
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		log.Printf("siem: rewrite spool (close) failed: %v", err)
		return
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		log.Printf("siem: rewrite spool (rename) failed: %v", err)
	}
}

// close stops the replay loop and waits for it to exit.
func (s *spool) close() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done
}

// data2reader wraps a byte slice as an io.Reader for the scanner without pulling in
// bytes.NewReader at every call site.
func data2reader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
