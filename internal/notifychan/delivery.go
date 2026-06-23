// delivery.go — the async delivery engine shared by every notification sink.
//
// Each sink (webhook, chat, email) is just a bounded queue drained by a worker that
// POSTs/sends one event at a time, so Deliver never blocks the triggering operation.
// The engine adds the durability all sinks need: retry transient failures with
// exponential backoff, count the terminal outcome to Prometheus, and abandon in-flight
// backoff promptly on shutdown so Close stays bounded. A sink supplies only its own
// send func (which reports whether a failure is transient) and a channel label.
package notifychan

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	// A transient failure is retried up to deliveryMaxAttempts with exponential
	// backoff (0.5s + 1s + 2s) so a brief destination blip doesn't lose an alert.
	deliveryMaxAttempts = 4
	deliveryBaseBackoff = 500 * time.Millisecond
)

// sendFunc delivers one event. retryable reports whether a non-nil err is transient
// (worth retrying) rather than permanent.
type sendFunc func(ctx context.Context, ev core.NotificationEvent) (retryable bool, err error)

// deliverer is the shared queue+worker+retry engine. Sinks embed one.
type deliverer struct {
	channel     string
	queue       chan core.NotificationEvent
	send        sendFunc
	baseBackoff time.Duration
	closing     chan struct{} // closed by close() to abort in-flight retry backoff
	closeOnce   sync.Once
	wg          sync.WaitGroup
	mu          sync.Mutex
	dropped     int
}

// newDeliverer starts the worker. channel is the Prometheus label; baseBackoff is
// injectable so tests don't sleep for real seconds.
func newDeliverer(channel string, queueSize int, baseBackoff time.Duration, send sendFunc) *deliverer {
	d := &deliverer{
		channel:     channel,
		queue:       make(chan core.NotificationEvent, queueSize),
		send:        send,
		baseBackoff: baseBackoff,
		closing:     make(chan struct{}),
	}
	d.wg.Add(1)
	go d.worker()
	return d
}

// enqueue offers the event to the queue without blocking; a full queue (a wedged
// destination) drops and counts it rather than stalling the caller.
func (d *deliverer) enqueue(ev core.NotificationEvent) {
	select {
	case d.queue <- ev:
	default:
		d.mu.Lock()
		d.dropped++
		dropped := d.dropped
		d.mu.Unlock()
		notifyDeliveries.WithLabelValues(d.channel, outcomeDropped).Inc()
		log.Printf("notifychan: %s queue full, dropped notification (total dropped: %d)", d.channel, dropped)
	}
}

func (d *deliverer) worker() {
	defer d.wg.Done()
	for ev := range d.queue {
		d.deliver(ev)
	}
}

// deliver sends one event, retrying transient failures with exponential backoff up to
// deliveryMaxAttempts and recording the terminal outcome. Backoff is abandoned promptly
// when closing so shutdown isn't extended by retries.
func (d *deliverer) deliver(ev core.NotificationEvent) {
	backoff := d.baseBackoff
	for attempt := 1; ; attempt++ {
		retryable, err := d.send(context.Background(), ev)
		if err == nil {
			notifyDeliveries.WithLabelValues(d.channel, outcomeDelivered).Inc()
			return
		}
		if !retryable || attempt >= deliveryMaxAttempts {
			notifyDeliveries.WithLabelValues(d.channel, outcomeFailed).Inc()
			log.Printf("notifychan: %s delivery failed after %d attempt(s): %v", d.channel, attempt, err)
			return
		}
		notifyRetries.WithLabelValues(d.channel).Inc()
		select {
		case <-time.After(backoff):
		case <-d.closing:
			notifyDeliveries.WithLabelValues(d.channel, outcomeFailed).Inc()
			log.Printf("notifychan: %s delivery abandoned on shutdown after %d attempt(s): %v", d.channel, attempt, err)
			return
		}
		backoff *= 2
	}
}

// close drains queued events, abandoning in-flight retry backoff so shutdown stays
// bounded. Idempotent.
func (d *deliverer) close() {
	d.closeOnce.Do(func() {
		close(d.closing)
		close(d.queue)
	})
	d.wg.Wait()
}
