// audit_stream.go — an in-process pub/sub broker that wakes live audit tails the
// instant an audit event is written, so the gRPC StreamAuditLogs RPC can deliver
// events push-driven instead of polling the database on a fixed interval.
//
// The broker carries a coalescing SIGNAL, not the events themselves: on each write it
// pokes every subscriber's 1-buffered channel (non-blocking — it must never slow the
// audit write path), and the subscriber responds by reading the new rows from storage
// using its forward cursor. Keeping the database authoritative means no event is ever
// lost to a full channel or a slow consumer; the signal only collapses the latency
// between "written" and "delivered".
package core

import "sync"

// auditBroker fans a write signal out to live audit-stream subscribers.
type auditBroker struct {
	mu   sync.Mutex
	next int
	subs map[int]chan struct{}
}

func newAuditBroker() *auditBroker {
	return &auditBroker{subs: make(map[int]chan struct{})}
}

// subscribe registers a tail and returns its id plus a channel that receives a
// (coalesced) tick whenever an audit event is written. Unsubscribe with the id.
func (b *auditBroker) subscribe() (int, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan struct{}, 1)
	b.subs[id] = ch
	return id, ch
}

func (b *auditBroker) unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, id)
}

// signal pokes every subscriber. The 1-slot buffer coalesces bursts (a subscriber
// that hasn't drained its previous tick keeps just one pending), and the default
// branch makes every send non-blocking so a slow tail never stalls an audit write.
func (b *auditBroker) signal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// SubscribeAuditStream registers a live audit tail; the returned channel ticks
// whenever an audit event is written. Callers MUST call UnsubscribeAuditStream with
// the returned id when done (e.g. on stream close) to avoid leaking the subscription.
func (c *KeyorixCore) SubscribeAuditStream() (int, <-chan struct{}) {
	return c.auditStream.subscribe()
}

// UnsubscribeAuditStream removes a tail registered with SubscribeAuditStream.
func (c *KeyorixCore) UnsubscribeAuditStream(id int) {
	c.auditStream.unsubscribe(id)
}
