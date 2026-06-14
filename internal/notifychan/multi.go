// multi.go — fan-out across multiple notification channels. When more than one
// channel is enabled, each notification is delivered to all of them; a slow or
// failing channel cannot affect the others (each Deliver is itself non-blocking).
package notifychan

import "github.com/keyorixhq/keyorix/internal/core"

// MultiSink delivers each event to every wrapped sink.
type MultiSink struct {
	sinks []core.NotificationSink
}

// NewMulti combines sinks into a single NotificationSink, dropping nils. It returns
// nil when no real sink is given (so callers leave notifications in-app only), the
// lone sink when exactly one is given, and a MultiSink otherwise.
func NewMulti(sinks ...core.NotificationSink) core.NotificationSink {
	live := make([]core.NotificationSink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			live = append(live, s)
		}
	}
	switch len(live) {
	case 0:
		return nil
	case 1:
		return live[0]
	default:
		return &MultiSink{sinks: live}
	}
}

// Deliver fans the event out to every wrapped sink.
func (m *MultiSink) Deliver(ev core.NotificationEvent) {
	for _, s := range m.sinks {
		s.Deliver(ev)
	}
}
