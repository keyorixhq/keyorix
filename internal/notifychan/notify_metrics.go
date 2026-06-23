// notify_metrics.go — Prometheus instrumentation shared by every notification sink
// (webhook, chat, email), labelled by channel.
//
// A dropped or failed operational alert (anomaly, break-glass, rotation reminder) used
// to leave only a log line — there was no series to alert on. These counters land on
// the default registry the server already exposes at /metrics, so a rising drop/failure
// rate on any channel is visible and alertable.
package notifychan

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// notifyDeliveries counts each event by channel and terminal outcome:
	//   - delivered: accepted by the destination.
	//   - failed:    a permanent error (e.g. 4xx) or retries exhausted / abandoned on shutdown.
	//   - dropped:   the bounded queue was full (a wedged destination) so it was never sent.
	notifyDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_notify_deliveries_total",
		Help: "Notification deliveries by channel and terminal outcome (delivered|failed|dropped).",
	}, []string{"channel", "outcome"})

	// notifyRetries counts retry attempts after a transient failure, by channel.
	notifyRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_notify_delivery_retries_total",
		Help: "Notification deliveries retried after a transient failure, by channel.",
	}, []string{"channel"})
)

const (
	outcomeDelivered = "delivered"
	outcomeFailed    = "failed"
	outcomeDropped   = "dropped"
)
