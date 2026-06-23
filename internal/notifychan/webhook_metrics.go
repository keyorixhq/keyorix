// webhook_metrics.go — Prometheus instrumentation for the webhook notification sink.
//
// Before this, a dropped or failed operational alert (anomaly, break-glass, rotation
// reminder) left only a log line — there was no series to alert on. These counters
// land on the default registry the server already exposes at /metrics, so a rising
// drop/failure rate is visible and alertable.
package notifychan

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// webhookDeliveries counts each event by its terminal outcome:
	//   - delivered: the endpoint accepted it (2xx).
	//   - failed:    a permanent error (4xx) or retries exhausted / abandoned on shutdown.
	//   - dropped:   the bounded queue was full (a wedged endpoint) so it was never sent.
	webhookDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_webhook_deliveries_total",
		Help: "Webhook notification deliveries by terminal outcome (delivered|failed|dropped).",
	}, []string{"outcome"})

	// webhookRetries counts retry attempts made after a transient failure (a 5xx/429 or
	// a transport error). Distinct from the failed outcome, which is terminal.
	webhookRetries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_webhook_delivery_retries_total",
		Help: "Webhook deliveries retried after a transient (5xx/429/transport) failure.",
	})
)

const (
	outcomeDelivered = "delivered"
	outcomeFailed    = "failed"
	outcomeDropped   = "dropped"
)
