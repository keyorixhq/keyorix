// metrics.go — Prometheus instrumentation for SIEM audit forwarding.
//
// A dropped or failed audit forward used to leave only a log line. Because audit
// events are security/compliance evidence (SOC 2 / ISO 27001), a SIEM that is silently
// losing them is a finding — so the forwarder's delivery health is exported on the
// default registry the server serves at /metrics.
package siem

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// siemForwards counts each audit event by terminal outcome:
	//   - delivered: the SIEM accepted it (2xx).
	//   - failed:    a permanent error (4xx) or retries exhausted / abandoned on shutdown.
	//   - dropped:   the bounded queue was full (a wedged SIEM) so it was never sent.
	siemForwards = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_siem_forwards_total",
		Help: "SIEM audit-event forwards by terminal outcome (delivered|failed|dropped).",
	}, []string{"outcome"})

	// siemRetries counts forwards retried after a transient (5xx/429/transport) failure.
	siemRetries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_siem_forward_retries_total",
		Help: "SIEM audit-event forwards retried after a transient failure.",
	})
)

const (
	outcomeDelivered = "delivered"
	outcomeFailed    = "failed"
	outcomeDropped   = "dropped"
)
