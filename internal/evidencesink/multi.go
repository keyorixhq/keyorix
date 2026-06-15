// multi.go — fan the scheduled evidence pack out to several off-box targets at once
// (e.g. a webhook AND an object-store bucket), so an operator isn't forced to pick a
// single off-box destination.
package evidencesink

import (
	"context"
	"fmt"
	"strings"
)

// Forwarder is an off-box evidence delivery target. It mirrors core.EvidenceForwarder
// structurally so this package needs no dependency on core.
type Forwarder interface {
	ForwardEvidence(ctx context.Context, name string, data []byte, signature string) error
	Target() string
}

// Multi delivers the evidence pack to every configured target. ForwardEvidence
// attempts ALL targets and aggregates failures — the pack reaches as many targets as
// possible, and an error is returned if any target failed (the core then handles it
// like any forwarder failure: non-fatal when a local file was also written).
type Multi struct{ forwarders []Forwarder }

// NewMulti builds a Multi over the given forwarders.
func NewMulti(fwds ...Forwarder) *Multi { return &Multi{forwarders: fwds} }

// ForwardEvidence delivers to every target, collecting any errors.
func (m *Multi) ForwardEvidence(ctx context.Context, name string, data []byte, signature string) error {
	var errs []string
	for _, f := range m.forwarders {
		if err := f.ForwardEvidence(ctx, name, data, signature); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", f.Target(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Target joins the labels of the wrapped targets, e.g. "webhook+objectstore:b/p".
func (m *Multi) Target() string {
	labels := make([]string, 0, len(m.forwarders))
	for _, f := range m.forwarders {
		labels = append(labels, f.Target())
	}
	return strings.Join(labels, "+")
}
