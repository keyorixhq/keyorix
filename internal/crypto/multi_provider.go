package crypto

import (
	"fmt"
	"log"
	"strings"
)

// MultiKeyProvider tries its providers in order, returning the KEK from the
// first that succeeds. If all fail it returns a wrapped error. An empty list
// is a configuration error.
type MultiKeyProvider struct {
	providers []KeyProvider
}

// NewMultiKeyProvider creates a MultiKeyProvider. Returns error if list is empty.
func NewMultiKeyProvider(providers []KeyProvider) (*MultiKeyProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("multi key provider: at least one provider is required")
	}
	return &MultiKeyProvider{providers: providers}, nil
}

// Name returns "multi(p1,p2,...)" for logging/status output.
func (m *MultiKeyProvider) Name() string {
	names := make([]string, len(m.providers))
	for i, p := range m.providers {
		names[i] = p.Name()
	}
	return "multi(" + strings.Join(names, ",") + ")"
}

// KEK tries each provider in order. The first successful result is returned.
func (m *MultiKeyProvider) KEK() ([]byte, error) {
	var errs []string
	for _, p := range m.providers {
		key, err := p.KEK()
		if err == nil {
			if len(m.providers) > 1 {
				log.Printf("key provider: %s succeeded", p.Name())
			}
			return key, nil
		}
		log.Printf("key provider: %s failed (%v), trying next", p.Name(), err)
		errs = append(errs, fmt.Sprintf("%s: %v", p.Name(), err))
	}
	return nil, fmt.Errorf("all key providers failed: %s", strings.Join(errs, "; "))
}
