// audit_diff.go — structured before/after diffs for secret mutation audit events.
//
// SECURITY: a diff must never carry a plaintext secret value. For the value
// field we record only {"changed": true}; all other fields are non-sensitive
// metadata (name, type, max_reads, expiration) whose before/after is safe to log.
package core

import (
	"encoding/json"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fieldChange is one field's before→after in an audit diff.
type fieldChange struct {
	Before interface{} `json:"before,omitempty"`
	After  interface{} `json:"after,omitempty"`
	// Changed marks a sensitive field (the secret value) as modified without
	// disclosing either side. Only set for the "value" entry.
	Changed bool `json:"changed,omitempty"`
}

// BuildSecretUpdateDiff returns a JSON diff of a secret update. old is the
// pre-update record; req is the requested change. valueProvided indicates the
// caller supplied a new value (we never compare plaintext, so any provided value
// is recorded as changed). Returns "" when nothing changed (no diff to log).
func BuildSecretUpdateDiff(old *models.SecretNode, req *UpdateSecretRequest, valueProvided bool) string {
	if old == nil || req == nil {
		return ""
	}
	diff := map[string]fieldChange{}

	if valueProvided {
		// Never log the value itself — only that it changed.
		diff["value"] = fieldChange{Changed: true}
	}
	if req.MaxReads != nil && !eqIntPtr(old.MaxReads, req.MaxReads) {
		diff["max_reads"] = fieldChange{Before: intPtrVal(old.MaxReads), After: intPtrVal(req.MaxReads)}
	}
	if req.Expiration != nil && !eqTimePtr(old.Expiration, req.Expiration) {
		diff["expiration"] = fieldChange{Before: timePtrVal(old.Expiration), After: timePtrVal(req.Expiration)}
	}

	if len(diff) == 0 {
		return ""
	}
	b, err := json.Marshal(diff)
	if err != nil {
		return ""
	}
	return string(b)
}

func eqIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func intPtrVal(p *int) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

func eqTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func timePtrVal(p *time.Time) interface{} {
	if p == nil {
		return nil
	}
	return p.UTC().Format(time.RFC3339)
}
