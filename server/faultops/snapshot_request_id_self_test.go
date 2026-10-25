package faultops

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AuditEvent.RequestID is presence-only (a random per-request id), but only on
// AuditEvent: AccessRequestApproval.RequestID is a deterministic foreign key and a
// changed value must still change the canonical row.
func TestCanonicalRow_AccessRequestApprovalRequestIDStillCompared(t *testing.T) {
	a, err := canonicalRow(&models.AccessRequestApproval{RequestID: 1, ApproverID: 2})
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalRow(&models.AccessRequestApproval{RequestID: 9, ApproverID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("AccessRequestApproval rows differing only in RequestID canonicalize the same: %s", a)
	}

	x, y := "aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb"
	ea, err := canonicalRow(&models.AuditEvent{EventType: "secret.read", RequestID: &x})
	if err != nil {
		t.Fatal(err)
	}
	eb, err := canonicalRow(&models.AuditEvent{EventType: "secret.read", RequestID: &y})
	if err != nil {
		t.Fatal(err)
	}
	if ea != eb {
		t.Fatalf("AuditEvent rows differing only in the random request id must canonicalize the same:\n%s\n%s", ea, eb)
	}
	en, err := canonicalRow(&models.AuditEvent{EventType: "secret.read"})
	if err != nil {
		t.Fatal(err)
	}
	if en == ea {
		t.Fatal("an AuditEvent with no request id must still differ from one with an id (presence is compared)")
	}
}
