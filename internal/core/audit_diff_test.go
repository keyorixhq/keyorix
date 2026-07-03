package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestBuildSecretUpdateDiff_ValueChangedOnly(t *testing.T) {
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{}
	diff := BuildSecretUpdateDiff(old, req, true)

	var parsed map[string]map[string]any
	if err := json.Unmarshal([]byte(diff), &parsed); err != nil {
		t.Fatalf("diff is not valid JSON: %v (%q)", err, diff)
	}
	v, ok := parsed["value"]
	if !ok {
		t.Fatalf("expected a value entry, got %q", diff)
	}
	if v["changed"] != true {
		t.Errorf("expected value.changed=true, got %v", v["changed"])
	}
	// Critical: the plaintext value must NEVER appear in a diff.
	if _, leaked := v["before"]; leaked {
		t.Errorf("value diff must not carry a before field: %q", diff)
	}
	if _, leaked := v["after"]; leaked {
		t.Errorf("value diff must not carry an after field: %q", diff)
	}
}

func TestBuildSecretUpdateDiff_MaxReadsChange(t *testing.T) {
	five, ten := 5, 10
	old := &models.SecretNode{MaxReads: &five}
	req := &UpdateSecretRequest{MaxReads: &ten}
	diff := BuildSecretUpdateDiff(old, req, false)

	var parsed map[string]map[string]any
	if err := json.Unmarshal([]byte(diff), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	mr := parsed["max_reads"]
	if mr["before"].(float64) != 5 || mr["after"].(float64) != 10 {
		t.Errorf("expected max_reads 5→10, got %v", mr)
	}
}

func TestBuildSecretUpdateDiff_NoChange(t *testing.T) {
	five := 5
	old := &models.SecretNode{MaxReads: &five}
	// Same max_reads, no value provided → nothing changed → empty diff.
	req := &UpdateSecretRequest{MaxReads: &five}
	if diff := BuildSecretUpdateDiff(old, req, false); diff != "" {
		t.Errorf("expected empty diff, got %q", diff)
	}
}

func TestBuildSecretUpdateDiff_ExpirationChange(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{Expiration: &exp}
	diff := BuildSecretUpdateDiff(old, req, false)
	if diff == "" {
		t.Fatal("expected a diff for an expiration change")
	}
	var parsed map[string]map[string]any
	_ = json.Unmarshal([]byte(diff), &parsed)
	if parsed["expiration"]["after"] != "2027-01-02T03:04:05Z" {
		t.Errorf("expected RFC3339 after, got %v", parsed["expiration"]["after"])
	}
}

// TestBuildSecretUpdateDiff_ClearExpiration locks in #285: UpdateSecret clears
// secret.Expiration when req.ClearExpiration is true even though req.Expiration
// is nil, and the diff must record that transition explicitly rather than
// silently omitting it (the old code only ever checked req.Expiration != nil).
func TestBuildSecretUpdateDiff_ClearExpiration(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	old := &models.SecretNode{Expiration: &exp}
	req := &UpdateSecretRequest{ClearExpiration: true}
	diff := BuildSecretUpdateDiff(old, req, false)
	if diff == "" {
		t.Fatal("expected a diff for a cleared expiration")
	}
	var parsed map[string]map[string]any
	if err := json.Unmarshal([]byte(diff), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	e, ok := parsed["expiration"]
	if !ok {
		t.Fatalf("expected an expiration entry, got %q", diff)
	}
	if e["before"] != "2027-01-02T03:04:05Z" {
		t.Errorf("expected before=2027-01-02T03:04:05Z, got %v", e["before"])
	}
	if _, hasAfter := e["after"]; hasAfter {
		t.Errorf("expected after to be omitted (nil) for a cleared expiration, got %v", e["after"])
	}
}

// TestBuildSecretUpdateDiff_ClearExpiration_NoOpWhenAlreadyUnset confirms that
// clearing an already-nil expiration produces no diff entry (nothing changed).
func TestBuildSecretUpdateDiff_ClearExpiration_NoOpWhenAlreadyUnset(t *testing.T) {
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{ClearExpiration: true}
	if diff := BuildSecretUpdateDiff(old, req, false); diff != "" {
		t.Errorf("expected empty diff, got %q", diff)
	}
}

// TestBuildSecretUpdateDiff_MetadataChange locks in #285: UpdateSecret
// unconditionally applies req.Metadata when non-nil, but the diff builder
// previously never inspected it at all.
func TestBuildSecretUpdateDiff_MetadataChange(t *testing.T) {
	old := &models.SecretNode{Metadata: models.JSON(`{"env":"staging"}`)}
	req := &UpdateSecretRequest{Metadata: map[string]string{"env": "production"}}
	diff := BuildSecretUpdateDiff(old, req, false)
	if diff == "" {
		t.Fatal("expected a diff for a metadata change")
	}
	var parsed map[string]map[string]any
	if err := json.Unmarshal([]byte(diff), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	m, ok := parsed["metadata"]
	if !ok {
		t.Fatalf("expected a metadata entry, got %q", diff)
	}
	before, _ := m["before"].(map[string]any)
	after, _ := m["after"].(map[string]any)
	if before["env"] != "staging" {
		t.Errorf("expected before.env=staging, got %v", m["before"])
	}
	if after["env"] != "production" {
		t.Errorf("expected after.env=production, got %v", m["after"])
	}
}

// TestBuildSecretUpdateDiff_MetadataUnchanged confirms setting metadata to the
// same value produces no diff entry.
func TestBuildSecretUpdateDiff_MetadataUnchanged(t *testing.T) {
	old := &models.SecretNode{Metadata: models.JSON(`{"env":"staging"}`)}
	req := &UpdateSecretRequest{Metadata: map[string]string{"env": "staging"}}
	if diff := BuildSecretUpdateDiff(old, req, false); diff != "" {
		t.Errorf("expected empty diff, got %q", diff)
	}
}

// TestBuildSecretUpdateDiff_MetadataFromEmpty confirms setting metadata on a
// secret that previously had none registers as a change.
func TestBuildSecretUpdateDiff_MetadataFromEmpty(t *testing.T) {
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{Metadata: map[string]string{"env": "production"}}
	diff := BuildSecretUpdateDiff(old, req, false)
	if diff == "" {
		t.Fatal("expected a diff when metadata is set from empty")
	}
}

// TestBuildSecretUpdateDiff_TagsStillNotDiffed documents (and locks in) that Tags
// is intentionally out of scope for #285: UpdateSecret never applies req.Tags to
// the stored secret (dead/no-op on both sides — see secrets.go UpdateSecret), so
// the diff builder correctly never emits a "tags" entry either. If UpdateSecret
// ever starts applying Tags, this test should be revisited alongside wiring a
// real diff for it.
func TestBuildSecretUpdateDiff_TagsStillNotDiffed(t *testing.T) {
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{Tags: []string{"prod", "db"}}
	if diff := BuildSecretUpdateDiff(old, req, false); diff != "" {
		t.Errorf("Tags is out of scope for #285 and must not appear in the diff, got %q", diff)
	}
}

func TestBuildSecretUpdateDiff_NilSafe(t *testing.T) {
	if got := BuildSecretUpdateDiff(nil, nil, true); got != "" {
		t.Errorf("nil inputs must yield empty diff, got %q", got)
	}
}

func TestImpersonationContext_RoundTrip(t *testing.T) {
	ctx := WithImpersonation(context.Background(), 42)
	id, ok := impersonatorFromContext(ctx)
	if !ok || id != 42 {
		t.Errorf("expected impersonator 42, got %d ok=%v", id, ok)
	}
}

func TestImpersonationContext_ZeroIsNoop(t *testing.T) {
	ctx := WithImpersonation(context.Background(), 0)
	if _, ok := impersonatorFromContext(ctx); ok {
		t.Error("admin ID 0 must not establish an impersonation context")
	}
}

func TestDetachedAuditContext_PreservesTag(t *testing.T) {
	parent := WithImpersonation(context.Background(), 7)
	detached := DetachedAuditContext(parent)
	id, ok := impersonatorFromContext(detached)
	if !ok || id != 7 {
		t.Errorf("detached context lost the impersonation tag: %d ok=%v", id, ok)
	}
}

func TestDetachedAuditContext_PlainPassesThrough(t *testing.T) {
	detached := DetachedAuditContext(context.Background())
	if _, ok := impersonatorFromContext(detached); ok {
		t.Error("a non-impersonation parent must not gain a tag")
	}
}
