// Package plan builds and executes the source-to-Keyorix mapping plan
// (docs/design-keyorix-migrate.md's "Source-to-Keyorix mapping" and "Idempotency" sections).
// It is source-agnostic — Entry is a generic (name, value, metadata) triple any source
// (Vault today, AWS/Azure/GCP later) can produce — and target-agnostic, depending only on
// internal/target.API so it can be unit-tested without a live Keyorix server.
package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/keyorixhq/keyorix/migrate/internal/target"
)

// sourceIDKey is the metadata key keyorix-migrate stores its own idempotency marker under.
// Prefixed distinctly from source-provided metadata (see Entry.Metadata / vaultsource's
// "vault." prefix) so the two namespaces never collide.
const sourceIDKey = "migrate.source-id"

// sourceKindKey records which source produced an entry (e.g. "vault"), for operator-readable
// reporting — not used by the idempotency check itself (SourceID alone is the key).
const sourceKindKey = "migrate.source"

// sourceVersionKey / sourceCreatedAtKey record which version of the source item was imported
// and when it was created there (Andrei's 2026-09-25 decision, docs/design-keyorix-migrate.md's
// "All-versions import (deferred)": only the latest version is ever imported, but every
// imported secret records which version that was). Empty for a source with no version concept
// (KV v1) — Apply omits the key entirely rather than writing an empty string.
const sourceVersionKey = "migrate.source-version"
const sourceCreatedAtKey = "migrate.source-created-at"

// Entry is one item a source produced, ready to be planned against Keyorix. Path is a
// human-readable source locator (e.g. a Vault path) used only for reporting — never for
// identity (SourceID is the stable identity, see Outcome).
type Entry struct {
	SourceKind string // "vault", "aws", "azure", "gcp"
	Path       string // human-readable locator, no secret material
	Name       string // target Keyorix secret name (already sanitized by the source)
	Value      string
	Metadata   map[string]string // source-native metadata (e.g. Vault custom_metadata), unprefixed
	// SourceID uniquely and stably identifies this entry within its source (e.g.
	// vaultsource.Entry.SourceID) — the idempotency key. Two runs against the same source
	// item must always produce the same SourceID.
	SourceID string
	// SourceVersion / SourceCreatedAt are the source's own version identifier and creation
	// timestamp for this item (e.g. vaultsource.Entry.Version/CreatedAt), when the source has a
	// version concept. Empty when it doesn't (e.g. Vault KV v1).
	SourceVersion   string
	SourceCreatedAt string
}

// Outcome classifies what BuildPlan decided for one Entry.
type Outcome string

const (
	Create   Outcome = "create"
	Update   Outcome = "update"
	Skip     Outcome = "skip"
	Conflict Outcome = "conflict"
	Error    Outcome = "error"
)

// Item is one planned action: an Entry plus the decision BuildPlan made about it.
type Item struct {
	Entry      Entry
	Outcome    Outcome
	ExistingID int    // 0 unless a same-name secret already exists.
	Reason     string // human-readable, for Skip/Conflict/Error — never includes a value.
}

// BuildPlan classifies every entry against the target by name, then (for a name match) by
// stored source-id — see docs/design-keyorix-migrate.md's "Idempotency" section for the full
// three-outcome rationale. It never writes anything; Apply does that.
func BuildPlan(ctx context.Context, api target.API, entries []Entry) ([]Item, error) {
	items := make([]Item, 0, len(entries))
	for _, e := range entries {
		item, err := planOne(ctx, api, e)
		if err != nil {
			// A lookup failure (network, auth, server error) is reported per-item as an
			// Error outcome rather than aborting the whole plan — one bad item must not
			// hide the plan for every other item (docs/design-keyorix-migrate.md's
			// per-item result report).
			items = append(items, Item{Entry: e, Outcome: Error, Reason: err.Error()})
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func planOne(ctx context.Context, api target.API, e Entry) (Item, error) {
	id, found, err := api.LookupByName(ctx, e.Name)
	if err != nil {
		return Item{}, fmt.Errorf("look up %q: %w", e.Name, err)
	}
	if !found {
		return Item{Entry: e, Outcome: Create}, nil
	}

	meta, err := api.Metadata(ctx, id)
	if err != nil {
		return Item{}, fmt.Errorf("read metadata for existing secret %q (id %d): %w", e.Name, id, err)
	}
	if meta[sourceIDKey] != e.SourceID {
		return Item{
			Entry:      e,
			Outcome:    Conflict,
			ExistingID: id,
			Reason:     fmt.Sprintf("a secret named %q already exists (id %d) that this tool did not create for this source item — rename one side, or re-run with --force to overwrite", e.Name, id),
		}, nil
	}

	existingValue, err := api.Value(ctx, id)
	if err != nil {
		return Item{}, fmt.Errorf("read value for existing secret %q (id %d): %w", e.Name, id, err)
	}
	if existingValue == e.Value {
		return Item{Entry: e, Outcome: Skip, ExistingID: id, Reason: "already up to date"}, nil
	}
	return Item{Entry: e, Outcome: Update, ExistingID: id, Reason: "source value changed since last import"}, nil
}

// Result is the outcome of actually executing one planned Item.
type Result struct {
	Item  Item
	Ran   bool // false when Apply left the item untouched (Skip, or a Conflict without --force).
	Error string
}

// Apply executes a plan built by BuildPlan. force turns a Conflict into an overwrite
// (docs/design-keyorix-migrate.md's "Idempotency" section) instead of leaving it untouched;
// every other outcome behaves the same regardless of force.
func Apply(ctx context.Context, api target.API, items []Item, force bool) []Result {
	results := make([]Result, 0, len(items))
	for _, item := range items {
		results = append(results, applyOne(ctx, api, item, force))
	}
	return results
}

func applyOne(ctx context.Context, api target.API, item Item, force bool) Result {
	switch item.Outcome {
	case Skip, Error:
		return Result{Item: item, Ran: false}
	case Conflict:
		if !force {
			return Result{Item: item, Ran: false}
		}
		if err := api.UpdateValue(ctx, item.ExistingID, item.Entry.Value); err != nil {
			return Result{Item: item, Ran: true, Error: err.Error()}
		}
		return Result{Item: item, Ran: true}
	case Update:
		if err := api.UpdateValue(ctx, item.ExistingID, item.Entry.Value); err != nil {
			return Result{Item: item, Ran: true, Error: err.Error()}
		}
		return Result{Item: item, Ran: true}
	case Create:
		metadata := map[string]string{
			sourceKindKey: item.Entry.SourceKind,
			sourceIDKey:   item.Entry.SourceID,
		}
		if item.Entry.SourceVersion != "" {
			metadata[sourceVersionKey] = item.Entry.SourceVersion
		}
		if item.Entry.SourceCreatedAt != "" {
			metadata[sourceCreatedAtKey] = item.Entry.SourceCreatedAt
		}
		for k, v := range item.Entry.Metadata {
			metadata[item.Entry.SourceKind+"."+k] = v
		}
		if _, err := api.Create(ctx, item.Entry.Name, item.Entry.Value, metadata); err != nil {
			return Result{Item: item, Ran: true, Error: err.Error()}
		}
		return Result{Item: item, Ran: true}
	default:
		return Result{Item: item, Ran: false, Error: fmt.Sprintf("unknown outcome %q", item.Outcome)}
	}
}

// SourceID hashes the given components into a stable identifier — a small helper sources can
// use directly rather than each hand-rolling their own hashing convention. vaultsource.Entry
// builds its own SourceID string first (addr|mount|kvN|path|field, all non-sensitive
// identifiers) and passes it through here so the stored metadata value is a fixed-length hash,
// not a value that could reveal the source's internal path layout to anyone who can list
// secret metadata.
func SourceID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
