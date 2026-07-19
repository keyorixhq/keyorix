// secret_version_diff.go — metadata diff between two versions of a secret.
//
// Values (encrypted ciphertext) are never compared. Only node-level metadata
// that can change across a secret's lifetime is diffed: classification, expiry,
// and the per-version read count. ACLs are secret-scoped (not version-scoped),
// so their current state is reported as a snapshot alongside the diff.
package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// SecretVersionDiff holds the metadata diff between two versions of a secret.
type SecretVersionDiff struct {
	SecretID    uint                  `json:"secret_id"`
	SecretName  string                `json:"secret_name"`
	FromVersion int                   `json:"from_version"`
	ToVersion   int                   `json:"to_version"`
	Changes     []SecretVersionChange `json:"changes"`
	// ACLUserIDs is the current ACL membership (user IDs with explicit access).
	// ACLs are secret-scoped, not version-scoped, so this is always the current
	// snapshot rather than a per-version diff.
	ACLUserIDs []uint `json:"acl_user_ids"`
}

// SecretVersionChange describes a single metadata field that differs between
// two versions of a secret.
type SecretVersionChange struct {
	Field    string `json:"field"`     // "classification", "expiry", "read_count_delta"
	OldValue string `json:"old_value"` // value at fromVersion (or "(none)")
	NewValue string `json:"new_value"` // value at toVersion   (or "(none)")
}

// DiffSecretVersions compares the metadata of two versions of a secret and
// returns a SecretVersionDiff. It compares: classification, expiry, and
// per-version read count. Values (encrypted ciphertext) are never compared.
// ACLs are secret-scoped (not version-scoped); the current membership is
// included in the result as a snapshot.
func (c *KeyorixCore) DiffSecretVersions(ctx context.Context, secretID uint, fromVersion, toVersion int) (*SecretVersionDiff, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if fromVersion <= 0 || toVersion <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version numbers must be positive")
	}
	if fromVersion == toVersion {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "from and to versions must differ")
	}

	// Load the parent secret node for name + metadata fields (classification,
	// expiry). These are stored on the node, not the version row.
	node, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Load the two version rows — we need at minimum their ReadCount for the
	// per-version counter diff. GetSecretVersion already validates versionNumber > 0.
	from, err := c.GetSecretVersion(ctx, secretID, fromVersion)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}
	to, err := c.GetSecretVersion(ctx, secretID, toVersion)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}

	var changes []SecretVersionChange

	// classification — stored on the node; identical for all versions at any
	// given point in time. We diff the snapshot at creation time by comparing
	// the version's CreatedAt (oldest version reflects the classification in
	// force when it was created).  Since we don't snapshot classification per
	// version, we can only report the current label against what was implied
	// at the FROM version's creation. For now we report the node-level value
	// as OldValue == NewValue to signal "no versioned history" unless the two
	// version rows were created at different times AND the node has a non-empty
	// classification.  The most useful diff is: if the FROM version was created
	// before any classification was set (empty) and the node now has one, show
	// that change.
	//
	// In practice, classification IS a node field; we surface what we know:
	// classification as of node.CreatedAt vs now. To give a meaningful diff we
	// treat the older (lower VersionNumber) version as "old classification" = ""
	// when the node's classification was set after the from-version was created,
	// and "new classification" = current value.  A simplification: since we
	// cannot retrieve the historical classification at version creation time
	// (it is not snapshotted), we report the current node classification for
	// both sides and mark "no change" — callers can interpret the absence of a
	// classification change as "no history available". This is the documented
	// behaviour (see task spec).
	//
	// UPDATE: The task spec asks us to compare the classification field between
	// versions. Since the classification is a node-level field (not versioned),
	// we do the best we can: use the node's current classification for both sides.
	// The read_count fields on the VERSION rows DO differ (that is per-version),
	// and we diff those. Classification and expiry comparisons are also node-level;
	// we include them as "current state" annotations rather than true diffs. For
	// a true diff you would need a classification_history table. We flag if they
	// exist (non-empty/non-nil) for completeness.
	//
	// PRACTICAL APPROACH: compare what can differ between two fetched version
	// rows plus the current node snapshot:
	//   - classification: node-level, compare as node.Classification against
	//     the from-version creation epoch (we use the from's CreatedAt vs the
	//     node's UpdatedAt to guess whether it changed — if UpdatedAt is after
	//     from.CreatedAt, we emit a "may have changed" note with the current value).
	//   - expiry: same reasoning — node-level.
	//   - read_count: per-version, straightforward compare.

	// --- classification ---
	oldClass, newClass := classificationAtVersion(node.Classification, from.CreatedAt, node.UpdatedAt)
	if oldClass != newClass {
		changes = append(changes, SecretVersionChange{
			Field:    "classification",
			OldValue: emptyOr(oldClass),
			NewValue: emptyOr(newClass),
		})
	}

	// --- expiry ---
	oldExpiry, newExpiry := expiryAtVersion(node.Expiration, from.CreatedAt, node.UpdatedAt)
	if oldExpiry != newExpiry {
		changes = append(changes, SecretVersionChange{
			Field:    "expiry",
			OldValue: oldExpiry,
			NewValue: newExpiry,
		})
	}

	// --- read_count (per-version) ---
	if from.ReadCount != to.ReadCount {
		delta := to.ReadCount - from.ReadCount
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		changes = append(changes, SecretVersionChange{
			Field:    "read_count_delta",
			OldValue: strconv.Itoa(from.ReadCount),
			NewValue: strconv.Itoa(to.ReadCount) + " (" + sign + strconv.Itoa(delta) + ")",
		})
	}

	// --- ACLs (current snapshot, not per-version) ---
	acls, _ := c.storage.ListSecretACLs(ctx, secretID) // best-effort; ignore error
	var aclUserIDs []uint
	for _, a := range acls {
		aclUserIDs = append(aclUserIDs, a.UserID)
	}

	return &SecretVersionDiff{
		SecretID:    secretID,
		SecretName:  node.Name,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Changes:     changes,
		ACLUserIDs:  aclUserIDs,
	}, nil
}

// classificationAtVersion returns (oldClassification, newClassification).
// Since classification is node-level we detect whether the node was updated
// after the from-version was created. If so, we cannot know the historical
// value — we report "(unknown)" as the old value and the current value as new.
// When the current classification is empty, there is nothing to report even if
// the node was updated (unclassified→unclassified is not a change).
// If the node has not been updated since from-version creation, both sides
// are the same (no change to report).
func classificationAtVersion(current string, fromCreatedAt, nodeUpdatedAt time.Time) (old, new string) {
	if strings.TrimSpace(current) != "" && nodeUpdatedAt.After(fromCreatedAt) {
		// Node was updated after from-version was created AND there is a current
		// classification — it may have changed.
		return "(unknown)", current
	}
	// Node unchanged since from-version, or no current classification: same on both sides.
	return current, current
}

// expiryAtVersion returns (oldExpiry, newExpiry) as formatted strings.
// Same caveat as classificationAtVersion: expiry is node-level.
// When the current expiry is nil, there is nothing meaningful to report even
// if the node was updated — nil→nil is not a change.
func expiryAtVersion(expiry *time.Time, fromCreatedAt, nodeUpdatedAt time.Time) (old, new string) {
	newStr := formatExpiry(expiry)
	if expiry != nil && nodeUpdatedAt.After(fromCreatedAt) {
		// Node was updated after from-version was created AND there is a current
		// expiry value — the expiry may have been added or changed.
		return "(unknown)", newStr
	}
	return newStr, newStr
}

func formatExpiry(t *time.Time) string {
	if t == nil {
		return "(none)"
	}
	return t.UTC().Format("2006-01-02")
}

func emptyOr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}
