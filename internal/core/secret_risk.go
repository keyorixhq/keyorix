package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Risk bands returned by ComputeSecretRiskScore.
const (
	RiskBandLow    = "low"
	RiskBandMedium = "medium"
	RiskBandHigh   = "high"
)

// SecretRiskFactor is one weighted contributor to a secret's risk score. Score
// is 0-100 (higher = riskier); the composite is the weight-weighted sum.
type SecretRiskFactor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

// SecretRiskScore is a per-secret risk assessment combining expiry, rotation
// age, usage (read activity), and exposure (how many principals can read it).
//
// #407: the exposure factor depends on ListSharesBySecret/ListGroupMembers, and a
// failure there is an UNDER-count (never an over-count) — a secret that's
// actually widely shared could get incorrectly deprioritized for rotation if its
// exposure silently read as low. Degraded + DegradedReasons make an incomplete
// exposure count detectable, mirroring CompliancePosture.Degraded
// (compliance_posture.go). ComputeSecretRiskScore additionally fails the exposure
// factor toward the worst case when degraded, so a degraded score is never
// LOWER than a fully-computed one would be.
type SecretRiskScore struct {
	SecretID   uint               `json:"secret_id"`
	SecretName string             `json:"secret_name"`
	Score      int                `json:"score"` // 0-100 weighted composite (higher = riskier)
	Band       string             `json:"band"`  // low | medium | high
	Factors    []SecretRiskFactor `json:"factors"`
	// Degraded is true when the exposure factor could not be fully computed —
	// treat Score/Band as a floor (best-case), not a verified value.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each failed lookup behind the exposure factor.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

func riskBand(score int) string {
	switch {
	case score >= 67:
		return RiskBandHigh
	case score >= 34:
		return RiskBandMedium
	default:
		return RiskBandLow
	}
}

// ComputeSecretRiskScore builds a per-secret risk score. Factor weights:
// expiry 30%, rotation age 30%, usage 20%, exposure 20%.
func (c *KeyorixCore) ComputeSecretRiskScore(ctx context.Context, secretID uint) (*SecretRiskScore, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	now := c.now()

	reads := c.countReads(ctx, secretID, now.AddDate(0, 0, -30))
	principalCount, expoDegraded, expoReasons := c.countPrincipals(ctx, secret)
	return scoreSecret(secret, now, reads, principalCount, expoDegraded, expoReasons), nil
}

// scoreSecret builds a SecretRiskScore from a secret row plus its already-resolved
// usage (read count) and exposure (principal count) inputs — the pure composite-
// scoring logic shared by ComputeSecretRiskScore (which resolves those inputs one
// secret at a time) and ComputeSecretRiskScoresBatch (which resolves them for many
// secrets at once via batched queries, #409), so both produce byte-for-byte the
// same score for the same inputs.
func scoreSecret(secret *models.SecretNode, now time.Time, reads, principalCount int, expoDegraded bool, expoReasons []string) *SecretRiskScore {
	expScore, expDetail := expiryRisk(secret.Expiration, now)
	rotScore, rotDetail := rotationRisk(secret.LastRotatedAt, secret.CreatedAt, now)
	usageScore, usageDetail := usageRisk(reads)

	expoScore, expoDetail := exposureRisk(principalCount)
	if expoDegraded {
		// #407: a share/group-membership lookup failed, so principalCount is an
		// UNDER-count at best — never trust it as a verified low-exposure reading.
		// Fail toward caution: force the worst exposure tier so a widely-shared
		// secret whose exposure lookup errored is never scored as LESS risky (and
		// so never incorrectly deprioritized for rotation) than a fully-resolved
		// equivalent would be.
		expoScore, _ = exposureRisk(1 << 30)
		expoDetail = fmt.Sprintf("Exposure data incomplete (%s) — treated as worst-case until resolved", strings.Join(expoReasons, "; "))
	}

	factors := []SecretRiskFactor{
		{Key: "expiry", Label: "Expiry", Score: expScore, Weight: 0.30, Detail: expDetail},
		{Key: "rotation", Label: "Rotation age", Score: rotScore, Weight: 0.30, Detail: rotDetail},
		{Key: "usage", Label: "Usage", Score: usageScore, Weight: 0.20, Detail: usageDetail},
		{Key: "exposure", Label: "Exposure", Score: expoScore, Weight: 0.20, Detail: expoDetail},
	}

	var composite float64
	for _, f := range factors {
		composite += float64(f.Score) * f.Weight
	}
	score := int(composite + 0.5)

	out := &SecretRiskScore{
		SecretID:   secret.ID,
		SecretName: secret.Name,
		Score:      score,
		Band:       riskBand(score),
		Factors:    factors,
	}
	if expoDegraded {
		out.Degraded = true
		for _, r := range expoReasons {
			out.DegradedReasons = append(out.DegradedReasons, "exposure:"+r)
		}
	}
	return out
}

// ComputeSecretRiskScoresBatch computes the risk score for every secret in
// secretIDs with a small, constant number of storage queries regardless of how
// many secrets are being scored — instead of ComputeSecretRiskScore's ~3+ queries
// called fresh for each one.
//
// #409: GenerateDeploymentRotationPlan called ComputeSecretRiskScore once per
// candidate secret, per project — an O(projects × candidates × groups-per-secret)
// unbounded fan-out on a single request (the same bug family as #238/#393). Each
// input ComputeSecretRiskScore needs is now fetched once for the whole batch: one
// GetSecretsByIDs, one CountSecretReadsBySecretIDs (GROUP BY), one
// ListSharesBySecretIDs, and (only if any share is a group share) one
// ListGroupMembersByGroupIDs — four queries total, not up to 3+N.
//
// Returns a map from secret ID to its score; a secretID with no matching row
// (e.g. deleted between candidate listing and this call) is simply absent from
// the result — callers must treat a missing entry the same as ComputeSecretRiskScore
// returning a "secret not found" error for that one ID.
//
// Batching changes failure GRANULARITY, not the scoring logic or the worst-case
// degrade bias (#407): a single failed grouped query now affects every secret in
// the batch whose score depends on that data, instead of only the one secret whose
// individual per-secret query happened to fail — strictly more conservative than
// before, never less:
//   - GetSecretsByIDs failing outright fails the whole batch (returns an error) —
//     mirrors ComputeSecretRiskScore's own GetSecret failure, just widened from one
//     secret to every secret requested in this call.
//   - CountSecretReadsBySecretIDs failing falls back to zero reads for every
//     secret, same as countReads' own per-secret fallback (never an error, never a
//     Degraded flag — usage was never part of the exposure-degrade contract).
//   - ListSharesBySecretIDs failing degrades every secret's exposure factor to the
//     worst case, same as countPrincipals' own per-secret "shares:" failure.
//   - ListGroupMembersByGroupIDs failing degrades only the secrets that actually
//     have a group share (secrets with only direct-user shares, or no shares, are
//     unaffected) — the query covers every group referenced by any candidate, so a
//     failure there means every one of those groups' membership is unresolved.
func (c *KeyorixCore) ComputeSecretRiskScoresBatch(ctx context.Context, secretIDs []uint) (map[uint]*SecretRiskScore, error) {
	out := make(map[uint]*SecretRiskScore, len(secretIDs))
	if len(secretIDs) == 0 {
		return out, nil
	}

	secrets, err := c.storage.GetSecretsByIDs(ctx, secretIDs)
	if err != nil {
		return nil, fmt.Errorf("get secrets: %w", err)
	}
	now := c.now()

	readCounts, err := c.storage.CountSecretReadsBySecretIDs(ctx, secretIDs, now.AddDate(0, 0, -30))
	if err != nil {
		// Same fallback as countReads: an unreadable read count is treated as zero
		// reads, not an error and not a Degraded flag.
		readCounts = map[uint]int{}
	}

	sharesBySecret := map[uint][]*models.ShareRecord{}
	sharesFailed := false
	var sharesErr error
	if shares, err := c.storage.ListSharesBySecretIDs(ctx, secretIDs); err != nil {
		sharesFailed = true
		sharesErr = err
	} else {
		for _, sh := range shares {
			sharesBySecret[sh.SecretID] = append(sharesBySecret[sh.SecretID], sh)
		}
	}

	groupIDSet := map[uint]struct{}{}
	for _, shares := range sharesBySecret {
		for _, sh := range shares {
			if sh.IsGroup {
				groupIDSet[sh.RecipientID] = struct{}{}
			}
		}
	}
	membersByGroup := map[uint][]*models.User{}
	groupsFailed := false
	var groupsErr error
	if len(groupIDSet) > 0 {
		groupIDs := make([]uint, 0, len(groupIDSet))
		for id := range groupIDSet {
			groupIDs = append(groupIDs, id)
		}
		if m, err := c.storage.ListGroupMembersByGroupIDs(ctx, groupIDs); err != nil {
			groupsFailed = true
			groupsErr = err
		} else {
			membersByGroup = m
		}
	}

	for _, secret := range secrets {
		principalCount, expoDegraded, expoReasons := principalsFromBatch(
			secret, sharesBySecret[secret.ID], membersByGroup, sharesFailed, sharesErr, groupsFailed, groupsErr,
		)
		out[secret.ID] = scoreSecret(secret, now, readCounts[secret.ID], principalCount, expoDegraded, expoReasons)
	}
	return out, nil
}

// principalsFromBatch is the batch-friendly equivalent of countPrincipals: same
// owner+shares+group-members counting logic, but reading from data already
// fetched for the whole candidate batch instead of issuing its own per-secret
// queries. See ComputeSecretRiskScoresBatch for how sharesFailed/groupsFailed
// (batch-wide) map onto countPrincipals' original per-secret failure reasons.
func principalsFromBatch(
	secret *models.SecretNode, shares []*models.ShareRecord, membersByGroup map[uint][]*models.User,
	sharesFailed bool, sharesErr error, groupsFailed bool, groupsErr error,
) (count int, degraded bool, reasons []string) {
	principals := map[uint]struct{}{}
	if secret.OwnerID != 0 {
		principals[secret.OwnerID] = struct{}{}
	}
	if sharesFailed {
		return len(principals), true, []string{fmt.Sprintf("shares: %v", sharesErr)}
	}
	for _, sh := range shares {
		if sh.IsGroup {
			if groupsFailed {
				degraded = true
				reasons = append(reasons, fmt.Sprintf("group_members:group=%d: %v", sh.RecipientID, groupsErr))
				continue
			}
			for _, m := range membersByGroup[sh.RecipientID] {
				principals[m.ID] = struct{}{}
			}
		} else {
			principals[sh.RecipientID] = struct{}{}
		}
	}
	return len(principals), degraded, reasons
}

func expiryRisk(exp *time.Time, now time.Time) (int, string) {
	if exp == nil {
		return 40, "No expiration set"
	}
	days := int(exp.Sub(now).Hours() / 24)
	switch {
	case days < 0:
		return 100, fmt.Sprintf("Expired %d day(s) ago", -days)
	case days <= 7:
		return 80, fmt.Sprintf("Expires in %d day(s)", days)
	case days <= 30:
		return 50, fmt.Sprintf("Expires in %d day(s)", days)
	default:
		return 10, fmt.Sprintf("Expires in %d day(s)", days)
	}
}

func rotationRisk(lastRotated *time.Time, created, now time.Time) (int, string) {
	basis, verb := created, "created"
	if lastRotated != nil {
		basis, verb = *lastRotated, "rotated"
	}
	days := int(now.Sub(basis).Hours() / 24)

	var score int
	switch {
	case days < 30:
		score = 10
	case days < 90:
		score = 30
	case days < 180:
		score = 60
	case days < 365:
		score = 80
	default:
		score = 100
	}

	never := ""
	if lastRotated == nil {
		never = " (never rotated)"
		if days >= 90 && score < 100 {
			score += 10
		}
	}
	return score, fmt.Sprintf("Last %s %d day(s) ago%s", verb, days, never)
}

func usageRisk(reads int) (int, string) {
	switch {
	case reads == 0:
		return 80, "No reads in the last 30 days"
	case reads <= 5:
		return 40, fmt.Sprintf("%d read(s) in the last 30 days", reads)
	default:
		return 10, fmt.Sprintf("%d reads in the last 30 days", reads)
	}
}

func exposureRisk(principals int) (int, string) {
	switch {
	case principals <= 1:
		return 10, "Only the owner has access"
	case principals <= 5:
		return 30, fmt.Sprintf("%d principals have access", principals)
	case principals <= 15:
		return 60, fmt.Sprintf("%d principals have access", principals)
	default:
		return 90, fmt.Sprintf("%d principals have access", principals)
	}
}

func (c *KeyorixCore) countReads(ctx context.Context, secretID uint, since time.Time) int {
	logs, err := c.storage.ListSecretAccessLogs(ctx, secretID, since)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range logs {
		if l.Action == "read" {
			n++
		}
	}
	return n
}

// countPrincipals counts the distinct users that can read a secret: the owner
// plus direct share recipients plus the members of any group it is shared with.
// degraded is true when a ListSharesBySecret/ListGroupMembers lookup failed — the
// returned count is then an UNDER-count (a share or group's members are missing
// from the tally), never a verified low-exposure reading. See #407: this used to
// silently fall back to an owner-only (or partial) count on any such error,
// deflating the exposure factor that both the risk dashboard and auto-rotation
// prioritization (rotation_planner.go) rely on.
func (c *KeyorixCore) countPrincipals(ctx context.Context, secret *models.SecretNode) (count int, degraded bool, reasons []string) {
	principals := map[uint]struct{}{}
	if secret.OwnerID != 0 { // an ownerless (machine-created) secret has no owner principal
		principals[secret.OwnerID] = struct{}{}
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secret.ID)
	if err != nil {
		return len(principals), true, []string{fmt.Sprintf("shares: %v", err)}
	}
	for _, sh := range shares {
		if sh.IsGroup {
			members, err := c.storage.ListGroupMembers(ctx, sh.RecipientID)
			if err != nil {
				degraded = true
				reasons = append(reasons, fmt.Sprintf("group_members:group=%d: %v", sh.RecipientID, err))
				continue
			}
			for _, m := range members {
				principals[m.ID] = struct{}{}
			}
		} else {
			principals[sh.RecipientID] = struct{}{}
		}
	}
	return len(principals), degraded, reasons
}
