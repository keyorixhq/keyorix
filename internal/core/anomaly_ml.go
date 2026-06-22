package core

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ML-based anomaly detection (ADR-050) layered onto the statistical rules in
// anomaly.go. The rules fire on a single binary signal (off-hours by a fixed clock
// band, a never-before-seen IP, a never-before-seen user, a volume spike). They are
// blind to two things an Isolation Forest catches:
//
//   - graduated rarity — an actor or IP that *is* in the baseline but is used only
//     rarely (the new_user/new_ip rules see "known" and stay silent);
//   - multivariate combinations — an access whose hour, source and actor are each
//     unremarkable alone but jointly fall in a sparse region of the learned pattern.
//
// A forest trained on the secret's 30-day access baseline scores each recent access
// on its joint feature vector; points it isolates quickly (a short average path
// length) are flagged as ml_outlier. It does not replace the rules — it complements
// them, and where a brand-new actor trips both, the higher ML score corroborates the
// rule. Metadata only — secret values are never examined.

const (
	// mlMinTrainSamples is the floor of baseline access events below which ML scoring
	// is skipped: an Isolation Forest learns nothing useful from a handful of points,
	// and the statistical rules already cover sparse-history secrets. The forest is
	// per-secret, so this is per-secret history, not global.
	mlMinTrainSamples = 20
	// mlHighSeverityScore is the anomaly-score cutoff at or above which an ml_outlier
	// is reported "high" rather than "medium". Scores approach 1.0 for points the
	// forest isolates almost immediately.
	mlHighSeverityScore = 0.75
)

// MLConfig gates and parameterises the Isolation Forest pass. Disabled by default;
// the statistical detection in anomaly.go always runs regardless. Normalise via
// withDefaults before use so a partially-specified config still has sane values.
type MLConfig struct {
	Enabled    bool
	Threshold  float64 // anomaly-score cutoff in (0.5,1.0); events scoring above it are flagged
	NumTrees   int     // ensemble size
	SampleSize int     // per-tree subsample size (psi)
	Seed       int64   // RNG seed, for reproducible scoring
}

// withDefaults returns a copy with any unset/out-of-range fields filled with the
// defaults from the paper's recommendations (100 trees, psi=256) and a threshold
// tuned to this feature set's score distribution: with the low-dimensional access
// features, normal accesses cluster near 0.5 and the genuinely rare tail reaches
// ~0.65–0.8, so 0.60 cleanly separates them while staying clear of the noise floor.
// A non-positive seed becomes a fixed constant so scoring stays deterministic across
// restarts rather than drifting with wall-clock entropy.
func (c MLConfig) withDefaults() MLConfig {
	if c.Threshold <= 0.5 || c.Threshold >= 1.0 {
		c.Threshold = 0.60
	}
	if c.NumTrees <= 0 {
		c.NumTrees = 100
	}
	if c.SampleSize <= 1 {
		c.SampleSize = 256
	}
	if c.Seed <= 0 {
		c.Seed = 1
	}
	return c
}

// accessFeatures turns one access-log entry into the feature vector the forest splits
// on, using the supplied baseline frequency maps for the novelty signals. Four
// dimensions, deliberately low and interpretable:
//
//	[0],[1] hour of day, cyclically encoded as (sin,cos) of 2π·hour/24
//	[2]     baseline count of this IP   — 0 for an unseen IP; small for a rarely-seen one
//	[3]     baseline count of this user — 0 for an unseen user; small for a rare one
//
// Hour is encoded on the unit circle rather than as a raw 0–23 integer for two
// reasons: it makes 23:00 and 01:00 adjacent (a raw integer would call them maximally
// distant), and it places every hour in the *interior* of a bounded space, so an
// access at an unused hour falls in an empty interior region the forest isolates
// quickly — a raw out-of-range integer would be an extrapolation point, which
// Isolation Forest separates poorly. Each tree splits on a single feature's own
// observed range, so the differing scales (unit-circle vs. counts) need no
// normalisation.
func accessFeatures(lg models.SecretAccessLog, ipFreq, userFreq map[string]int) []float64 {
	radians := 2 * math.Pi * float64(lg.AccessTime.UTC().Hour()) / 24
	return []float64{
		math.Sin(radians),
		math.Cos(radians),
		float64(ipFreq[lg.IPAddress]),
		float64(userFreq[lg.AccessedBy]),
	}
}

// mlOutlierAlerts trains a per-secret Isolation Forest on the baseline access logs and
// returns an ml_outlier alert for each recent access whose anomaly score exceeds the
// configured threshold. Returns nil when there is too little baseline to train on or
// the forest could not be grown — the caller then relies on the statistical rules.
func mlOutlierAlerts(secret models.SecretNode, baselineLogs, recentLogs []models.SecretAccessLog, cfg MLConfig, now time.Time) []models.AnomalyAlert {
	cfg = cfg.withDefaults()
	if len(baselineLogs) < mlMinTrainSamples || len(recentLogs) == 0 {
		return nil
	}

	ipFreq := make(map[string]int, len(baselineLogs))
	userFreq := make(map[string]int, len(baselineLogs))
	for _, lg := range baselineLogs {
		if lg.IPAddress != "" {
			ipFreq[lg.IPAddress]++
		}
		if lg.AccessedBy != "" {
			userFreq[lg.AccessedBy]++
		}
	}

	train := make([][]float64, len(baselineLogs))
	for i, lg := range baselineLogs {
		train[i] = accessFeatures(lg, ipFreq, userFreq)
	}

	rng := rand.New(rand.NewSource(cfg.Seed)) // #nosec G404 -- model sampling must be reproducible, not unpredictable; no security decision rides on this RNG
	forest := newIsolationForest(train, cfg.NumTrees, cfg.SampleSize, rng)
	if forest == nil {
		return nil
	}

	var alerts []models.AnomalyAlert
	for _, lg := range recentLogs {
		score := forest.score(accessFeatures(lg, ipFreq, userFreq))
		if score < cfg.Threshold {
			continue
		}
		severity := "medium"
		if score >= mlHighSeverityScore {
			severity = "high"
		}
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "ml_outlier",
			Severity:     severity,
			Description: fmt.Sprintf("ML detected an anomalous access pattern (score %.2f): %s from %s at %s UTC differs from this secret's learned baseline",
				score, displayOrUnknown(lg.AccessedBy), displayOrUnknown(lg.IPAddress), lg.AccessTime.UTC().Format("15:04")),
			AccessedBy: lg.AccessedBy,
			IPAddress:  lg.IPAddress,
			DetectedAt: now,
		})
	}
	return alerts
}

// displayOrUnknown renders an empty actor/IP as a readable placeholder in alert text.
func displayOrUnknown(s string) string {
	if s == "" {
		return "an unknown source"
	}
	return s
}
