package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mathrand "math/rand"
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
//
// A non-positive seed is drawn from crypto/rand, not a fixed constant (#101): every
// default deployment used to run an IDENTICAL, publicly-known-from-source forest
// structure (seed=1), so an attacker who knew (or could infer) the training data could
// precompute which subsamples/splits an access would land in and craft one that the
// forest isolates poorly — i.e. tune an access to score low on purpose. An operator who
// genuinely wants reproducible scoring (e.g. to diff forest behavior across a config
// change) can still set Seed explicitly; only the *unset* default stops being a known
// constant.
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
		c.Seed = randomSeed()
	}
	return c
}

// randomSeed draws a positive int64 from crypto/rand for MLConfig's default seed. Falls
// back to a time-based seed only if the OS CSPRNG is unavailable — vanishingly rare, and
// still per-process-unique rather than a hardcoded constant.
func randomSeed() int64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return time.Now().UnixNano()
	}
	v := int64(binary.BigEndian.Uint64(buf[:]) >> 1) // clear sign bit: always positive
	if v <= 0 {
		v = 1
	}
	return v
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

// buildFreqMapsWithCutoff is like buildFreqMaps but skips any log entry whose
// AccessTime is not strictly before trustCutoff — the ANOMALY-03 quarantine
// guard that prevents an attacker's recently-seen IP/user from inflating its
// frequency score in the ML training features.
func buildFreqMapsWithCutoff(logs []models.SecretAccessLog, trustCutoff time.Time) (ipFreq, userFreq map[string]int) {
	ipFreq = make(map[string]int, len(logs))
	userFreq = make(map[string]int, len(logs))
	for _, lg := range logs {
		if !lg.AccessTime.Before(trustCutoff) {
			continue
		}
		if lg.IPAddress != "" {
			ipFreq[lg.IPAddress]++
		}
		if lg.AccessedBy != "" {
			userFreq[lg.AccessedBy]++
		}
	}
	return
}

func mlOutlierSeverity(score float64) string {
	if score >= mlHighSeverityScore {
		return "high"
	}
	return "medium"
}

// mlOutlierAlerts trains a per-secret Isolation Forest on the baseline access logs and
// returns an ml_outlier alert for each recent access whose anomaly score exceeds the
// configured threshold. Returns nil when there is too little baseline to train on or
// the forest could not be grown — the caller then relies on the statistical rules.
//
// mlQuarantineDuration mirrors the statistical baseline's quarantine period (#101).
// Without this filter, warm-up accesses (e.g. from an attacker's IP, 25+ hours old)
// age into the ML training feature maps and inflate ipFreq/userFreq for that
// attacker-controlled IP — lowering its novelty signal in the forest and potentially
// letting malicious accesses score below the detection threshold.
const mlQuarantineDuration = 24 * time.Hour

func mlOutlierAlerts(secret models.SecretNode, baselineLogs, recentLogs []models.SecretAccessLog, cfg MLConfig, now time.Time) []models.AnomalyAlert {
	cfg = cfg.withDefaults()
	if len(baselineLogs) < mlMinTrainSamples || len(recentLogs) == 0 {
		return nil
	}

	// ANOMALY-03: compute the same trustCutoff used by buildBaseline so that accesses
	// inside the quarantine window are excluded from the ML feature-frequency maps.
	// "windowStart" is derived as the minimum AccessTime across recentLogs; falls back
	// to now minus mlQuarantineDuration (guarded above, so this is belt-and-suspenders).
	windowStart := now
	for _, lg := range recentLogs {
		if lg.AccessTime.Before(windowStart) {
			windowStart = lg.AccessTime
		}
	}
	mlTrustCutoff := windowStart.Add(-mlQuarantineDuration)
	ipFreq, userFreq := buildFreqMapsWithCutoff(baselineLogs, mlTrustCutoff)

	train := make([][]float64, len(baselineLogs))
	for i, lg := range baselineLogs {
		train[i] = accessFeatures(lg, ipFreq, userFreq)
	}

	// #nosec G404 -- math/rand, seeded from cfg.Seed, drives tree-building sampling only;
	// the seed itself is crypto/rand-sourced by default (see randomSeed), so an attacker
	// cannot predict the forest structure. An explicitly configured seed opts back into
	// deterministic-for-reproducibility behavior on purpose.
	rng := mathrand.New(mathrand.NewSource(cfg.Seed))
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
		alerts = append(alerts, models.AnomalyAlert{
			SecretNodeID: secret.ID,
			SecretName:   secret.Name,
			AlertType:    "ml_outlier",
			Severity:     mlOutlierSeverity(score),
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
