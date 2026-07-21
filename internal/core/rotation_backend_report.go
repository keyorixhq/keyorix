// rotation_backend_report.go — deployment-wide rotation-overdue aggregation grouped
// by RotationBackend so operators can see "200 secrets overdue on Postgres, 50 on
// Vault" to triage remediation. Uses the same rotation-status evaluation path as the
// compliance-posture and hygiene-rollup callers — no new storage queries.
package core

import (
	"context"
	"sort"
	"time"
)

// BackendRotationStat holds per-backend rotation counts for the overdue-by-backend
// report.
type BackendRotationStat struct {
	// Backend is the RotationBackend label — e.g. "aws_sm", "vault", "generic",
	// or "" (empty string) for secrets whose rotation is regenerated in Keyorix only.
	Backend      string `json:"backend"`
	Total        int    `json:"total"`         // total secrets with a rotation policy on this backend
	Overdue      int    `json:"overdue"`        // past their scheduled rotation date
	UpToDate     int    `json:"up_to_date"`     // rotated within their schedule (ok + due_soon)
	NeverRotated int    `json:"never_rotated"`  // policy set but LastRotatedAt is nil
}

// RotationBackendReport is the response body for GET /api/v1/compliance/rotation-by-backend.
type RotationBackendReport struct {
	GeneratedAt  time.Time             `json:"generated_at"`
	Backends     []BackendRotationStat `json:"backends"`
	TotalOverdue int                   `json:"total_overdue"`
}

// GetRotationBackendReport aggregates rotation-policy status (overdue / up-to-date /
// never-rotated) grouped by RotationBackend across the whole deployment.
//
// It reuses GetRotationStatus with no project filter so the result spans every
// active policy; callers should gate this endpoint on audit.read.
func (k *KeyorixCore) GetRotationBackendReport(ctx context.Context) (*RotationBackendReport, error) {
	entries, err := k.GetRotationStatus(ctx, nil, nil)
	if err != nil {
		return nil, err
	}

	// Accumulate per-backend stats in a map; preserve insertion order for stable
	// output by tracking first-seen order separately.
	type mutableStat struct {
		BackendRotationStat
	}
	byBackend := make(map[string]*mutableStat)
	var order []string

	for _, e := range entries {
		key := e.RotationBackend
		stat, ok := byBackend[key]
		if !ok {
			stat = &mutableStat{BackendRotationStat{Backend: key}}
			byBackend[key] = stat
			order = append(order, key)
		}
		stat.Total++
		if e.LastRotatedAt == nil {
			stat.NeverRotated++
		}
		if e.Status == RotationStatusOverdue {
			stat.Overdue++
		} else {
			stat.UpToDate++
		}
	}

	// Build result slice sorted by Overdue descending, then by Backend name for
	// determinism within ties.
	stats := make([]BackendRotationStat, 0, len(order))
	for _, key := range order {
		stats = append(stats, byBackend[key].BackendRotationStat)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Overdue != stats[j].Overdue {
			return stats[i].Overdue > stats[j].Overdue
		}
		return stats[i].Backend < stats[j].Backend
	})

	totalOverdue := 0
	for _, s := range stats {
		totalOverdue += s.Overdue
	}

	return &RotationBackendReport{
		GeneratedAt:  k.now(),
		Backends:     stats,
		TotalOverdue: totalOverdue,
	}, nil
}
