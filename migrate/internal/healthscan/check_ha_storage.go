package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "ha-storage", Title: "HA and storage topology", Fn: checkHAStorage})
	RegisterCheck(Check{ID: "raft-autopilot", Title: "Raft autopilot health", Fn: checkRaftAutopilot})
}

// checkHAStorage is SESSION-G2 item (c)'s HA/leader/peer half: storage type (from
// sys/seal-status, which carries it alongside seal info), HA/standby status (sys/leader), and
// raft peer/voter count (sys/storage/raft/configuration, only meaningful when storage is raft).
func checkHAStorage(ctx context.Context, c *Client) Result {
	var seal struct {
		StorageType string `json:"storage_type"`
	}
	sealStatus, err := getJSON(ctx, c, "sys/seal-status", &seal)
	if err != nil {
		return Result{Err: err}
	}
	if sealStatus == StatusForbidden {
		return denied("ha-storage", "sys/seal-status", `path "sys/seal-status" { capabilities = ["read"] }`)
	}

	var leader struct {
		HAEnabled          bool `json:"ha_enabled"`
		IsSelf             bool `json:"is_self"`
		PerformanceStandby bool `json:"performance_standby"`
	}
	leaderStatus, err := getJSON(ctx, c, "sys/leader", &leader)
	if err != nil {
		return Result{Err: err}
	}
	if leaderStatus == StatusForbidden {
		return denied("ha-storage", "sys/leader", `path "sys/leader" { capabilities = ["read"] }`)
	}

	evidence := fmt.Sprintf("storage=%s, ha_enabled=%t, node_is_leader=%t, performance_standby=%t",
		valueOrUnknown(seal.StorageType), leader.HAEnabled, leader.IsSelf, leader.PerformanceStandby)
	sev := SeverityInfo
	remediation := ""
	if !leader.HAEnabled {
		sev = SeverityHigh
		remediation = "Run Vault in HA mode (a storage backend that supports it, e.g. raft or Consul) so a single node failure doesn't take the whole install down."
	}

	if seal.StorageType != "raft" {
		return Result{Finding: &Finding{
			ID: "ha-storage", Title: "HA and storage topology", Severity: sev,
			Evidence: evidence + " (peer/voter count only checked for raft storage)", WhyItMatters: "Single-node or non-HA storage is a single point of failure.",
			Remediation: remediation,
		}}
	}

	var raftConfig struct {
		Data struct {
			Config struct {
				Servers []struct {
					NodeID string `json:"node_id"`
					Voter  bool   `json:"voter"`
					Leader bool   `json:"leader"`
				} `json:"servers"`
			} `json:"config"`
		} `json:"data"`
	}
	raftStatus, err := getJSON(ctx, c, "sys/storage/raft/configuration", &raftConfig)
	if err != nil {
		return Result{Err: err}
	}
	if raftStatus == StatusForbidden {
		return denied("ha-storage", "sys/storage/raft/configuration", `path "sys/storage/raft/configuration" { capabilities = ["read"] }`)
	}

	voters := 0
	for _, s := range raftConfig.Data.Config.Servers {
		if s.Voter {
			voters++
		}
	}
	total := len(raftConfig.Data.Config.Servers)
	evidence = fmt.Sprintf("%s, raft peers=%d (voters=%d)", evidence, total, voters)
	if total <= 1 {
		sev = SeverityHigh
		remediation = "A single-node raft cluster has no redundancy — add at least 2 more voting peers for quorum to survive one node's loss."
	}

	return Result{Finding: &Finding{
		ID: "ha-storage", Title: "HA and storage topology", Severity: sev,
		Evidence: evidence, WhyItMatters: "Single-node or non-HA storage is a single point of failure.", Remediation: remediation,
	}}
}

// checkRaftAutopilot is (c)'s autopilot-health half. Only meaningful for raft storage — a 404
// (raft autopilot not present, e.g. non-raft storage or a Vault too old to have autopilot) is
// "not applicable," not a gap.
func checkRaftAutopilot(ctx context.Context, c *Client) Result {
	var autopilot struct {
		Data struct {
			Healthy          bool `json:"healthy"`
			FailureTolerance int  `json:"failure_tolerance"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/storage/raft/autopilot/state", &autopilot)
	if err != nil {
		return Result{Err: err}
	}
	switch status {
	case StatusForbidden:
		return denied("raft-autopilot", "sys/storage/raft/autopilot/state", `path "sys/storage/raft/autopilot/state" { capabilities = ["read"] }`)
	case StatusNotFound:
		return Result{Finding: &Finding{
			ID: "raft-autopilot", Title: "Raft autopilot health", Severity: SeverityInfo,
			Evidence: "not present (non-raft storage, or a Vault version without autopilot)",
		}}
	case StatusOK:
		sev := SeverityInfo
		remediation := ""
		if !autopilot.Data.Healthy {
			sev = SeverityHigh
			remediation = "Investigate the unhealthy raft peer(s) — autopilot reports the cluster is not in a fully healthy state."
		}
		return Result{Finding: &Finding{
			ID: "raft-autopilot", Title: "Raft autopilot health", Severity: sev,
			Evidence:     fmt.Sprintf("healthy=%t, failure_tolerance=%d", autopilot.Data.Healthy, autopilot.Data.FailureTolerance),
			WhyItMatters: "Autopilot tracks raft cluster health continuously; an unhealthy cluster may be one more node loss away from losing quorum.",
			Remediation:  remediation,
		}}
	default:
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/storage/raft/autopilot/state", status)}
	}
}
