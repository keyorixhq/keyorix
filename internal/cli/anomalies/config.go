package anomalies

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// anomalyConfigRecord mirrors models.AnomalyConfigRecord for CLI JSON decoding.
type anomalyConfigRecord struct {
	LookbackDays     int     `json:"lookback_days"`
	QuarantineHours  int     `json:"quarantine_hours"`
	OffHoursEnabled  bool    `json:"off_hours_enabled"`
	OffHoursTimezone string  `json:"off_hours_timezone"`
	OffHoursStart    int     `json:"off_hours_start"`
	OffHoursEnd      int     `json:"off_hours_end"`
	MLEnabled        bool    `json:"ml_enabled"`
	MLThreshold      float64 `json:"ml_threshold"`
	MLNumTrees       int     `json:"ml_num_trees"`
	MLSampleSize     int     `json:"ml_sample_size"`
	UpdatedAt        string  `json:"updated_at"`
	UpdatedBy        string  `json:"updated_by"`
}

type anomalyConfigResponse struct {
	Config anomalyConfigRecord `json:"config"`
}

// configCmd is the "anomaly config" subcommand group.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage anomaly detection runtime configuration",
}

var configGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the current anomaly detection configuration",
	RunE:  runConfigGet,
}

// flags for "anomaly config set"
var (
	cfgLookbackDays     int
	cfgQuarantineHours  int
	cfgOffHoursEnabled  bool
	cfgOffHoursTimezone string
	cfgOffHoursStart    int
	cfgOffHoursEnd      int
	cfgMLEnabled        bool
	cfgMLThreshold      float64
	cfgMLNumTrees       int
	cfgMLSampleSize     int
)

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update one or more anomaly detection configuration fields",
	Long: `Update the anomaly detection runtime configuration.

Only flags that are explicitly provided are changed; all others keep their
current stored values.  Changes take effect on the next detection scan
without restarting the server.`,
	RunE: runConfigSet,
}

func init() {
	configSetCmd.Flags().IntVar(&cfgLookbackDays, "lookback-days", 0, "Lookback window for baseline (days)")
	configSetCmd.Flags().IntVar(&cfgQuarantineHours, "quarantine-hours", 0, "Quarantine period before a new actor is trusted (hours)")
	configSetCmd.Flags().BoolVar(&cfgOffHoursEnabled, "off-hours-enabled", false, "Enable off-hours rule")
	configSetCmd.Flags().StringVar(&cfgOffHoursTimezone, "off-hours-timezone", "", "IANA timezone for off-hours band (e.g. America/New_York)")
	configSetCmd.Flags().IntVar(&cfgOffHoursStart, "off-hours-start", 0, "Off-hours band start hour (0–23)")
	configSetCmd.Flags().IntVar(&cfgOffHoursEnd, "off-hours-end", 0, "Off-hours band end hour (0–23)")
	configSetCmd.Flags().BoolVar(&cfgMLEnabled, "ml-enabled", false, "Enable ML (Isolation Forest) anomaly detection")
	configSetCmd.Flags().Float64Var(&cfgMLThreshold, "ml-threshold", 0, "ML anomaly-score threshold (0.5–1.0)")
	configSetCmd.Flags().IntVar(&cfgMLNumTrees, "ml-num-trees", 0, "ML Isolation Forest tree count")
	configSetCmd.Flags().IntVar(&cfgMLSampleSize, "ml-sample-size", 0, "ML Isolation Forest per-tree subsample size")

	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	AnomaliesCmd.AddCommand(configCmd)
}

const anomalyConfigPath = "/api/v1/admin/anomaly-config"

func runConfigGet(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runConfigGetRemote(rc)
}

func runConfigGetRemote(rc *common.RemoteClient) error {
	var resp anomalyConfigResponse
	if err := rc.Get(context.Background(), anomalyConfigPath, &resp); err != nil {
		return err
	}
	printAnomalyConfig(resp.Config)
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runConfigSetRemote(rc, cmd)
}

func runConfigSetRemote(rc *common.RemoteClient, cmd *cobra.Command) error {
	// NOTE on the GET-then-PUT race (unsynchronized read-modify-write):
	//
	// The server-side full-replace PUT semantic this relies on is a deliberate,
	// accepted tradeoff, not a bug -- confirmed during a repo-wide full-row-
	// overwrite sweep (see internal/core/anomaly_config.go's UpdateAnomalyConfig).
	//
	// This is a full-replace update: we GET the current config, patch only the
	// flags the caller passed on the CLI, and PUT the whole object back. If two
	// "anomaly config set" invocations (or any other future writer of this
	// endpoint) run concurrently, the later PUT can silently clobber the
	// earlier one's change based on its own stale GET — a classic lost-update
	// race. There is currently no server-side primitive to close this window:
	// AnomalyConfigRecord has no version/ETag column, UpdateAnomalyConfig
	// (internal/core/anomaly_config.go) unconditionally stamps UpdatedAt with
	// time.Now() on every call, and LocalStorage.SaveAnomalyConfig
	// (internal/storage/store/local_anomaly_config.go) does an unconditional
	// GORM Save — there is no compare-and-swap to build a conditional PUT on.
	//
	// Adding real optimistic concurrency (a version field + migration +
	// conditional UPDATE ... WHERE version = ? threaded through the storage
	// interface, both storage backends, the core layer, and the HTTP handler)
	// is out of scope for this CLI-hygiene pass, and this isn't a security
	// boundary — anomaly-config is an infrequently-touched operator knob, not
	// a control an attacker can leverage by winning the race. If concurrent
	// operators updating this config becomes a real operational problem,
	// revisit with a proper version/ETag column on AnomalyConfigRecord.
	//
	// The window itself is already minimal: everything between the GET and
	// the PUT below is pure in-memory flag application and JSON marshaling —
	// no I/O, no unrelated work — so there is nothing further to trim here.
	//
	// Fetch the current config so we can do a partial update (only changed flags).
	var resp anomalyConfigResponse
	if err := rc.Get(context.Background(), anomalyConfigPath, &resp); err != nil {
		return fmt.Errorf("fetch current config: %w", err)
	}
	current := resp.Config

	// Apply only the flags the caller explicitly provided.
	if cmd.Flags().Changed("lookback-days") {
		current.LookbackDays = cfgLookbackDays
	}
	if cmd.Flags().Changed("quarantine-hours") {
		current.QuarantineHours = cfgQuarantineHours
	}
	if cmd.Flags().Changed("off-hours-enabled") {
		current.OffHoursEnabled = cfgOffHoursEnabled
	}
	if cmd.Flags().Changed("off-hours-timezone") {
		current.OffHoursTimezone = cfgOffHoursTimezone
	}
	if cmd.Flags().Changed("off-hours-start") {
		current.OffHoursStart = cfgOffHoursStart
	}
	if cmd.Flags().Changed("off-hours-end") {
		current.OffHoursEnd = cfgOffHoursEnd
	}
	if cmd.Flags().Changed("ml-enabled") {
		current.MLEnabled = cfgMLEnabled
	}
	if cmd.Flags().Changed("ml-threshold") {
		current.MLThreshold = cfgMLThreshold
	}
	if cmd.Flags().Changed("ml-num-trees") {
		current.MLNumTrees = cfgMLNumTrees
	}
	if cmd.Flags().Changed("ml-sample-size") {
		current.MLSampleSize = cfgMLSampleSize
	}

	var updated anomalyConfigResponse
	// Marshal current (the patched struct) into a generic map for the PUT body.
	b, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(b, &body); err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := rc.Put(context.Background(), anomalyConfigPath, body, &updated); err != nil {
		return err
	}
	fmt.Println("Anomaly detection configuration updated.")
	printAnomalyConfig(updated.Config)
	return nil
}

func printAnomalyConfig(cfg anomalyConfigRecord) {
	fmt.Printf("Lookback:          %d days\n", cfg.LookbackDays)
	fmt.Printf("Quarantine:        %d hours\n", cfg.QuarantineHours)
	fmt.Printf("Off-hours enabled: %v\n", cfg.OffHoursEnabled)
	fmt.Printf("Off-hours tz:      %s\n", cfg.OffHoursTimezone)
	fmt.Printf("Off-hours band:    %02d:00–%02d:00\n", cfg.OffHoursStart, cfg.OffHoursEnd)
	fmt.Printf("ML enabled:        %v\n", cfg.MLEnabled)
	fmt.Printf("ML threshold:      %.2f\n", cfg.MLThreshold)
	fmt.Printf("ML num trees:      %d\n", cfg.MLNumTrees)
	fmt.Printf("ML sample size:    %d\n", cfg.MLSampleSize)
	if cfg.UpdatedBy != "" {
		fmt.Printf("Last updated by:   %s at %s\n", cfg.UpdatedBy, cfg.UpdatedAt)
	}
}
