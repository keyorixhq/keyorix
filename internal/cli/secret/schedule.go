// schedule.go — the `keyorix secret schedule` CLI: manage per-secret temporal access policies.
//
// Commands:
//
//	keyorix secret set-schedule <name> --days mon,tue,wed,thu,fri --start-hour 9 --end-hour 17 [--timezone UTC]
//	keyorix secret get-schedule <name>
//	keyorix secret clear-schedule <name>
//
// All three commands talk to the server's REST API under
// /api/v1/secrets/{id}/schedule, requiring secrets.manage permission server-side.
//
// Day names ("mon", "tue", …, "sun") are converted to ISO weekday numbers before
// being sent; integers ("1"–"7") are passed through as-is.
package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// dayNameToISO maps 3-letter English day abbreviations to ISO weekday numbers (Mon=1…Sun=7).
var dayNameToISO = map[string]int{
	"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7,
}

// convertDayNames converts a comma-separated list of day names or numbers
// (e.g. "mon,fri" or "1,5" or "*") to a canonical comma-separated ISO integer string.
func convertDayNames(days string) (string, error) {
	if days == "*" {
		return "*", nil
	}
	var parts []string
	for _, raw := range strings.Split(days, ",") {
		s := strings.TrimSpace(strings.ToLower(raw))
		if iso, ok := dayNameToISO[s]; ok {
			parts = append(parts, strconv.Itoa(iso))
			continue
		}
		// Try numeric.
		d, err := strconv.Atoi(s)
		if err != nil || d < 1 || d > 7 {
			return "", fmt.Errorf("invalid day %q: must be mon–sun or 1–7 (or \"*\")", raw)
		}
		parts = append(parts, strconv.Itoa(d))
	}
	return strings.Join(parts, ","), nil
}

var (
	schedDays      string
	schedStartHour int
	schedEndHour   int
	schedTimezone  string
)

var setScheduleCmd = &cobra.Command{
	Use:   "set-schedule <secret-name>",
	Short: "Set a temporal access schedule for a secret",
	Long: `Restrict read access to a secret to a specific day-of-week + hour window.

The schedule applies to all permission-checked reads (human users); admin/machine
reads bypass it.

Examples:
  keyorix secret set-schedule db-prod-password --days mon,tue,wed,thu,fri --start-hour 9 --end-hour 17
  keyorix secret set-schedule db-prod-password --days 1,2,3,4,5 --start-hour 9 --end-hour 17 --timezone America/New_York
  keyorix secret set-schedule db-prod-password --days "*" --start-hour 0 --end-hour 24`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		isoDays, err := convertDayNames(schedDays)
		if err != nil {
			return err
		}
		tz := schedTimezone
		if tz == "" {
			tz = "UTC"
		}
		c, err := scheduleClient()
		if err != nil {
			return err
		}
		body := map[string]interface{}{
			"allowed_days": isoDays,
			"start_hour":   schedStartHour,
			"end_hour":     schedEndHour,
			"timezone":     tz,
		}
		var out models.SecretAccessSchedule
		if err := c.Put(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/schedule", id), body, &out); err != nil {
			return err
		}
		fmt.Printf("Schedule set: secret %d is readable on days %q, %02d:00–%02d:00 %s\n",
			id, out.AllowedDays, out.StartHour, out.EndHour, out.Timezone)
		return nil
	},
}

var getScheduleCmd = &cobra.Command{
	Use:          "get-schedule <secret-name>",
	Short:        "Show the temporal access schedule for a secret",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := scheduleClient()
		if err != nil {
			return err
		}
		var out models.SecretAccessSchedule
		if err := c.Get(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/schedule", id), &out); err != nil {
			return err
		}
		fmt.Printf("Secret %d schedule:\n", id)
		fmt.Printf("  Days:       %s\n", out.AllowedDays)
		fmt.Printf("  Start hour: %d:00\n", out.StartHour)
		fmt.Printf("  End hour:   %d:00\n", out.EndHour)
		fmt.Printf("  Timezone:   %s\n", out.Timezone)
		return nil
	},
}

var clearScheduleCmd = &cobra.Command{
	Use:          "clear-schedule <secret-name>",
	Short:        "Remove the temporal access schedule for a secret (idempotent)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := scheduleClient()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/schedule", id)); err != nil {
			return err
		}
		fmt.Printf("Schedule cleared for secret %d.\n", id)
		return nil
	},
}

func scheduleClient() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

func init() {
	setScheduleCmd.Flags().StringVar(&schedDays, "days", "", "Allowed days: comma-separated day names (mon,tue,…) or ISO numbers (1–7), or \"*\" for all days (required)")
	setScheduleCmd.Flags().IntVar(&schedStartHour, "start-hour", 0, "Start hour of the read window (0–23, inclusive)")
	setScheduleCmd.Flags().IntVar(&schedEndHour, "end-hour", 24, "End hour of the read window (1–24, exclusive)")
	setScheduleCmd.Flags().StringVar(&schedTimezone, "timezone", "UTC", "IANA timezone name (default: UTC)")
	_ = setScheduleCmd.MarkFlagRequired("days")

	SecretCmd.AddCommand(setScheduleCmd)
	SecretCmd.AddCommand(getScheduleCmd)
	SecretCmd.AddCommand(clearScheduleCmd)
}
