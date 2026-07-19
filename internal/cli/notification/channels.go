// Package notification provides CLI commands for managing notification channels.
package notification

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// NotificationCmd is the top-level "notification" command.
var NotificationCmd = &cobra.Command{
	Use:   "notification",
	Short: "Manage notifications and notification channels",
}

// channelCmd groups the "notification channel" sub-commands.
var channelCmd = &cobra.Command{
	Use:   "channel",
	Short: "Manage runtime notification channel destinations",
}

var (
	flagChannelType    string
	flagChannelURL     string
	flagChannelEmail   string
	flagChannelEvents  string
	flagChannelEnabled bool
	flagChannelDisable bool
	flagConfirm        bool
)

func init() {
	// channel add flags
	addCmd.Flags().StringVar(&flagChannelType, "type", "", "Channel type: webhook, slack, teams, or email (required)")
	addCmd.Flags().StringVar(&flagChannelURL, "url", "", "Webhook URL (required for webhook/slack/teams)")
	addCmd.Flags().StringVar(&flagChannelEmail, "email", "", "Email address (required for email type)")
	addCmd.Flags().StringVar(&flagChannelEvents, "events", "", "Comma-separated event types, e.g. secret.rotated,anomaly.detected (empty = all)")
	_ = addCmd.MarkFlagRequired("type")

	// channel update flags
	updateCmd.Flags().StringVar(&flagChannelURL, "url", "", "New webhook URL")
	updateCmd.Flags().StringVar(&flagChannelEmail, "email", "", "New email address")
	updateCmd.Flags().StringVar(&flagChannelEvents, "events", "", "New event filter (comma-separated)")
	updateCmd.Flags().BoolVar(&flagChannelEnabled, "enabled", false, "Enable the channel")
	updateCmd.Flags().BoolVar(&flagChannelDisable, "disabled", false, "Disable the channel")

	// channel delete flags
	deleteCmd.Flags().BoolVar(&flagConfirm, "confirm", false, "Confirm deletion without interactive prompt")

	channelCmd.AddCommand(listCmd)
	channelCmd.AddCommand(addCmd)
	channelCmd.AddCommand(getCmd)
	channelCmd.AddCommand(updateCmd)
	channelCmd.AddCommand(deleteCmd)
	NotificationCmd.AddCommand(channelCmd)
}

// notificationChannelWire is the API wire shape returned by the server.
type notificationChannelWire struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Email     string `json:"email"`
	Events    string `json:"events"`
	CreatedBy string `json:"created_by"`
}

type channelListResponse struct {
	Channels []notificationChannelWire `json:"channels"`
}

const channelsBasePath = "/api/v1/notification-channels"

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all notification channels",
	RunE:  runChannelList,
}

func runChannelList(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runChannelListRemote(rc)
}

func runChannelListRemote(rc *common.RemoteClient) error {
	var result channelListResponse
	if err := rc.Get(context.Background(), channelsBasePath, &result); err != nil {
		return err
	}
	if len(result.Channels) == 0 {
		fmt.Println("No notification channels configured.")
		return nil
	}
	fmt.Printf("%-5s %-24s %-8s %-8s %s\n", "ID", "NAME", "TYPE", "ENABLED", "EVENTS")
	for _, ch := range result.Channels {
		enabled := "no"
		if ch.Enabled {
			enabled = "yes"
		}
		events := ch.Events
		if events == "" {
			events = "*"
		}
		fmt.Printf("%-5d %-24s %-8s %-8s %s\n", ch.ID, ch.Name, ch.Type, enabled, events)
	}
	return nil
}

var addCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a notification channel",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelAdd,
}

func runChannelAdd(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runChannelAddRemote(rc, args[0], flagChannelType, flagChannelURL, flagChannelEmail, flagChannelEvents)
}

func runChannelAddRemote(rc *common.RemoteClient, name, chType, url, email, events string) error {
	body := map[string]interface{}{
		"name":    name,
		"type":    chType,
		"enabled": true,
		"url":     url,
		"email":   email,
		"events":  events,
	}
	var result notificationChannelWire
	if err := rc.Post(context.Background(), channelsBasePath, body, &result); err != nil {
		return err
	}
	fmt.Printf("Notification channel %q (id=%d, type=%s) created.\n", result.Name, result.ID, result.Type)
	return nil
}

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get details of a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelGet,
}

func runChannelGet(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runChannelGetRemote(rc, args[0])
}

func runChannelGetRemote(rc *common.RemoteClient, name string) error {
	// List all and find by name (no server-side name-lookup endpoint).
	var result channelListResponse
	if err := rc.Get(context.Background(), channelsBasePath, &result); err != nil {
		return err
	}
	for _, ch := range result.Channels {
		if strings.EqualFold(ch.Name, name) {
			printChannel(ch)
			return nil
		}
	}
	return fmt.Errorf("notification channel %q not found", name)
}

func printChannel(ch notificationChannelWire) {
	enabled := "no"
	if ch.Enabled {
		enabled = "yes"
	}
	events := ch.Events
	if events == "" {
		events = "*"
	}
	fmt.Printf("id:         %d\n", ch.ID)
	fmt.Printf("name:       %s\n", ch.Name)
	fmt.Printf("type:       %s\n", ch.Type)
	fmt.Printf("enabled:    %s\n", enabled)
	if ch.URL != "" {
		fmt.Printf("url:        %s\n", ch.URL)
	}
	if ch.Email != "" {
		fmt.Printf("email:      %s\n", ch.Email)
	}
	fmt.Printf("events:     %s\n", events)
	fmt.Printf("created by: %s\n", ch.CreatedBy)
}

var updateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelUpdate,
}

func buildUpdateBody(cmd *cobra.Command, url, email, events string, enable, disable bool) map[string]interface{} {
	body := map[string]interface{}{}
	if cmd.Flags().Changed("url") {
		body["url"] = url
	}
	if cmd.Flags().Changed("email") {
		body["email"] = email
	}
	if cmd.Flags().Changed("events") {
		body["events"] = events
	}
	if enable {
		body["enabled"] = true
	}
	if disable {
		body["enabled"] = false
	}
	return body
}

func runChannelUpdate(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	body := buildUpdateBody(cmd, flagChannelURL, flagChannelEmail, flagChannelEvents, flagChannelEnabled, flagChannelDisable)
	return runChannelUpdateRemote(rc, args[0], body)
}

func runChannelUpdateRemote(rc *common.RemoteClient, name string, body map[string]interface{}) error {
	// Resolve name → id.
	id, err := resolveChannelID(rc, name)
	if err != nil {
		return err
	}
	var result notificationChannelWire
	if err := rc.Put(context.Background(), fmt.Sprintf("%s/%d", channelsBasePath, id), body, &result); err != nil {
		return err
	}
	fmt.Printf("Notification channel %q (id=%d) updated.\n", result.Name, result.ID)
	return nil
}

var deleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a notification channel by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelDelete,
}

func runChannelDelete(cmd *cobra.Command, args []string) error {
	if !flagConfirm {
		return fmt.Errorf("add --confirm to confirm deletion of notification channel %q", args[0])
	}
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runChannelDeleteRemote(rc, args[0])
}

func runChannelDeleteRemote(rc *common.RemoteClient, name string) error {
	id, err := resolveChannelID(rc, name)
	if err != nil {
		return err
	}
	if err := rc.Delete(context.Background(), fmt.Sprintf("%s/%d", channelsBasePath, id)); err != nil {
		return err
	}
	fmt.Printf("Notification channel %q deleted.\n", name)
	return nil
}

// resolveChannelID lists all channels and returns the id for the given name.
func resolveChannelID(rc *common.RemoteClient, name string) (uint, error) {
	var result channelListResponse
	if err := rc.Get(context.Background(), channelsBasePath, &result); err != nil {
		return 0, err
	}
	for _, ch := range result.Channels {
		if strings.EqualFold(ch.Name, name) {
			return ch.ID, nil
		}
	}
	return 0, fmt.Errorf("notification channel %q not found", name)
}
