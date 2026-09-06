package user

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	updateUserID      uint
	updateUsername    string
	updateEmail       string
	updateDisplayName string
	updateActiveStr   string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a user",
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().UintVar(&updateUserID, "id", 0, "User ID (required)")
	updateCmd.Flags().StringVar(&updateUsername, "username", "", "New username")
	updateCmd.Flags().StringVar(&updateEmail, "email", "", "New email")
	updateCmd.Flags().StringVar(&updateDisplayName, "display-name", "", "New display name")
	updateCmd.Flags().StringVar(&updateActiveStr, "active", "", "Active status: true or false")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if updateUserID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if updateUsername == "" && updateEmail == "" && updateDisplayName == "" && updateActiveStr == "" {
		return errors.New("provide at least one of --username, --email, --display-name, --active")
	}

	var active *bool
	if updateActiveStr != "" {
		v, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(updateActiveStr)))
		if err != nil {
			return fmt.Errorf("invalid --active value (use true or false): %w", err)
		}
		active = &v
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runUpdateRemote(rc, active)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	u, err := service.UpdateUser(ctx, &core.UpdateUserRequest{
		ID:          updateUserID,
		Username:    updateUsername,
		Email:       updateEmail,
		DisplayName: updateDisplayName,
		IsActive:    active,
	})
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	fmt.Printf("User updated: id=%d username=%s email=%s\n", u.ID, u.Username, u.Email)
	return nil
}

// runUpdateRemote handles `user update` in remote mode via PUT /api/v1/users/{id},
// matching UserHandler.UpdateUser's request body (server/http/handlers/users_crud.go).
func runUpdateRemote(rc *common.RemoteClient, active *bool) error {
	fmt.Printf("Target: user %d on %s\n", updateUserID, rc.Endpoint)
	body := map[string]interface{}{}
	if updateUsername != "" {
		body["username"] = updateUsername
	}
	if updateEmail != "" {
		body["email"] = updateEmail
	}
	if updateDisplayName != "" {
		body["display_name"] = updateDisplayName
	}
	if active != nil {
		body["active"] = *active
	}

	var resp remoteUserResponse
	if err := rc.Put(context.Background(), fmt.Sprintf("/api/v1/users/%d", updateUserID), body, &resp); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	fmt.Printf("User updated: id=%d username=%s email=%s\n", resp.ID, resp.Username, resp.Email)
	return nil
}
