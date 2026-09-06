package user

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// remoteUserResponse decodes the {"data": ...} envelope's inner payload from
// GET /api/v1/users/{id} and GET /api/v1/users/by-email, matching the field
// names userToAPIResponse (server/http/handlers/users_handler.go) writes.
type remoteUserResponse struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func printRemoteUser(u *remoteUserResponse) {
	fmt.Printf("ID: %d\nUsername: %s\nEmail: %s\nDisplay: %s\nActive: %t\nCreated: %s\nUpdated: %s\n",
		u.ID, u.Username, u.Email, u.DisplayName, u.Active, u.CreatedAt, u.UpdatedAt)
}

var (
	getUserID    uint
	getUserEmail string
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a user by id or email",
	RunE:  runGet,
}

func init() {
	getCmd.Flags().UintVar(&getUserID, "id", 0, "User ID")
	getCmd.Flags().StringVar(&getUserEmail, "email", "", "User email")
}

func printUser(u *models.User) {
	dn := u.DisplayName
	if dn == "" {
		dn = u.Username
	}
	fmt.Printf("ID: %d\nUsername: %s\nEmail: %s\nDisplay: %s\nActive: %t\nCreated: %s\nUpdated: %s\n",
		u.ID, u.Username, u.Email, dn, u.IsActive,
		u.CreatedAt.Format("2006-01-02 15:04:05"),
		u.UpdatedAt.Format("2006-01-02 15:04:05"))
}

func runGet(cmd *cobra.Command, args []string) error {
	if getUserID == 0 && getUserEmail == "" {
		return errors.New("specify --id or --email")
	}
	if getUserID != 0 && getUserEmail != "" {
		return errors.New("use only one of --id or --email")
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runGetRemote(rc)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	if getUserID != 0 {
		u, err := service.GetUser(ctx, getUserID)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		printUser(u)
		return nil
	}
	u, err := service.GetUserByEmail(ctx, getUserEmail)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	printUser(u)
	return nil
}

// runGetRemote handles `user get` in remote mode: GET /api/v1/users/{id} for
// --id, or GET /api/v1/users/by-email for --email (#503) — a server-side
// route added exactly for a caller, like this one, that only has the email.
func runGetRemote(rc *common.RemoteClient) error {
	fmt.Printf("Target: %s\n", rc.Endpoint)
	var u remoteUserResponse
	ctx := context.Background()
	if getUserID != 0 {
		if err := rc.Get(ctx, fmt.Sprintf("/api/v1/users/%d", getUserID), &u); err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	} else {
		path := "/api/v1/users/by-email?email=" + url.QueryEscape(getUserEmail)
		if err := rc.Get(ctx, path, &u); err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
	}
	printRemoteUser(&u)
	return nil
}
