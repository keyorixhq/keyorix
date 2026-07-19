package rbac

import (
	"github.com/spf13/cobra"
)

var RbacCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Role-Based Access Control management commands",
}

func init() {
	RbacCmd.AddCommand(assignRoleCmd)
	RbacCmd.AddCommand(removeRoleCmd)
	RbacCmd.AddCommand(listRolesCmd)
	RbacCmd.AddCommand(listUserRolesCmd)
	RbacCmd.AddCommand(checkPermissionCmd)
	RbacCmd.AddCommand(listPermissionsCmd)
	RbacCmd.AddCommand(auditLogsCmd)
	RbacCmd.AddCommand(assignRoleToGroupCmd)
	RbacCmd.AddCommand(removeRoleFromGroupCmd)
	RbacCmd.AddCommand(listGroupRolesCmd)
	RbacCmd.AddCommand(exportMatrixCmd)
}
