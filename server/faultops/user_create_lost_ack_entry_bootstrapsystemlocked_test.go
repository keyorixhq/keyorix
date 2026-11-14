package faultops

// bootstrapSystemLocked (internal/core/auth_bootstrap.go): POST /system/init. A lost
// ack answers failure while the admin, the catalog and the initialised marker
// committed (a retry answers AlreadyInitialized), and skips the post-commit
// user.created / project.created rows and the password-history seed.
func init() {
	registerUserCreateLostAckSite("bootstrapSystemLocked", userCreateLostAckSite{
		outOfScope: "PARTIAL-COMMIT-NOV-2 was verify-only for auth_bootstrap.go, which DEMO-COPY-TAILS (#4218) changes; " +
			"read the lost ack back there after #4218 merges (#3225)",
	})
}
