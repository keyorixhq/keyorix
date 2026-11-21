package faultops

// bootstrapSystemLocked (internal/core/auth_bootstrap.go): POST /system/init. A lost
// ack answered failure while the admin, the catalog and the initialised marker
// committed, and skipped the post-commit user.created / project.created rows, the
// password-history seed and the token clear. Fixed by PARTIAL-COMMIT-TAILS-NOV-3
// item 1 (#3225); the op is ops_system_init_test.go.
func init() {
	registerUserCreateLostAckSite("bootstrapSystemLocked", userCreateLostAckSite{op: "REST POST /system/init"})
}
