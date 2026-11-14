package faultops

// CreateUserWithAssignments (internal/core/users.go): gRPC UserService.CreateUser
// with an admin-set password, REST POST /api/v1/users/ with a role or project
// assignments. Fixed by PARTIAL-COMMIT-NOV-2 (#3225).
func init() {
	registerUserCreateLostAckSite("CreateUserWithAssignments", userCreateLostAckSite{op: "GRPC keyorix.v1.UserService.CreateUser"})
}
