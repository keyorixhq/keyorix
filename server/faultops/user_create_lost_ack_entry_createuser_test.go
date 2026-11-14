package faultops

// createUser (internal/core/users.go): CreateUser, CreateUserAudited and everything
// built on them (REST POST /api/v1/users/ without role or assignments, the setup-link
// and one-time-password creates on REST and gRPC, invitation accept through
// c.CreateUser). Fixed by #4208.
func init() {
	registerUserCreateLostAckSite("createUser", userCreateLostAckSite{op: "REST POST /api/v1/users/"})
}
