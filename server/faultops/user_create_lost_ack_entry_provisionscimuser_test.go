package faultops

// ProvisionSCIMUser (internal/core/scim.go): SCIM POST /scim/v2/Users. Fixed by
// PARTIAL-COMMIT-NOV-2 (#3225).
func init() {
	registerUserCreateLostAckSite("ProvisionSCIMUser", userCreateLostAckSite{op: "REST POST /scim/v2/Users"})
}
