// machine_ip_allowlist.go — IP-based allowlist enforcement for machine tokens.
//
// When a MachineIdentityCredential carries AllowedCIDRs, ValidateMachineToken
// returns a MachineTokenRestriction that the HTTP and gRPC middleware use to
// deny requests from outside the listed networks (fail-closed: an
// unparseable/empty source IP is denied).
//
// This file documents the design; the CIDR encoding/decoding lives in
// machine_token.go (machineRestrictionFrom) and the struct definition lives
// in authz.go (MachineTokenRestriction), consistent with the PAT pattern.
package core
