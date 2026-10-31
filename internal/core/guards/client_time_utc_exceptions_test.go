// client_time_utc_exceptions_test.go -- the known unhooked expiry writes that
// TestEveryUnhookedExpiryWriteInCoreIsUTC does not yet require to be UTC.
//
// Each row names a write that was NOT probed against the production SQLite dialect by
// SQLITE-TIME-TAILS-1 and sits in an area another session owns (login, session, SSO, setup/OTP).
// The fix for each is the same one token (`.UTC()` on the value, as in invitations.go); delete the
// row in the same change. The guard fails the row if it ever stops matching a hit.

package guards

func init() {
	registerClientTimeUTCException("auth.go:RefreshSession:Session.AbsoluteExpiresAt",
		"copies old.AbsoluteExpiresAt from the stored row; session/login area (FIX-3277), not probed")
	registerClientTimeUTCException("sso.go:BeginSSO:SSOLoginState.ExpiresAt",
		"c.now().Add(ssoStateTTL) in the host zone; SSO login area (FIX-3277), not probed")
	registerClientTimeUTCException("sso.go:BeginSAML:SSOLoginState.ExpiresAt",
		"c.now().Add(ssoStateTTL) in the host zone; SSO login area (FIX-3277), not probed")
	registerClientTimeUTCException("users.go:buildUserForCreate:User.OneTimePasswordExpiresAt",
		"set from setup_delivery.go's server-clock expiry; setup/OTP area (FIX-3277), not probed")
}
