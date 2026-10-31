// client_time_utc_exceptions_test.go -- the known unhooked expiry writes that
// TestEveryUnhookedExpiryWriteInCoreIsUTC does not require to be UTC.
//
// The list is empty: UTC-WRITES-1 fixed the last four (RefreshSession, BeginSSO, BeginSAML,
// buildUserForCreate) and deleted their rows. A new row is a registerClientTimeUTCException call
// from init() here, keyed "file.go:Func:Type.Field", with the reason the write is safe; the guard
// fails a row that no longer matches a hit.

package guards
