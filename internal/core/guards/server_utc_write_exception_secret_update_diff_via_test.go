package guards

func init() {
	registerServerTimeWriteException("http:secret_update_diff.go:updateSecretViaDiff:Expiration",
		"client expiry handed to core.UpdateSecret; UpdateSecretFields stores it as expiration.UTC() (local_secrets.go), proven by TestUpdateSecretFields_StoresExpirationInUTCForAnyCallerZone; the SecretNode BeforeSave hook covers the create path")
}
