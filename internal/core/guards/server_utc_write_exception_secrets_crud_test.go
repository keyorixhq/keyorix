package guards

func init() {
	registerServerTimeWriteException("http:secrets_crud.go:UpdateSecret:Expiration",
		"client expiry handed to core.UpdateSecret; UpdateSecretFields stores it as expiration.UTC() (local_secrets.go), proven by TestUpdateSecretFields_StoresExpirationInUTCForAnyCallerZone; the SecretNode BeforeSave hook covers the create path")
}
