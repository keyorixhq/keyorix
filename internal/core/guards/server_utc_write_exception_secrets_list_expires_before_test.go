package guards

func init() {
	registerServerTimeWriteException("http:secrets_list.go:ListSecrets:ExpiresBefore",
		"client bound for a read filter; core evaluates it in Go as an instant comparison (secret_listing_query.go, "+
			"Expiration.Before(*ExpiresBefore)), which does not depend on the zone")
}
