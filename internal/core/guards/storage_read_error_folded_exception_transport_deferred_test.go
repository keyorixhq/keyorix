package guards

// Exceptions to TestNoStorageReadErrorFoldedIntoNotFound found by its widening to
// server/http/handlers and server/grpc/services (STORAGE-ERR-CLASS-5 item 5), not fixed there.
// Each one is a handler that answers 404 when the error TEXT contains "not found", so a storage
// read fault whose driver message contains those words reads as a missing target. They are the
// families of the "text-match suspects" list that STORAGE-ERR-CLASS-5 item 4 did not take
// (project catalog Get, groups Get, secret templates Get, share status): each has a typed
// storage not-found already or needs one, and a row in
// testdata/errtext_classification_exceptions.tsv that goes with the fix. Delete a row here when
// its handler classifies with errors.Is on the typed not-found and answers a fault 503.

func init() {
	const why = "text-matched not-found in a handler pre-check (a read fault reads as 404): deferred, same fix as STORAGE-ERR-CLASS-5 item 4"
	// {file in server/http/handlers, function}: the hit key is "handlers/<file>:<function>".
	for _, site := range [][2]string{
		{"catalog.go", "GetProject"},
		{"groups_handler.go", "GetGroup"},
		{"secret_templates.go", "Get"},
		{"shares_query.go", "GetSharingStatusWithIndicators"},
	} {
		registerFoldedReadException("handlers/"+site[0]+":"+site[1], why)
	}
}
