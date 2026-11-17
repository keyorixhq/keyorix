- **INV-FUZZCLOUD-mysql-no-local-infile-egress** A hostile MySQL server's LOCAL INFILE
  request must never make the go-sql-driver client read a local file and send its content
  to the server, under the config Keyorix builds (`openMySQLConfig`,
  `internal/dynamic/mysql.go`, which refuses `AllowAllFiles` and registers no reader). Why:
  LOCAL INFILE is a server-driven local-file-read primitive; honouring it against a hostile
  target database exfiltrates arbitrary files from the Keyorix host. Guard:
  `TestMySQLLocalInfileCanary_NotRead` and `FuzzMySQLLocalInfile` plant a unique-content
  canary file, point the (fuzzed) request at it, and assert the content never appears in
  the client's writes back to the server; `TestMySQLLocalInfileCanary_RedProof` sets
  `AllowAllFiles=true` and shows the same request DOES egress the canary (oracle not
  vacuous). Does NOT cover a path explicitly allowlisted via `mysql.RegisterLocalFile`
  (Keyorix registers none) nor assert anything about the driver's own error text — only
  that the file body does not reach the server.
